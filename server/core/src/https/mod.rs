mod csp_headers;
mod generic;
mod manifest;
mod middleware;
mod oauth2;
mod tests;
mod ui;
mod v1;
mod v1_scim;

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::ServerRole;
use axum::extract::connect_info::{IntoMakeServiceWithConnectInfo, ResponseFuture};
use axum::middleware::from_fn;
use axum::response::Response;
use axum::routing::*;
use axum::Router;
use axum_macros::FromRef;
use axum_sessions::extractors::WritableSession;
use axum_sessions::{async_session, SameSite, SessionLayer};
use compact_jwt::{Jws, JwsSigner, JwsUnverified};
use generic::*;
use http::HeaderMap;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream, Http};
use hyper::Body;
use kanidm_proto::v1::OperationError;
use kanidmd_lib::status::StatusActor;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use tokio_openssl::SslStream;

use futures_util::future::poll_fn;
use serde::Serialize;
use tokio::net::TcpListener;

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::CoreAction;

use self::v1::SessionId;

#[derive(Clone, FromRef)]
pub struct ServerState {
    pub status_ref: &'static kanidmd_lib::status::StatusActor,
    pub qe_w_ref: &'static crate::actors::v1_write::QueryServerWriteV1,
    pub qe_r_ref: &'static crate::actors::v1_read::QueryServerReadV1,
    // Store the token management parts.
    pub jws_signer: compact_jwt::JwsSigner,
    pub jws_validator: compact_jwt::JwsValidator,
    // /// The SHA384 hashes of javascript files we're going to serve to users
    pub js_files: Vec<JavaScriptFile>,
    // pub(crate) trust_x_forward_for: bool,
}

impl ServerState {
    fn get_current_auth_session_id(
        &self,
        headers: HeaderMap,
        session: &WritableSession,
    ) -> Option<Uuid> {
        // We see if there is a signed header copy first.
        headers
            .get("X-KANIDM-AUTH-SESSION-ID")
            .and_then(|hv| {
                // Get the first header value.
                hv.to_str().ok()
            })
            .and_then(|h| {
                // Take the token str and attempt to decrypt
                // Attempt to re-inflate a uuid from bytes.
                JwsUnverified::from_str(h).ok()
            })
            .and_then(|jwsu| {
                jwsu.validate(&self.jws_validator)
                    .map(|jws: Jws<SessionId>| jws.into_inner().sessionid)
                    .ok()
            })
            // If not there, get from the cookie instead.
            .or_else(|| session.get::<Uuid>("auth-session-id"))
    }
}

pub fn get_js_files(role: ServerRole) -> Vec<JavaScriptFile> {
    let mut js_files: Vec<JavaScriptFile> = Vec::new();

    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        // let's set up the list of js module hashes
        {
            let filepath = "wasmloader.js";
            js_files.push(JavaScriptFile {
                filepath,
                hash: generate_integrity_hash(format!(
                    "{}/{}",
                    env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                    filepath,
                ))
                .unwrap(),
                filetype: Some("module".to_string()),
            });
        }
        // let's set up the list of non-module hashes
        {
            let filepath = "external/bootstrap.bundle.min.js";
            js_files.push(JavaScriptFile {
                filepath,
                hash: generate_integrity_hash(format!(
                    "{}/{}",
                    env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                    filepath,
                ))
                .unwrap(),
                filetype: None,
            });
        }
    };
    js_files
}

pub async fn create_https_server(
    address: String,
    domain: String,
    tlsconfig: Option<crate::config::TlsConfiguration>,
    role: ServerRole,
    // trust_x_forward_for: bool,
    cookie_key: [u8; 32],
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let jws_validator = jws_signer
        .get_validator()
        .map_err(|e| {
            error!(?e, "Failed to get jws validator");
        })
        .unwrap();

    // TODO this whole session store is kinda cursed and doesn't work the way we need, I think?
    let store = async_session::CookieStore::new();
    // let secret = b"..."; // MUST be at least 64 bytes!
    let secret = format!("{:?}", cookie_key);
    let secret = secret.as_bytes(); // TODO the cookie/session secret needs to be longer?
    let session_layer = SessionLayer::new(store, secret)
        .with_cookie_name("kanidm-session")
        .with_session_ttl(None)
        .with_cookie_domain(domain)
        .with_same_site_policy(SameSite::Strict)
        .with_secure(true);

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files: get_js_files(role.clone()),
    };

    let static_routes = match role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            Router::new()
                .route("/", get(crate::https::ui::ui_handler))
                .route("/*ui", get(crate::https::ui::ui_handler))
                .route("/manifest.webmanifest", get(manifest::manifest))
                .layer(from_fn(csp_headers::strip_csp_headers))
                .layer(middleware::compression::new()) // TODO: this needs to be configured properly
        }
        ServerRole::WriteReplicaNoUI => Router::new(),
    };

    //  // == oauth endpoints.
    // TODO: turn this from a nest into a merge because state things are bad in nested routes
    let app = Router::new()
        .nest("/oauth2", oauth2::oauth2_route_setup(state.clone()))
        .route("/robots.txt", get(robots_txt))
        .nest("/v1", v1::router(state.clone()))
        .nest("/scim", v1_scim::scim_route_setup());

    let pkg_path = PathBuf::from(env!("KANIDM_WEB_UI_PKG_PATH"));
    if !pkg_path.exists() {
        eprintln!(
            "Couldn't find Web UI package path: ({}), quitting.",
            env!("KANIDM_WEB_UI_PKG_PATH")
        );
        std::process::exit(1);
    }

    let app = app
        // Shared account features only - mainly this is for unix-like features.
        .route("/status", get(status))
        .nest_service("/pkg", ServeDir::new(pkg_path))
        .layer(from_fn(crate::https::csp_headers::cspheaders_layer))
        .merge(static_routes)
        .layer(session_layer)
        .layer(from_fn(middleware::version_middleware))
        .layer(from_fn(middleware::kopid_end))
        .with_state(state)
        .layer(from_fn(middleware::kopid_start))
        .layer(TraceLayer::new_for_http())
        // the connect_info bit here lets us pick up the remote address of the client
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from_str(&address).unwrap();
    info!("Starting the web server...");

    Ok(tokio::spawn(async move {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => {},
                }
            }
            res = match tlsconfig {
                Some(tls_param) => {

                    let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();

                    tls_builder
                        .set_certificate_file(
                            tls_param.chain.clone(),
                            SslFiletype::PEM,
                        ).unwrap();
                    tls_builder.set_private_key_file(
                            tls_param.key.clone(),
                            SslFiletype::PEM,
                        )
                        .unwrap();
                    tls_builder.check_private_key().unwrap();

                    let acceptor = tls_builder.build();
                    let listener = TcpListener::bind(addr).await.unwrap();
                    let listener = hyper::server::conn::AddrIncoming::from_listener(listener).unwrap();

                    let protocol = Arc::new(Http::new());
                    server_loop(listener, acceptor, protocol, app).await
                },
                None => {
                    tokio::spawn(axum_server::bind(addr).serve(app))
                }
            } => {
                if let Err(err) = res {
                    error!("Web server exited with {:?}", err);
                }
            }
        };
        #[cfg(feature = "otel")]
        opentelemetry::global::shutdown_tracer_provider();
        info!("Stopped WebAcceptorActor");
    }))
}

async fn server_loop(
    listener: AddrIncoming,
    acceptor: SslAcceptor,
    protocol: Arc<Http>,
    app: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
) -> tokio::task::JoinHandle<Result<(), std::io::Error>> {
    let mut listener = listener;
    let mut app = app;
    tokio::spawn(async move {
        loop {
            let stream = poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx))
                .await
                .unwrap()
                .unwrap();
            let acceptor = acceptor.clone();
            let svc = tower::MakeService::make_service(&mut app, &stream);
            tokio::spawn(handle_conn(acceptor, stream, svc, protocol.clone()));
        }
    })
}
#[instrument(name = "handle-connection", skip(acceptor, stream, svc, protocol))]
/// This handles an individual connection.
async fn handle_conn(
    acceptor: SslAcceptor,
    stream: AddrStream,
    svc: ResponseFuture<Router, SocketAddr>,
    protocol: Arc<Http>,
) -> Result<(), hyper::Error> {
    let mut tls_stream = SslStream::new(Ssl::new(acceptor.context()).unwrap(), stream).unwrap();
    match SslStream::accept(Pin::new(&mut tls_stream)).await {
        Ok(_) => {
            protocol
                .serve_connection(tls_stream, svc.await.unwrap())
                .await
        }
        Err(_error) => {
            // error!("Failed to handle connection: {:?}", error);
            Ok(())
        }
    }
}

/// Generates the integrity hash for a file based on a filename
pub fn generate_integrity_hash(filename: String) -> Result<String, String> {
    let wasm_filepath = PathBuf::from(filename);
    match wasm_filepath.exists() {
        false => Err(format!(
            "Can't find {:?} to generate file hash",
            &wasm_filepath
        )),
        true => {
            let filecontents = match std::fs::read(&wasm_filepath) {
                Ok(value) => value,
                Err(error) => {
                    return Err(format!(
                        "Failed to read {:?}, skipping: {:?}",
                        wasm_filepath, error
                    ));
                }
            };
            let shasum =
                openssl::hash::hash(openssl::hash::MessageDigest::sha384(), &filecontents).unwrap();
            Ok(format!("sha384-{}", openssl::base64::encode_block(&shasum)))
        }
    }
}

#[derive(Clone)]
pub struct JavaScriptFile {
    // Relative to the pkg/ dir
    pub filepath: &'static str,
    // SHA384 hash of the file
    pub hash: String,
    // if it's a module add the "type"
    pub filetype: Option<String>,
}

impl JavaScriptFile {
    /// return the hash for use in CSP headers
    // pub fn as_csp_hash(self) -> String {
    //     self.hash
    // }
    /// returns a `<script>` HTML tag
    pub fn as_tag(&self) -> String {
        let typeattr = match &self.filetype {
            Some(val) => {
                format!(" type=\"{}\"", val.as_str())
            }
            _ => String::from(""),
        };
        format!(
            r#"<script src="/pkg/{}" integrity="{}"{}></script>"#,
            self.filepath, &self.hash, &typeattr,
        )
    }
}

// /// Silly placeholder response for unimplemented routes
// pub async fn do_nothing() -> impl IntoResponse {
//     "Not implemented"
// }

/// Convert any kind of Result<T, OperationError> into an axum response with a stable type
/// by JSON-encoding the body.
pub fn to_axum_response<T: Serialize>(v: Result<T, OperationError>) -> Response<Body> {
    match v {
        Ok(iv) => {
            let body = match serde_json::to_string(&iv) {
                Ok(val) => val,
                Err(_) => todo!("Handle JSON serialization of body"),
            };
            #[allow(clippy::unwrap_used)]
            Response::builder().body(Body::from(body)).unwrap()
        }
        Err(e) => {
            let res = match &e {
                OperationError::NotAuthenticated | OperationError::SessionExpired => {
                    // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                    Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer")
                }
                OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                    Response::builder().status(http::StatusCode::FORBIDDEN)
                }
                OperationError::NoMatchingEntries => {
                    Response::builder().status(http::StatusCode::NOT_FOUND)
                }
                OperationError::PasswordQuality(_)
                | OperationError::EmptyRequest
                | OperationError::SchemaViolation(_) => {
                    Response::builder().status(http::StatusCode::BAD_REQUEST)
                }
                _ => Response::builder().status(http::StatusCode::INTERNAL_SERVER_ERROR),
            };
            match serde_json::to_string(&e) {
                Ok(val) => res.body(Body::from(val)).unwrap(),
                Err(_) => res.body(Body::empty()).unwrap(),
            }
        }
    }
}

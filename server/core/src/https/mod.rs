mod apidocs;
pub(crate) mod errors;

mod extractors;
mod generic;
mod javascript;
mod manifest;
pub(crate) mod middleware;
mod oauth2;
mod tests;
pub(crate) mod trace;
mod ui;
mod v1;
mod v1_oauth2;
mod v1_scim;

use self::javascript::*;
use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::{Configuration, ServerRole, TlsConfiguration};
use axum::extract::connect_info::{IntoMakeServiceWithConnectInfo, ResponseFuture};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Redirect;
use axum::routing::*;
use axum::Router;
use axum_csp::{CspDirectiveType, CspValue};
use axum_macros::FromRef;
use compact_jwt::{Jws, JwsSigner, JwsUnverified};
use hashbrown::HashMap;
use http::{HeaderMap, HeaderValue};
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrStream, Http};
use kanidm_proto::constants::KSESSIONID;
use kanidmd_lib::status::StatusActor;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use sketching::*;
use tokio_openssl::SslStream;

use futures_util::future::poll_fn;
use tokio::net::TcpListener;
use tracing::Level;

use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultOnRequest, TraceLayer};
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
    // The SHA384 hashes of javascript files we're going to serve to users
    pub js_files: JavaScriptFiles,
    pub(crate) trust_x_forward_for: bool,
    pub csp_header: HeaderValue,
}

impl ServerState {
    fn reinflate_uuid_from_bytes(&self, input: &str) -> Option<Uuid> {
        match JwsUnverified::from_str(input) {
            Ok(val) => val
                .validate(&self.jws_validator)
                .map(|jws: Jws<SessionId>| jws.into_inner().sessionid)
                .ok(),
            Err(_) => None,
        }
    }

    fn get_current_auth_session_id(&self, headers: &HeaderMap) -> Option<Uuid> {
        // We see if there is a signed header copy first.
        headers
            .get(KSESSIONID)
            .and_then(|hv| {
                // Get the first header value.
                hv.to_str().ok()
            })
            .and_then(|s| self.reinflate_uuid_from_bytes(s))
    }
}

#[derive(Clone)]
pub struct JavaScriptFiles {
    all_pages: Vec<JavaScriptFile>,
    selected: HashMap<String, JavaScriptFile>,
}

pub fn get_js_files(role: ServerRole) -> Result<JavaScriptFiles, ()> {
    let mut all_pages: Vec<JavaScriptFile> = Vec::new();
    let mut selected: HashMap<String, JavaScriptFile> = HashMap::new();

    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        // let's set up the list of js module hashes
        for filepath in [
            "wasmloader.js", // TODO: deprecate this
            "wasmloader_admin.js",
            "wasmloader_login_flows.js",
            "wasmloader_user.js",
        ] {
            match generate_integrity_hash(format!(
                "{}/{}",
                env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                filepath,
            )) {
                Ok(hash) => {
                    selected.insert(
                        filepath.to_string(),
                        JavaScriptFile {
                            filepath,
                            hash,
                            filetype: Some("module".to_string()),
                        },
                    );
                }
                Err(err) => {
                    admin_error!(
                        ?err,
                        "Failed to generate integrity hash for {} THIS IS GOING TO CAUSE PROBLEMS",
                        filepath
                    );
                    return Err(());
                }
            };
        }

        for filepath in ["shared.js", "external/bootstrap.bundle.min.js"] {
            // let's set up the list of non-wasm-module js files we want to serve
            // for filepath in ["external/bootstrap.bundle.min.js", "shared.js"] {
            match generate_integrity_hash(format!(
                "{}/{}",
                env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                filepath,
            )) {
                Ok(hash) => all_pages.push(JavaScriptFile {
                    filepath,
                    hash,
                    filetype: None,
                }),
                Err(err) => {
                    admin_error!(
                        ?err,
                        "Failed to generate integrity hash for {} THIS IS GOING TO CAUSE PROBLEMS!",
                        filepath
                    );
                    return Err(());
                }
            }
        }
    }
    Ok(JavaScriptFiles {
        all_pages,
        selected,
    })
}

pub async fn create_https_server(
    config: Configuration,
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let jws_validator = jws_signer.get_validator().map_err(|e| {
        error!(?e, "Failed to get jws validator");
    })?;

    let js_files = get_js_files(config.role)?;
    // set up the CSP headers
    // script-src 'self'
    //      'sha384-Zao7ExRXVZOJobzS/uMp0P1jtJz3TTqJU4nYXkdmsjpiVD+/wcwCyX7FGqRIqvIz'
    //      'sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM'
    //      'unsafe-eval';
    let mut all_js_files = js_files.all_pages.clone();
    for (_, jsfile) in js_files.selected.clone() {
        all_js_files.push(jsfile);
    }

    let js_directives = all_js_files
        .into_iter()
        .map(|f| f.hash)
        .collect::<Vec<String>>();
    let mut js_directives: Vec<CspValue> = js_directives
        .into_iter()
        .map(|value| CspValue::Sha384 { value })
        .collect();
    js_directives.extend(vec![CspValue::UnsafeEval, CspValue::SelfSite]);

    let csp_header = axum_csp::CspSetBuilder::new()
        // default-src 'self';
        .add(CspDirectiveType::DefaultSrc, vec![CspValue::SelfSite])
        // form-action https: 'self';
        .add(
            CspDirectiveType::FormAction,
            vec![CspValue::SelfSite, CspValue::SchemeHttps],
        )
        // base-uri 'self';
        .add(
            CspDirectiveType::BaseUri,
            vec![CspValue::SelfSite, CspValue::SchemeHttps],
        )
        // worker-src 'none';
        .add(CspDirectiveType::WorkerSource, vec![CspValue::None])
        // frame-ancestors 'none'
        .add(CspDirectiveType::FrameAncestors, vec![CspValue::None])
        .add(CspDirectiveType::ScriptSource, js_directives)
        .add(
            CspDirectiveType::ImgSrc,
            vec![CspValue::SelfSite, CspValue::SchemeData],
        );

    let trust_x_forward_for = config.trust_x_forward_for;

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files,
        trust_x_forward_for,
        csp_header: csp_header.finish(),
    };

    let static_routes = match config.role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            // Create a spa router that captures everything at ui without key extraction.

            Router::new()
                // direct users to the base app page. If a login is required,
                // then views will take care of redirection. We shouldn't redir
                // to login because that force clears previous sessions!
                // ^ TODO: this is dumb and we should stop that.
                .route("/", get(|| async { Redirect::temporary("/ui") }))
                .route("/manifest.webmanifest", get(manifest::manifest)) // skip_route_check
                .nest("/ui", ui::spa_router())
                .nest("/ui/login", ui::spa_router_login_flows())
                .nest("/ui/reauth", ui::spa_router_login_flows())
                .nest("/ui/oauth2", ui::spa_router_login_flows())
                .nest("/ui/admin", ui::spa_router_admin())
                .layer(middleware::compression::new())
                .route("/ui/images/oauth2/:rs_name", get(oauth2::oauth2_image_get))
            // skip_route_check
        }
        ServerRole::WriteReplicaNoUI => Router::new(),
    };
    let app = Router::new()
        .merge(generic::route_setup())
        .merge(oauth2::route_setup(state.clone()))
        .merge(v1_scim::route_setup())
        .merge(v1::route_setup(state.clone()));

    let app = match config.role {
        ServerRole::WriteReplicaNoUI => app,
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            let pkg_path = PathBuf::from(env!("KANIDM_WEB_UI_PKG_PATH"));
            if !pkg_path.exists() {
                eprintln!(
                    "Couldn't find Web UI package path: ({}), quitting.",
                    env!("KANIDM_WEB_UI_PKG_PATH")
                );
                std::process::exit(1);
            }
            let pkg_router = Router::new()
                .nest_service("/pkg", ServeDir::new(pkg_path).precompressed_br())
                .layer(middleware::compression::new());
            app.merge(pkg_router)
        }
    };

    // this sets up the default span which logs the URL etc.
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace::DefaultMakeSpanKanidmd::new())
        // setting these to trace because all they do is print "started processing request", and we are already doing that enough!
        .on_request(DefaultOnRequest::new().level(Level::TRACE));

    let app = app
        .merge(static_routes)
        .layer(from_fn_with_state(
            state.clone(),
            middleware::security_headers::security_headers_layer,
        ))
        .layer(from_fn(middleware::version_middleware))
        .layer(from_fn(
            middleware::hsts_header::strict_transport_security_layer,
        ));

    // layer which checks the responses have a content-type of JSON when we're in debug mode
    #[cfg(any(test, debug_assertions))]
    let app = app.layer(from_fn(middleware::are_we_json_yet));

    let app = app
        // This must be the LAST middleware.
        // This is because the last middleware here is the first to be entered and the last
        // to be exited, and this middleware sets up ids' and other bits for for logging
        // coherence to be maintained.
        .layer(from_fn(middleware::kopid_middleware))
        .merge(apidocs::router())
        // this MUST be the last layer before with_state else the span never starts and everything breaks.
        .layer(trace_layer)
        .with_state(state)
        // the connect_info bit here lets us pick up the remote address of the client
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from_str(&config.address).map_err(|err| {
        error!(
            "Failed to parse address ({:?}) from config: {:?}",
            config.address, err
        );
    })?;

    info!("Starting the web server...");

    Ok(tokio::spawn(async move {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => {},
                }
            }
            res = match config.tls_config {
                Some(tls_param) => {
                    // This isn't optimal, but we can't share this with the
                    // other path for integration tests because that doesn't
                    // do tls (yet?)
                    let listener = match TcpListener::bind(addr).await {
                        Ok(l) => l,
                        Err(err) => {
                            error!(?err, "Failed to bind tcp listener");
                            return
                        }
                    };
                    tokio::spawn(server_loop(tls_param, listener, app))
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
        info!("Stopped {}", super::TaskName::HttpsServer);
    }))
}

async fn server_loop(
    tls_param: TlsConfiguration,
    listener: TcpListener,
    app: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
) -> Result<(), std::io::Error> {
    let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let mut app = app;
    tls_builder
        .set_certificate_chain_file(tls_param.chain.clone())
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("Failed to create TLS listener: {:?}", err),
            )
        })?;
    tls_builder
        .set_private_key_file(tls_param.key.clone(), SslFiletype::PEM)
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("Failed to create TLS listener: {:?}", err),
            )
        })?;
    tls_builder.check_private_key().map_err(|err| {
        std::io::Error::new(
            ErrorKind::Other,
            format!("Failed to create TLS listener: {:?}", err),
        )
    })?;
    let acceptor = tls_builder.build();

    let protocol = Arc::new(Http::new());
    let mut listener =
        hyper::server::conn::AddrIncoming::from_listener(listener).map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("Failed to create listener: {:?}", err),
            )
        })?;
    loop {
        if let Some(Ok(stream)) = poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
            let acceptor = acceptor.clone();
            let svc = tower::MakeService::make_service(&mut app, &stream);
            tokio::spawn(handle_conn(acceptor, stream, svc, protocol.clone()));
        }
    }
}

/// This handles an individual connection.
pub(crate) async fn handle_conn(
    acceptor: SslAcceptor,
    stream: AddrStream,
    svc: ResponseFuture<Router, SocketAddr>,
    protocol: Arc<Http>,
) -> Result<(), std::io::Error> {
    let ssl = Ssl::new(acceptor.context()).map_err(|e| {
        error!("Failed to create TLS context: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    let mut tls_stream = SslStream::new(ssl, stream).map_err(|e| {
        error!("Failed to create TLS stream: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    match SslStream::accept(Pin::new(&mut tls_stream)).await {
        Ok(_) => {
            let svc = svc.await.map_err(|e| {
                error!("Failed to build HTTP response: {:?}", e);
                std::io::Error::from(ErrorKind::Other)
            })?;

            protocol
                .serve_connection(tls_stream, svc)
                .await
                .map_err(|e| {
                    debug!("Failed to complete connection: {:?}", e);
                    std::io::Error::from(ErrorKind::ConnectionAborted)
                })
        }
        Err(error) => {
            trace!("Failed to handle connection: {:?}", error);
            Ok(())
        }
    }
}

mod apidocs;
pub(crate) mod cache_buster;
pub(crate) mod errors;
mod extractors;
mod generic;
mod javascript;
mod manifest;
pub(crate) mod middleware;
mod oauth2;
pub(crate) mod trace;
mod v1;
mod v1_domain;
mod v1_oauth2;
mod v1_scim;
mod views;

use self::extractors::ClientConnInfo;
use self::javascript::*;
use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use crate::config::{Configuration, ServerRole};
use crate::CoreAction;

use axum::{
    body::Body,
    extract::connect_info::IntoMakeServiceWithConnectInfo,
    http::{HeaderMap, HeaderValue, Request},
    middleware::{from_fn, from_fn_with_state},
    response::Redirect,
    routing::*,
    Router,
};

use axum_extra::extract::cookie::CookieJar;
use compact_jwt::{error::JwtError, JwsCompact, JwsHs256Signer, JwsVerifier};
use futures::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kanidm_proto::{constants::KSESSIONID, internal::COOKIE_AUTH_SESSION_ID};
use kanidmd_lib::{idm::ClientCertInfo, status::StatusActor};
use openssl::ssl::{Ssl, SslAcceptor};

use kanidm_lib_crypto::x509_cert::{der::Decode, x509_public_key_s256, Certificate};

use serde::de::DeserializeOwned;
use sketching::*;
use std::fmt::Write;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::broadcast,
    sync::mpsc,
    task,
};
use tokio_openssl::SslStream;
use tower::Service;
use tower_http::{services::ServeDir, trace::TraceLayer};
use url::Url;
use uuid::Uuid;

use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::{net::SocketAddr, str::FromStr};

#[derive(Clone)]
pub struct ServerState {
    pub(crate) status_ref: &'static StatusActor,
    pub(crate) qe_w_ref: &'static QueryServerWriteV1,
    pub(crate) qe_r_ref: &'static QueryServerReadV1,
    // Store the token management parts.
    pub(crate) jws_signer: JwsHs256Signer,
    pub(crate) trust_x_forward_for: bool,
    pub(crate) csp_header: HeaderValue,
    pub(crate) origin: Url,
    pub(crate) domain: String,
    // This is set to true by default, and is only false on integration tests.
    pub(crate) secure_cookies: bool,
}

impl ServerState {
    /// Deserialize some input string validating that it was signed by our instance's
    /// HMAC signer. This is used for short lived server-only sessions and context
    /// data. This has applications in both accessing cookie content and header content.
    fn deserialise_from_str<T: DeserializeOwned>(&self, input: &str) -> Option<T> {
        match JwsCompact::from_str(input) {
            Ok(val) => match self.jws_signer.verify(&val) {
                Ok(val) => val.from_json::<T>().ok(),
                Err(err) => {
                    error!(?err, "Failed to deserialise JWT from request");
                    if matches!(err, JwtError::InvalidSignature) {
                        // The server has an ephemeral in memory HMAC signer. This is important as
                        // auth (login) sessions on one node shouldn't validate on another. Sessions
                        // that are shared beween nodes use the internal ECDSA signer.
                        //
                        // But because of this if the server restarts it rolls the key. Additionally
                        // it can occur if the load balancer isn't sticking sessions to the correct
                        // node. That can cause this error. So we want to specifically call it out
                        // to admins so they can investigate that the fault is occurring *outside*
                        // of kanidm.
                        warn!("Invalid Signature errors can occur if your instance restarted recently, if a load balancer is not configured for sticky sessions, or a session was tampered with.");
                    }
                    None
                }
            },
            Err(_) => None,
        }
    }

    #[instrument(level = "trace", skip_all)]
    fn get_current_auth_session_id(&self, headers: &HeaderMap, jar: &CookieJar) -> Option<Uuid> {
        // We see if there is a signed header copy first.
        headers
            .get(KSESSIONID)
            .and_then(|hv| {
                trace!("trying header");
                // Get the first header value.
                hv.to_str().ok()
            })
            .or_else(|| {
                trace!("trying cookie");
                jar.get(COOKIE_AUTH_SESSION_ID).map(|c| c.value())
            })
            .and_then(|s| {
                trace!(id_jws = %s);
                self.deserialise_from_str::<Uuid>(s)
            })
    }
}

pub(crate) fn get_js_files(role: ServerRole) -> Result<Vec<JavaScriptFile>, ()> {
    let mut all_pages: Vec<JavaScriptFile> = Vec::new();

    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        // let's set up the list of js module hashes
        let pkg_path = env!("KANIDM_HTMX_UI_PKG_PATH").to_owned();

        let filelist = [
            "external/bootstrap.bundle.min.js",
            "external/htmx.min.1.9.12.js",
            "external/confetti.js",
            "external/base64.js",
            "modules/cred_update.mjs",
            "pkhtml.js",
            "style.js",
        ];

        for filepath in filelist {
            match generate_integrity_hash(format!("{}/{}", pkg_path, filepath,)) {
                Ok(hash) => {
                    let js = JavaScriptFile { hash };
                    all_pages.push(js)
                }
                Err(err) => {
                    admin_error!(
                        ?err,
                        "Failed to generate integrity hash for {} - cancelling startup!",
                        filepath
                    );
                    return Err(());
                }
            }
        }
    }
    Ok(all_pages)
}

pub async fn create_https_server(
    config: Configuration,
    jws_signer: JwsHs256Signer,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    server_message_tx: broadcast::Sender<CoreAction>,
    maybe_tls_acceptor: Option<SslAcceptor>,
    tls_acceptor_reload_rx: mpsc::Receiver<SslAcceptor>,
) -> Result<task::JoinHandle<()>, ()> {
    let rx = server_message_tx.subscribe();

    let all_js_files = get_js_files(config.role)?;
    // set up the CSP headers
    // script-src 'self'
    //      'sha384-Zao7ExRXVZOJobzS/uMp0P1jtJz3TTqJU4nYXkdmsjpiVD+/wcwCyX7FGqRIqvIz'
    //      'sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM';

    let js_directives = all_js_files
        .into_iter()
        .map(|f| f.hash)
        .collect::<Vec<String>>();

    let js_checksums: String = js_directives
        .iter()
        .fold(String::new(), |mut output, value| {
            let _ = write!(output, " 'sha384-{}'", value);
            output
        });

    let csp_header = format!(
        concat!(
            "default-src 'self'; ",
            "base-uri 'self' https:; ",
            "form-action 'self' https:;",
            "frame-ancestors 'none'; ",
            "img-src 'self' data:; ",
            "worker-src 'none'; ",
            "script-src 'self' 'unsafe-eval'{};",
        ),
        js_checksums
    );

    let csp_header = HeaderValue::from_str(&csp_header).map_err(|err| {
        error!(?err, "Unable to generate content security policy");
    })?;

    let trust_x_forward_for = config.trust_x_forward_for;

    let origin = Url::parse(&config.origin)
        // Should be impossible!
        .map_err(|err| {
            error!(?err, "Unable to parse origin URL - refusing to start. You must correct the value for origin. {:?}", config.origin);
        })?;

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        trust_x_forward_for,
        csp_header,
        origin,
        domain: config.domain.clone(),
        secure_cookies: config.integration_test_config.is_none(),
    };

    let static_routes = match config.role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            Router::new()
                .route("/ui/images/oauth2/:rs_name", get(oauth2::oauth2_image_get))
                .route("/ui/images/domain", get(v1_domain::image_get))
                .route("/manifest.webmanifest", get(manifest::manifest)) // skip_route_check
                // Layers only apply to routes that are *already* added, not the ones
                // added after.
                .layer(middleware::compression::new())
                .layer(from_fn(middleware::caching::cache_me_short))
                .route("/", get(|| async { Redirect::to("/ui") }))
                .nest("/ui", views::view_router())
            // Can't compress on anything that changes
        }
        ServerRole::WriteReplicaNoUI => Router::new(),
    };
    let app = Router::new()
        .merge(oauth2::route_setup(state.clone()))
        .merge(v1_scim::route_setup())
        .merge(v1::route_setup(state.clone()))
        .route("/robots.txt", get(generic::robots_txt));

    let app = match config.role {
        ServerRole::WriteReplicaNoUI => app,
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            let pkg_path = PathBuf::from(env!("KANIDM_HTMX_UI_PKG_PATH"));
            if !pkg_path.exists() {
                eprintln!(
                    "Couldn't find htmx UI package path: ({}), quitting.",
                    env!("KANIDM_HTMX_UI_PKG_PATH")
                );
                std::process::exit(1);
            }
            let pkg_router = Router::new()
                .nest_service("/pkg", ServeDir::new(pkg_path))
                // TODO: Add in the br precompress
                .layer(from_fn(middleware::caching::cache_me_short));

            app.merge(pkg_router)
        }
    };

    // this sets up the default span which logs the URL etc.
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace::DefaultMakeSpanKanidmd::new())
        // setting these to trace because all they do is print "started processing request", and we are already doing that enough!
        .on_response(trace::DefaultOnResponseKanidmd::new());

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
        .route("/status", get(generic::status))
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
        .into_make_service_with_connect_info::<ClientConnInfo>();

    let addr = SocketAddr::from_str(&config.address).map_err(|err| {
        error!(
            "Failed to parse address ({:?}) from config: {:?}",
            config.address, err
        );
    })?;

    info!("Starting the web server...");

    match maybe_tls_acceptor {
        Some(tls_acceptor) => {
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(err) => {
                    error!(?err, "Failed to bind tcp listener");
                    return Err(());
                }
            };
            Ok(task::spawn(server_loop(
                tls_acceptor,
                listener,
                app,
                rx,
                server_message_tx,
                tls_acceptor_reload_rx,
            )))
        }
        None => Ok(task::spawn(server_loop_plaintext(addr, app, rx))),
    }
}

async fn server_loop(
    mut tls_acceptor: SslAcceptor,
    listener: TcpListener,
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    mut rx: broadcast::Receiver<CoreAction>,
    server_message_tx: broadcast::Sender<CoreAction>,
    mut tls_acceptor_reload_rx: mpsc::Receiver<SslAcceptor>,
) {
    pin_mut!(listener);

    loop {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => break,
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let app = app.clone();
                        task::spawn(handle_conn(tls_acceptor, stream, app, addr));
                    }
                    Err(err) => {
                        error!("Web server exited with {:?}", err);
                        if let Err(err) = server_message_tx.send(CoreAction::Shutdown) {
                            error!("Web server failed to send shutdown message! {:?}", err)
                        };
                        break;
                    }
                }
            }
            Some(mut new_tls_acceptor) = tls_acceptor_reload_rx.recv() => {
                std::mem::swap(&mut tls_acceptor, &mut new_tls_acceptor);
                info!("Reloaded http tls acceptor");
            }
        }
    }

    info!("Stopped {}", super::TaskName::HttpsServer);
}

async fn server_loop_plaintext(
    addr: SocketAddr,
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    mut rx: broadcast::Receiver<CoreAction>,
) {
    let listener = axum_server::bind(addr).serve(app);

    pin_mut!(listener);

    loop {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown =>
                        break,
                }
            }
            _ = &mut listener => {}
        }
    }

    info!("Stopped {}", super::TaskName::HttpsServer);
}

/// This handles an individual connection.
pub(crate) async fn handle_conn(
    acceptor: SslAcceptor,
    stream: TcpStream,
    mut app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    addr: SocketAddr,
) -> Result<(), std::io::Error> {
    let ssl = Ssl::new(acceptor.context()).map_err(|e| {
        error!("Failed to create TLS context: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    let mut tls_stream = SslStream::new(ssl, stream).map_err(|err| {
        error!(?err, "Failed to create TLS stream");
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    match SslStream::accept(Pin::new(&mut tls_stream)).await {
        Ok(_) => {
            // Process the client cert (if any)
            let client_cert = if let Some(peer_cert) = tls_stream.ssl().peer_certificate() {
                // TODO: This is where we should be checking the CRL!!!

                // Extract the cert from openssl to x509-cert which is a better
                // parser to handle the various extensions.

                let cert_der = peer_cert.to_der().map_err(|ossl_err| {
                    error!(?ossl_err, "unable to process x509 certificate as DER");
                    std::io::Error::from(ErrorKind::ConnectionAborted)
                })?;

                let certificate = Certificate::from_der(&cert_der).map_err(|ossl_err| {
                    error!(?ossl_err, "unable to process DER certificate to x509");
                    std::io::Error::from(ErrorKind::ConnectionAborted)
                })?;

                let public_key_s256 = x509_public_key_s256(&certificate).ok_or_else(|| {
                    error!("subject public key bitstring is not octet aligned");
                    std::io::Error::from(ErrorKind::ConnectionAborted)
                })?;

                Some(ClientCertInfo {
                    public_key_s256,
                    certificate,
                })
            } else {
                None
            };

            let client_conn_info = ClientConnInfo { addr, client_cert };

            debug!(?client_conn_info);

            let svc = axum_server::service::MakeService::<ClientConnInfo, hyper::Request<Body>>::make_service(
                &mut app,
                client_conn_info,
            );

            let svc = svc.await.map_err(|e| {
                error!("Failed to build HTTP response: {:?}", e);
                std::io::Error::from(ErrorKind::Other)
            })?;

            // Hyper has its own `AsyncRead` and `AsyncWrite` traits and doesn't use tokio.
            // `TokioIo` converts between them.
            let stream = TokioIo::new(tls_stream);

            // Hyper also has its own `Service` trait and doesn't use tower. We can use
            // `hyper::service::service_fn` to create a hyper `Service` that calls our app through
            // `tower::Service::call`.
            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                // We have to clone `tower_service` because hyper's `Service` uses `&self` whereas
                // tower's `Service` requires `&mut self`.
                //
                // We don't need to call `poll_ready` since `Router` is always ready.
                svc.clone().call(request)
            });

            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
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

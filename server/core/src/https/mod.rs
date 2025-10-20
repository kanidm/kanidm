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
use crate::config::{AddressSet, Configuration, ServerRole};
use crate::CoreAction;
use axum::{
    body::Body,
    extract::connect_info::IntoMakeServiceWithConnectInfo,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{from_fn, from_fn_with_state},
    response::{IntoResponse, Redirect, Response},
    routing::*,
    Router,
};
use axum_extra::extract::cookie::CookieJar;
use cidr::IpCidr;
use compact_jwt::{error::JwtError, JwsCompact, JwsHs256Signer, JwsVerifier};
use futures::pin_mut;
use haproxy_protocol::{ProxyHdrV2, RemoteAddress};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kanidm_lib_crypto::x509_cert::{der::Decode, x509_public_key_s256, Certificate};
use kanidm_proto::{constants::KSESSIONID, internal::COOKIE_AUTH_SESSION_ID};
use kanidmd_lib::{idm::ClientCertInfo, status::StatusActor};
use serde::de::DeserializeOwned;
use sketching::*;
use std::fmt::Write;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::broadcast,
    sync::mpsc,
    task,
};
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower_http::{services::ServeDir, trace::TraceLayer};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct ServerState {
    pub(crate) status_ref: &'static StatusActor,
    pub(crate) qe_w_ref: &'static QueryServerWriteV1,
    pub(crate) qe_r_ref: &'static QueryServerReadV1,
    // Store the token management parts.
    pub(crate) jws_signer: JwsHs256Signer,
    pub(crate) trust_x_forward_for_ips: Option<Arc<AddressSet>>,
    pub(crate) csp_header: HeaderValue,
    pub(crate) csp_header_no_form_action: HeaderValue,
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
                        // that are shared between nodes use the internal ECDSA signer.
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
        let pkg_path = env!("KANIDM_SERVER_UI_PKG_PATH").to_owned();

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
            match generate_integrity_hash(format!("{pkg_path}/{filepath}",)) {
                Ok(hash) => {
                    debug!("Integrity hash for {}: {}", filepath, hash);
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

async fn handler_404() -> Response {
    (StatusCode::NOT_FOUND, "Route not found").into_response()
}

pub async fn create_https_server(
    config: Configuration,
    jws_signer: JwsHs256Signer,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    server_message_tx: broadcast::Sender<CoreAction>,
    maybe_tls_acceptor: Option<TlsAcceptor>,
    tls_acceptor_reload_rx: mpsc::Receiver<TlsAcceptor>,
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
            let _ = write!(output, " 'sha384-{value}'");
            output
        });

    let csp_header = format!(
        concat!(
            "default-src 'self'; ",
            "base-uri 'self' https:; ",
            "form-action 'self'; ",
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

    // Omit form action - form action is interpreted by chrome to also control valid
    // redirect targets on submit. This breaks oauth2 in many cases.
    //
    // Normally this would be considered BAD to remove a CSP control to make Oauth2 work
    // but we need to consider the primary attack form-action protects from - open redirectors
    // in the form submission. Since the paths that use this header do NOT have open
    // redirectors, we are safe to remove the form-action directive.
    let csp_header_no_form_action = format!(
        concat!(
            "default-src 'self'; ",
            "base-uri 'self' https:; ",
            "frame-ancestors 'none'; ",
            "img-src 'self' data:; ",
            "worker-src 'none'; ",
            "script-src 'self' 'unsafe-eval'{};",
        ),
        js_checksums
    );

    let csp_header_no_form_action =
        HeaderValue::from_str(&csp_header_no_form_action).map_err(|err| {
            error!(
                ?err,
                "Unable to generate content security policy with no form action"
            );
        })?;

    let trust_x_forward_for_ips = config
        .http_client_address_info
        .trusted_x_forward_for()
        .map(Arc::new);

    let trusted_proxy_v2_ips = config
        .http_client_address_info
        .trusted_proxy_v2()
        .map(Arc::new);

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        trust_x_forward_for_ips,
        csp_header,
        csp_header_no_form_action,
        origin: config.origin,
        domain: config.domain.clone(),
        secure_cookies: config.integration_test_config.is_none(),
    };

    let static_routes = match config.role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            Router::new()
                .route("/ui/images/oauth2/{rs_name}", get(oauth2::oauth2_image_get))
                .route("/ui/images/domain", get(v1_domain::image_get))
                .route("/manifest.webmanifest", get(manifest::manifest)) // skip_route_check
                // Layers only apply to routes that are *already* added, not the ones
                // added after.
                .layer(middleware::compression::new())
                .layer(from_fn(middleware::caching::cache_me_short))
                .route("/", get(|| async { Redirect::to("/ui") }))
                .nest("/ui", views::view_router(state.clone()))
            // Can't compress on anything that changes
        }
        ServerRole::WriteReplicaNoUI => Router::new(),
    };
    let app = Router::new()
        .merge(oauth2::route_setup(state.clone()))
        .merge(v1_scim::route_setup())
        .merge(v1::route_setup(state.clone()))
        .route("/robots.txt", get(generic::robots_txt))
        .route(
            views::constants::Urls::WellKnownChangePassword.as_ref(),
            get(generic::redirect_to_update_credentials),
        );

    let app = match config.role {
        ServerRole::WriteReplicaNoUI => app,
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            let pkg_path = PathBuf::from(env!("KANIDM_SERVER_UI_PKG_PATH"));
            if !pkg_path.exists() {
                eprintln!(
                    "Couldn't find htmx UI package path: ({}), quitting.",
                    env!("KANIDM_SERVER_UI_PKG_PATH")
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
        // 404 handler
        .fallback(handler_404)
        // This must be the LAST middleware.
        // This is because the last middleware here is the first to be entered and the last
        // to be exited, and this middleware sets up ids' and other bits for for logging
        // coherence to be maintained.
        .layer(from_fn_with_state(
            state.clone(),
            middleware::ip_address_middleware,
        ))
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

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(err) => {
            error!(?err, "Failed to bind tcp listener");
            return Err(());
        }
    };

    match maybe_tls_acceptor {
        Some(tls_acceptor) => Ok(task::spawn(server_tls_loop(
            tls_acceptor,
            listener,
            app,
            rx,
            server_message_tx,
            tls_acceptor_reload_rx,
            trusted_proxy_v2_ips,
        ))),
        None => Ok(task::spawn(server_plaintext_loop(
            listener,
            app,
            rx,
            trusted_proxy_v2_ips,
        ))),
    }
}

async fn server_tls_loop(
    mut tls_acceptor: TlsAcceptor,
    listener: TcpListener,
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    mut rx: broadcast::Receiver<CoreAction>,
    server_message_tx: broadcast::Sender<CoreAction>,
    mut tls_acceptor_reload_rx: mpsc::Receiver<TlsAcceptor>,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
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
                        task::spawn(handle_tls_conn(tls_acceptor, stream, app, addr, trusted_proxy_v2_ips.clone()));
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

async fn server_plaintext_loop(
    listener: TcpListener,
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    mut rx: broadcast::Receiver<CoreAction>,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
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
                        let app = app.clone();
                        task::spawn(handle_conn(stream, app, addr, trusted_proxy_v2_ips.clone()));
                    }
                    Err(err) => {
                        error!("Web server exited with {:?}", err);
                        break;
                    }
                }
            }
        }
    }

    info!("Stopped {}", super::TaskName::HttpsServer);
}

/// This handles an individual connection.
pub(crate) async fn handle_conn(
    stream: TcpStream,
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    connection_addr: SocketAddr,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
) -> Result<(), std::io::Error> {
    let (stream, client_ip_addr) =
        process_client_addr(stream, connection_addr, trusted_proxy_v2_ips).await?;

    let client_conn_info = ClientConnInfo {
        connection_addr,
        client_ip_addr,
        client_cert: None,
    };

    // Hyper has its own `AsyncRead` and `AsyncWrite` traits and doesn't use tokio.
    // `TokioIo` converts between them.
    let stream = TokioIo::new(stream);

    process_client_hyper(stream, app, client_conn_info).await
}

/// This handles an individual connection.
pub(crate) async fn handle_tls_conn(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    connection_addr: SocketAddr,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
) -> Result<(), std::io::Error> {
    let (stream, client_ip_addr) =
        process_client_addr(stream, connection_addr, trusted_proxy_v2_ips).await?;

    let tls_stream = acceptor.accept(stream).await.map_err(|err| {
        error!(?err, "Failed to create TLS stream");
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    let maybe_peer_cert = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        // The first certificate relates to the peer.
        .and_then(|peer_certs| peer_certs.first());

    // Process the client cert (if any)
    let client_cert = if let Some(peer_cert) = maybe_peer_cert {
        // We don't need to check the CRL here - it's already completed as part of the
        // TLS connection establishment process.

        // Extract the cert from rustls DER to x509-cert which is a better
        // parser to handle the various extensions.
        let certificate = Certificate::from_der(peer_cert).map_err(|ossl_err| {
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

    let client_conn_info = ClientConnInfo {
        connection_addr,
        client_ip_addr,
        client_cert,
    };

    // Hyper has its own `AsyncRead` and `AsyncWrite` traits and doesn't use tokio.
    // `TokioIo` converts between them.
    let stream = TokioIo::new(tls_stream);

    process_client_hyper(stream, app, client_conn_info).await
}

async fn process_client_addr(
    stream: TcpStream,
    connection_addr: SocketAddr,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
) -> Result<(TcpStream, IpAddr), std::io::Error> {
    let enable_proxy_v2_hdr = trusted_proxy_v2_ips
        .map(|trusted| {
            trusted
                .iter()
                .any(|ip_cidr| ip_cidr.contains(&connection_addr.ip().to_canonical()))
        })
        .unwrap_or_default();

    let (stream, client_addr) = if enable_proxy_v2_hdr {
        match ProxyHdrV2::parse_from_read(stream).await {
            Ok((stream, hdr)) => {
                let remote_socket_addr = match hdr.to_remote_addr() {
                    RemoteAddress::Local => {
                        debug!("PROXY protocol liveness check - will not contain client data");
                        // This is a check from the proxy, so just use the connection address.
                        connection_addr
                    }
                    RemoteAddress::TcpV4 { src, dst: _ } => SocketAddr::from(src),
                    RemoteAddress::TcpV6 { src, dst: _ } => SocketAddr::from(src),
                    remote_addr => {
                        error!(?remote_addr, "remote address in proxy header is invalid");
                        return Err(std::io::Error::from(ErrorKind::ConnectionAborted));
                    }
                };

                (stream, remote_socket_addr)
            }
            Err(err) => {
                error!(?connection_addr, ?err, "Unable to process proxy v2 header");
                return Err(std::io::Error::from(ErrorKind::ConnectionAborted));
            }
        }
    } else {
        (stream, connection_addr)
    };

    Ok((stream, client_addr.ip()))
}

async fn process_client_hyper<T>(
    stream: TokioIo<T>,
    mut app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    client_conn_info: ClientConnInfo,
) -> Result<(), std::io::Error>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::marker::Send + 'static,
{
    debug!(?client_conn_info);

    let svc = tower::MakeService::<ClientConnInfo, hyper::Request<Body>>::make_service(
        &mut app,
        client_conn_info,
    );

    let svc = svc.await.map_err(|e| {
        error!("Failed to build HTTP response: {:?}", e);
        std::io::Error::from(ErrorKind::Other)
    })?;

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

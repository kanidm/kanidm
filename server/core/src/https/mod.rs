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

use self::extractors::ClientConnInfo;
use self::javascript::*;
use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use crate::config::{Configuration, ServerRole, TlsConfiguration};
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Redirect;
use axum::routing::*;
use axum::Router;
use axum_csp::{CspDirectiveType, CspValue};
use axum_macros::FromRef;
use compact_jwt::{JwsCompact, JwsHs256Signer, JwsVerifier};
use hashbrown::HashMap;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrStream, Http};
use kanidm_proto::constants::KSESSIONID;
use kanidmd_lib::idm::ClientCertInfo;
use kanidmd_lib::status::StatusActor;
use openssl::nid;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslSessionCacheMode, SslVerifyMode};
use openssl::x509::X509;
use sketching::*;
use tokio_openssl::SslStream;

use futures_util::future::poll_fn;
use tokio::net::TcpListener;

use std::fs;
use std::io::{ErrorKind, Read};
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
    pub status_ref: &'static StatusActor,
    pub qe_w_ref: &'static QueryServerWriteV1,
    pub qe_r_ref: &'static QueryServerReadV1,
    // Store the token management parts.
    pub jws_signer: JwsHs256Signer,
    // The SHA384 hashes of javascript files we're going to serve to users
    pub js_files: JavaScriptFiles,
    pub(crate) trust_x_forward_for: bool,
    pub csp_header: HeaderValue,
}

impl ServerState {
    fn reinflate_uuid_from_bytes(&self, input: &str) -> Option<Uuid> {
        match JwsCompact::from_str(input) {
            Ok(val) => match self.jws_signer.verify(&val) {
                Ok(val) => val.from_json::<SessionId>().ok(),
                Err(err) => {
                    error!("Failed to unmarshal JWT from headers: {:?}", err);
                    None
                }
            }
            .map(|inner| inner.sessionid),
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
                            dynamic: false,
                            hash,
                            filetype: Some("module".to_string()),
                        },
                    );
                }
                Err(err) => {
                    admin_error!(
                        ?err,
                        "Failed to generate integrity hash for {} - cancelling startup!",
                        filepath
                    );
                    return Err(());
                }
            };
        }

        for (filepath, filetype, dynamic) in [
            ("shared.js", Some("module".to_string()), false),
            ("external/bootstrap.bundle.min.js", None, false),
            ("external/viz.js", None, true),
        ] {
            // let's set up the list of non-wasm-module js files we want to serve
            // for filepath in ["external/bootstrap.bundle.min.js", "shared.js"] {
            match generate_integrity_hash(format!(
                "{}/{}",
                env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                filepath,
            )) {
                Ok(hash) => all_pages.push(JavaScriptFile {
                    filepath,
                    dynamic,
                    hash,
                    filetype,
                }),
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
    Ok(JavaScriptFiles {
        all_pages,
        selected,
    })
}

pub async fn create_https_server(
    config: Configuration,
    jws_signer: JwsHs256Signer,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
    server_message_tx: broadcast::Sender<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
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
            vec![
                CspValue::SelfSite,
                CspValue::SchemeData,
                CspValue::SchemeOther {
                    value: "blob:".into(),
                },
            ],
        );

    let trust_x_forward_for = config.trust_x_forward_for;

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        js_files,
        trust_x_forward_for,
        csp_header: csp_header.finish(),
    };

    let static_routes = match config.role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            // Create a spa router that captures everything at ui without key extraction.

            Router::new()
                // Direct users to the base app page. If a login is required,
                // then views will take care of redirection.
                .route("/", get(|| async { Redirect::temporary("/ui") }))
                .route("/manifest.webmanifest", get(manifest::manifest)) // skip_route_check
                // user UI app is the catch-all
                .nest("/ui", ui::spa_router_user_ui())
                // login flows app
                .nest("/ui/login", ui::spa_router_login_flows())
                .nest("/ui/reauth", ui::spa_router_login_flows())
                .nest("/ui/oauth2", ui::spa_router_login_flows())
                // admin app
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
                .layer(middleware::compression::new())
                .layer(from_fn(middleware::caching::cache_me));
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
                match res {
                    Ok(res_inner) => {
                        match res_inner {
                            Ok(_) => debug!("Web server exited OK"),
                            Err(err) => {
                                error!("Web server exited with {:?}", err);
                            }
                        }

                    },
                    Err(err) => {
                        error!("Web server exited with {:?}", err);
                    }
                };
                if let Err(err) = server_message_tx.send(CoreAction::Shutdown) {
                    error!("Web server failed to send shutdown message! {:?}", err)
                };
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
    app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
) -> Result<(), std::io::Error> {
    let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

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

    // If configured, setup TLS client authentication.
    if let Some(client_ca) = tls_param.client_ca.as_ref() {
        info!("Loading client certificates from {}", client_ca.display());

        let verify = SslVerifyMode::PEER;
        // In future we may add a "require mTLS option" which would necesitate this.
        // verify.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        tls_builder.set_verify(verify);

        // When client certs are available, we disable the TLS session cache.
        // This is so that when the smartcard is *removed* on the client, it forces
        // the client session to immediately expire.
        //
        // https://stackoverflow.com/questions/12393711/session-disconnect-the-client-after-smart-card-is-removed
        //
        // Alternately, on logout we need to trigger https://docs.rs/openssl/latest/openssl/ssl/struct.Ssl.html#method.set_ssl_context
        // with https://docs.rs/openssl/latest/openssl/ssl/struct.Ssl.html#method.ssl_context +
        // https://docs.rs/openssl/latest/openssl/ssl/struct.SslContextRef.html#method.remove_session
        //
        // Or we lower session time outs etc.
        tls_builder.set_session_cache_mode(SslSessionCacheMode::OFF);

        let read_dir = fs::read_dir(client_ca).map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to create TLS listener while loading client ca from {}: {:?}",
                    client_ca.display(),
                    err
                ),
            )
        })?;

        for cert_dir_ent in read_dir.filter_map(|item| item.ok()).filter(|item| {
            item.file_name()
                .to_str()
                // Hashed certs end in .0
                // Hsahed crls are .r0
                .map(|fname| fname.ends_with(".0"))
                .unwrap_or_default()
        }) {
            let mut cert_pem = String::new();
            fs::File::open(cert_dir_ent.path())
                .and_then(|mut file| file.read_to_string(&mut cert_pem))
                .map_err(|err| {
                    std::io::Error::new(
                        ErrorKind::Other,
                        format!("Failed to create TLS listener: {:?}", err),
                    )
                })?;

            let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|err| {
                std::io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to create TLS listener: {:?}", err),
                )
            })?;

            let cert_store = tls_builder.cert_store_mut();
            cert_store.add_cert(cert.clone()).map_err(|err| {
                std::io::Error::new(
                    ErrorKind::Other,
                    format!(
                        "Failed to load cert store while creating TLS listener: {:?}",
                        err
                    ),
                )
            })?;
            // This tells the client what CA's they should use. It DOES NOT
            // verify them. That's the job of the cert store above!
            tls_builder.add_client_ca(&cert).map_err(|err| {
                std::io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to create TLS listener: {:?}", err),
                )
            })?;
        }

        // TODO: Build our own CRL map HERE!

        // Allow dumping client cert chains for dev debugging
        // In the case this is status=false, should we be dumping these anyway?
        if enabled!(tracing::Level::TRACE) {
            tls_builder.set_verify_callback(verify, |status, x509store| {
                if let Some(current_cert) = x509store.current_cert() {
                    let cert_text_bytes = current_cert.to_text().unwrap_or_default();
                    let cert_text = String::from_utf8_lossy(cert_text_bytes.as_slice());
                    tracing::warn!(client_cert = %cert_text);
                };

                if let Some(chain) = x509store.chain() {
                    for cert in chain.iter() {
                        let cert_text_bytes = cert.to_text().unwrap_or_default();
                        let cert_text = String::from_utf8_lossy(cert_text_bytes.as_slice());
                        tracing::warn!(chain_cert = %cert_text);
                    }
                }

                status
            });
        }

        // End tls_client setup
    }

    let tls_acceptor = tls_builder.build();

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
            let tls_acceptor = tls_acceptor.clone();
            let app = app.clone();

            // let svc = tower::MakeService::make_service(&mut app, &stream);
            // tokio::spawn(handle_conn(tls_acceptor, stream, svc, protocol.clone()));
            tokio::spawn(handle_conn(tls_acceptor, stream, app, protocol.clone()));
        }
    }
}

/// This handles an individual connection.
pub(crate) async fn handle_conn(
    acceptor: SslAcceptor,
    stream: AddrStream,
    // svc: ResponseFuture<Router, ClientConnInfo>,
    mut app: IntoMakeServiceWithConnectInfo<Router, ClientConnInfo>,
    protocol: Arc<Http>,
) -> Result<(), std::io::Error> {
    let ssl = Ssl::new(acceptor.context()).map_err(|e| {
        error!("Failed to create TLS context: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    let addr = stream.remote_addr();

    let mut tls_stream = SslStream::new(ssl, stream).map_err(|e| {
        error!("Failed to create TLS stream: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    match SslStream::accept(Pin::new(&mut tls_stream)).await {
        Ok(_) => {
            // Process the client cert (if any)
            let client_cert = if let Some(peer_cert) = tls_stream.ssl().peer_certificate() {
                // TODO: This is where we should be checking the CRL!!!

                let subject_key_id = peer_cert
                    .subject_key_id()
                    .map(|ski| ski.as_slice().to_vec());

                let cn = if let Some(cn) = peer_cert
                    .subject_name()
                    .entries_by_nid(nid::Nid::COMMONNAME)
                    .next()
                {
                    String::from_utf8(cn.data().as_slice().to_vec())
                        .map_err(|err| {
                            warn!(?err, "client certificate CN contains invalid utf-8 - the CN will be ignored!");
                        })
                        .ok()
                } else {
                    None
                };

                Some(ClientCertInfo { subject_key_id, cn })
            } else {
                None
            };

            let client_conn_info = ClientConnInfo { addr, client_cert };

            debug!(?client_conn_info);

            let svc = tower::MakeService::make_service(&mut app, client_conn_info);

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

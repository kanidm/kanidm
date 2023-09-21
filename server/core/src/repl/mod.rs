use futures_util::future::poll_fn;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, Http};
use openssl::{
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::X509,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::error;

use crate::https::trace;
use tower_http::trace::{DefaultOnRequest, TraceLayer};
use tracing::Level;

use kanidmd_lib::prelude::duration_from_epoch_now;
use kanidmd_lib::prelude::IdmServer;

use crate::config::RepNodeConfig;
use crate::config::ReplicationConfiguration;
use crate::https::handle_conn;
use crate::https::middleware;
use crate::CoreAction;

use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

pub(crate) async fn create_repl_server(
    idms: Arc<IdmServer>,
    repl_config: &ReplicationConfiguration,
    rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    /*
    let address = repl_config.bindaddress.as_str();
    if address.starts_with(":::") {
        // takes :::xxxx to xxxx
        let port = address.replacen(":::", "", 1);
        error!("Address '{}' looks like an attempt to wildcard bind with IPv6 on port {} - please try using ldapbindaddress = '[::]:{}'", address, port, port);
    };

    let addr = net::SocketAddr::from_str(address).map_err(|e| {
        error!("Could not parse LDAP server address {} -> {:?}", address, e);
    })?;
    */

    // We need to start the tcp listener. This will persist over ssl reloads!
    let listener = TcpListener::bind(&repl_config.bindaddress)
        .await
        .map_err(|e| {
            error!(
                "Could not bind to LDAP server address {} -> {:?}",
                repl_config.bindaddress, e
            );
        })?;

    let listener = hyper::server::conn::AddrIncoming::from_listener(listener)
        .map_err(|err| error!(?err, "Unable to spawn hyper server from listener"))?;

    // We need to start the tcp listener. This will persist over ssl reloads!
    info!(
        "Starting replication interface https://{} ...",
        repl_config.bindaddress
    );
    let repl_handle = tokio::spawn(repl_acceptor(listener, idms, repl_config.clone(), rx));

    info!("Created replication interface");
    Ok(repl_handle)
}

async fn repl_acceptor(
    mut listener: AddrIncoming,
    idms: Arc<IdmServer>,
    repl_config: ReplicationConfiguration,
    mut rx: broadcast::Receiver<CoreAction>,
) {
    // Setup the routes for the replication app

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace::DefaultMakeSpanKanidmd::new())
        // setting these to trace because all they do is print "started processing request", and we are already doing that enough!
        .on_request(DefaultOnRequest::new().level(Level::TRACE));

    let mut app = Router::new()
        .route("/test", get(test))
        // This must be the LAST middleware.
        // This is because the last middleware here is the first to be entered and the last
        // to be exited, and this middleware sets up ids' and other bits for for logging
        // coherence to be maintained.
        .layer(from_fn(middleware::kopid_middleware))
        // this MUST be the last layer before with_state else the span never starts and everything breaks.
        .layer(trace_layer)
        // .with_state(state)
        // the connect_info bit here lets us pick up the remote address of the client
        .into_make_service_with_connect_info::<SocketAddr>();

    // Persistent parts
    let retry_timeout = Duration::from_secs(60);
    let protocol = Arc::new(Http::new());

    // Create another broadcast to control the replication tasks and their need to reload.

    // Spawn a KRC communication task?

    // In future we need to update this from the KRC if configured, and we default this
    // to "empty". But if this map exists in the config, we have to always use that.
    let replication_node_map = repl_config.manual.clone();

    // This needs to have an event loop that can respond to changes.
    // For now we just design it to reload ssl if the map changes internally.
    'event: loop {
        // Get the private key / cert.
        let (server_key, server_cert) = {
            // Does this actually need to be a read incase we need to write
            // to sqlite?
            let ct = duration_from_epoch_now();
            let mut idms_prox_write = idms.proxy_write(ct).await;
            let res = idms_prox_write
                .qs_write
                .supplier_get_key_cert()
                .and_then(|res| idms_prox_write.commit().map(|()| res));

            match res {
                Ok(r) => r,
                Err(err) => {
                    error!(?err, "CRITICAL: Unable to access supplier certificate/key.");
                    continue;
                }
            }
        };

        // Filter and get the list of certs that are allowed in the client
        // list.
        let client_certs: Vec<X509> = replication_node_map
            .values()
            .filter_map(|node| match node {
                RepNodeConfig::AllowPull { consumer_cert } => Some(consumer_cert.clone()),
                RepNodeConfig::Pull { .. } => None,
            })
            .collect();

        // ⚠️  This section is critical to the security of replication
        //    Since replication relies on mTLS we MUST ensure these options
        //    are absolutely correct!
        //
        // Setup the TLS builder.
        let mut tls_builder = match SslAcceptor::mozilla_modern_v5(SslMethod::tls()) {
            Ok(tls_builder) => tls_builder,
            Err(err) => {
                error!(?err, "CRITICAL, unable to create SslAcceptorBuilder.");
                sleep(retry_timeout).await;
                continue;
            }
        };

        // tls_builder.set_keylog_callback(keylog_cb);
        if let Err(err) = tls_builder
            .set_certificate(&server_cert)
            .and_then(|_| tls_builder.set_private_key(&server_key))
            .and_then(|_| tls_builder.check_private_key())
        {
            error!(?err, "CRITICAL, unable to set server_cert and server key.");
            sleep(retry_timeout).await;
            continue;
        };

        // ⚠️  CRITICAL - ensure that the cert store only has client certs from
        // the repl map added.
        let cert_store = tls_builder.cert_store_mut();
        for client_cert in client_certs.into_iter() {
            if let Err(err) = cert_store.add_cert(client_cert.clone()) {
                error!(?err, "CRITICAL, unable to add client certificates.");
                sleep(retry_timeout).await;
                continue;
            }
        }

        // ⚠️  CRITICAL - Both verifications here are needed. PEER requests
        // the client cert to be sent. FAIL_IF_NO_PEER_CERT triggers an
        // error if the cert is NOT present. FAIL_IF_NO_PEER_CERT on it's own
        // DOES NOTHING.
        let mut verify = SslVerifyMode::PEER;
        verify.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        tls_builder.set_verify(verify);

        let tls_acceptor = tls_builder.build();

        loop {
            tokio::select! {
                Ok(action) = rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break 'event,
                    }
                }
                // Handle accepts.
                // Handle *reloads*
                /*
                _ = reload.recv() => {
                    info!("initiate tls reload");
                    continue
                }
                */

                Some(Ok(stream)) = poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)) => {
                    let acceptor = tls_acceptor.clone();
                    let svc = tower::MakeService::make_service(&mut app, &stream);
                    tokio::spawn(handle_conn(acceptor, stream, svc, protocol.clone()));
                }
            }
            // Continue to poll/loop
        }
    }
    info!("Stopped Replication Acceptor");
}

async fn test() -> impl IntoResponse {
    axum::response::Html(
        r#"
Testing!
"#,
    )
}

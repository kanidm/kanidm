use futures_util::future::poll_fn;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, Http};
use openssl::{
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::{timeout, interval, sleep};
use tracing::error;
use url::Url;
use uuid::Uuid;

use http::{Request, StatusCode};
use hyper::{client::conn, Body};

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

pub(crate) enum ReplCtrl {
    GetCertificate { respond: oneshot::Sender<X509> },
}

pub(crate) async fn create_repl_server(
    idms: Arc<IdmServer>,
    repl_config: &ReplicationConfiguration,
    rx: broadcast::Receiver<CoreAction>,
) -> Result<(tokio::task::JoinHandle<()>, mpsc::Sender<ReplCtrl>), ()> {
    // We need to start the tcp listener. This will persist over ssl reloads!
    let listener = TcpListener::bind(&repl_config.bindaddress)
        .await
        .map_err(|e| {
            error!(
                "Could not bind to replication address {} -> {:?}",
                repl_config.bindaddress, e
            );
        })?;

    let listener = hyper::server::conn::AddrIncoming::from_listener(listener)
        .map_err(|err| error!(?err, "Unable to spawn hyper server from listener"))?;

    // Create the control channel. Use a low msg count, there won't be that much going on.
    let (ctrl_tx, ctrl_rx) = mpsc::channel(4);

    // We need to start the tcp listener. This will persist over ssl reloads!
    info!(
        "Starting replication interface https://{} ...",
        repl_config.bindaddress
    );
    let repl_handle = tokio::spawn(repl_acceptor(
        listener,
        idms,
        repl_config.clone(),
        rx,
        ctrl_rx,
    ));

    info!("Created replication interface");
    Ok((repl_handle, ctrl_tx))
}

async fn repl_run_consumer(
    sock_addrs: &[SocketAddr],
    tls_connector: &SslConnector,
    _automatic_refresh: bool,
    _idms: &IdmServer,
) {
    let replica_connect_timeout = Duration::from_secs(2);

    // This is pretty gnarly, but we need to loop to try out each socket addr.

    for sock_addr in sock_addrs {

        let tcpclient = match TcpStream::connect(server_addr).await 
        {
            Ok(tc) => tc,
            Err(err) => {
                error!("Failed to connect to {}", server_addr);
                continue;
            }
        }

        trace!("connection established");

        let tlsstream = Ssl::new(tls_connector.context())
            .and_then(|tls_obj| SslStream::new(tls_obj, tcpclient))
            .unwrap();

        let (mut request_sender, connection) = conn::handshake(target_stream).await?;

        // Now we can do requests.



        return;
    }

    error!("Unable to complete replication successfully.");

}

async fn repl_task(
    origin: Url,
    client_key: PKey<Private>,
    client_cert: X509,
    supplier_cert: X509,
    task_poll_interval: Duration,
    mut task_rx: broadcast::Receiver<()>,
    automatic_refresh: bool,
    idms: Arc<IdmServer>,
) {
    if origin.scheme() != "https" {
        error!("Replica origin is not https - refusing to proceed.");
        return;
    }

    let domain = match origin.domain() {
        Some(d) => d,
        None => {
            error!("Replica origin does not have a valid domain name, unable to proceed. Perhaps you tried to use an ip address?");
            return;
        }
    };

    let socket_addrs = match origin.socket_addrs(|| Some(443)) {
        Ok(sa) => sa,
        Err(err) => {
            error!(?err, "Replica origin could not resolve to ip:port");
            return;
        }
    };

    // Setup our tls connector.
    let mut ssl_builder = match SslConnector::builder(SslMethod::tls_client()) {
        Ok(sb) => sb,
        Err(err) => {
            error!(?err, "Unable to configure tls connector");
            return;
        }
    };

    let setup_client_cert = ssl_builder
        .set_certificate(&client_cert)
        .and_then(|_| ssl_builder.set_private_key(&client_key))
        .and_then(|_| ssl_builder.check_private_key());
    if let Err(err) = setup_client_cert {
        error!(?err, "Unable to configure client certificate/key");
        return;
    }

    // Add the supplier cert.
    // ⚠️  note that here we need to build a new cert store. This is because
    // openssl SslConnector adds the default system cert locations with
    // the call to ::builder and we *don't* want this. We want our certstore
    // to pin a single certificate!
    let mut cert_store = match X509StoreBuilder::new() {
        Ok(csb) => csb,
        Err(err) => {
            error!(?err, "Unable to configure certificate store builder.");
            return;
        }
    };

    if let Err(err) = cert_store.add_cert(supplier_cert) {
        error!(?err, "Unable to add supplier certificate to cert store");
        return;
    }

    let cert_store = cert_store.build();
    ssl_builder.set_cert_store(cert_store);

    // Configure the expected hostname of the remote.
    let verify_param = ssl_builder.verify_param_mut();
    if let Err(err) = verify_param.set_host(domain) {
        error!(?err, "Unable to set domain name for tls peer verification");
        return;
    }

    ssl_builder.set_verify(SslVerifyMode::PEER);
    let tls_connector = ssl_builder.build();

    let mut repl_interval = interval(task_poll_interval);

    info!("Replica task for {} has started.", origin);

    // Okay, all the parameters are setup. Now we wait on our interval.
    loop {
        tokio::select! {
            Ok(()) = task_rx.recv() => {
                break;
            }
            _ = repl_interval.tick() => {
                // Interval passed, attempt a replication run.
                let eventid = Uuid::new_v4();
                let span = info_span!("replication_run_consumer", uuid = ?eventid);
                let _enter = span.enter();
                repl_run_consumer(
                    &socket_addrs,
                    &tls_connector,
                    automatic_refresh,
                    &idms
                ).await;
            }
        }
    }

    info!("Replica task for {} has stopped.", origin);
}

async fn repl_acceptor(
    mut listener: AddrIncoming,
    idms: Arc<IdmServer>,
    repl_config: ReplicationConfiguration,
    mut rx: broadcast::Receiver<CoreAction>,
    mut ctrl_rx: mpsc::Receiver<ReplCtrl>,
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
    let task_poll_interval = Duration::from_secs(30);
    let retry_timeout = Duration::from_secs(60);
    let protocol = Arc::new(Http::new());

    // Setup a broadcast to control our tasks.
    let (task_tx, task_rx1) = broadcast::channel(2);
    // Note, we drop this task here since each task will re-subscribe. That way the
    // broadcast doesn't jam up because we aren't draining this task.
    drop(task_rx1);
    let mut task_handles = VecDeque::new();

    // Create another broadcast to control the replication tasks and their need to reload.

    // Spawn a KRC communication task?

    // In future we need to update this from the KRC if configured, and we default this
    // to "empty". But if this map exists in the config, we have to always use that.
    let replication_node_map = repl_config.manual.clone();

    // This needs to have an event loop that can respond to changes.
    // For now we just design it to reload ssl if the map changes internally.
    'event: loop {
        // Tell existing tasks to shutdown.
        // Note: We ignore the result here since an err can occur *if* there are
        // no tasks currently listening on the channel.
        debug_assert!(task_handles.len() == task_tx.receiver_count());
        let _ = task_tx.send(());
        for task_handle in task_handles.drain(..) {
            // Let each task join.
            let res: Result<(), _> = task_handle.await;
            if res.is_err() {
                warn!("Failed to join replication task, continuing ...");
            }
        }

        // Now we can start to re-load configurations and setup our client tasks
        // as well.

        // Get the private key / cert.
        let res = {
            // Does this actually need to be a read incase we need to write
            // to sqlite?
            let ct = duration_from_epoch_now();
            let mut idms_prox_write = idms.proxy_write(ct).await;
            idms_prox_write
                .qs_write
                .supplier_get_key_cert()
                .and_then(|res| idms_prox_write.commit().map(|()| res))
        };

        let (server_key, server_cert) = match res {
            Ok(r) => r,
            Err(err) => {
                error!(?err, "CRITICAL: Unable to access supplier certificate/key.");
                sleep(retry_timeout).await;
                continue;
            }
        };

        let mut client_certs = Vec::new();

        // For each node in the map, either spawn a task to pull from that node,
        // or setup the node as allowed to pull from us.
        for (origin, node) in replication_node_map.iter() {
            match node {
                RepNodeConfig::AllowPull { consumer_cert } => {
                    client_certs.push(consumer_cert.clone())
                }
                RepNodeConfig::Pull {
                    supplier_cert,
                    automatic_refresh,
                } => {
                    let task_rx = task_tx.subscribe();

                    let handle = tokio::spawn(repl_task(
                        origin.clone(),
                        server_key.clone(),
                        server_cert.clone(),
                        supplier_cert.clone(),
                        task_poll_interval,
                        task_rx,
                        *automatic_refresh,
                        idms.clone(),
                    ));

                    task_handles.push_back(handle);
                    debug_assert!(task_handles.len() == task_tx.receiver_count());
                }
            }
        }

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
                Some(ctrl_msg) = ctrl_rx.recv() => {
                    match ctrl_msg {
                        ReplCtrl::GetCertificate {
                            respond
                        } => {
                            if let Err(_) = respond.send(server_cert.clone()) {
                                warn!("Server certificate was requested, but requsetor disconnected");
                            } else {
                                trace!("Sent server certificate via control channel");
                            }
                        }
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
    // Shutdown child tasks.
    info!("Stopping {} Replication Tasks ...", task_handles.len());
    debug_assert!(task_handles.len() == task_tx.receiver_count());
    let _ = task_tx.send(());
    for task_handle in task_handles.drain(..) {
        // Let each task join.
        let res: Result<(), _> = task_handle.await;
        if res.is_err() {
            warn!("Failed to join replication task, continuing ...");
        }
    }

    info!("Stopped Replication Acceptor");
}

async fn test() -> impl IntoResponse {
    axum::response::Html("Ok")
}

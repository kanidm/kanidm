use openssl::{
    pkey::{PKey, Private},
    ssl::{Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::{interval, sleep, timeout};
use tokio_openssl::SslStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, Instrument};
use url::Url;
use uuid::Uuid;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;

use kanidmd_lib::prelude::duration_from_epoch_now;
use kanidmd_lib::prelude::IdmServer;
use kanidmd_lib::repl::proto::ConsumerState;
use kanidmd_lib::server::QueryServerTransaction;

use crate::config::RepNodeConfig;
use crate::config::ReplicationConfiguration;
use crate::CoreAction;

use self::codec::{ConsumerRequest, SupplierResponse};

mod codec;

pub(crate) enum ReplCtrl {
    GetCertificate { respond: oneshot::Sender<X509> },
    RenewCertificate { respond: oneshot::Sender<bool> },
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

#[instrument(level = "info", skip_all)]
async fn repl_run_consumer(
    max_frame_bytes: usize,
    domain: &str,
    sock_addrs: &[SocketAddr],
    tls_connector: &SslConnector,
    automatic_refresh: bool,
    idms: &IdmServer,
) {
    let replica_connect_timeout = Duration::from_secs(2);

    // This is pretty gnarly, but we need to loop to try out each socket addr.
    for sock_addr in sock_addrs {
        debug!("Connecting to {} replica via {}", domain, sock_addr);

        let tcpstream = match timeout(replica_connect_timeout, TcpStream::connect(sock_addr)).await
        {
            Ok(Ok(tc)) => tc,
            Ok(Err(err)) => {
                error!(?err, "Failed to connect to {}", sock_addr);
                continue;
            }
            Err(_) => {
                error!("Timeout connecting to {}", sock_addr);
                continue;
            }
        };

        trace!("connection established");

        let mut tlsstream = match Ssl::new(tls_connector.context())
            .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
        {
            Ok(ta) => ta,
            Err(e) => {
                error!("replication client TLS setup error, continuing -> {:?}", e);
                continue;
            }
        };

        if let Err(e) = SslStream::connect(Pin::new(&mut tlsstream)).await {
            error!("replication client TLS accept error, continuing -> {:?}", e);
            continue;
        };
        let (r, w) = tokio::io::split(tlsstream);
        let mut r = FramedRead::new(r, codec::ConsumerCodec::new(max_frame_bytes));
        let mut w = FramedWrite::new(w, codec::ConsumerCodec::new(max_frame_bytes));

        // Perform incremental.
        let consumer_ruv_range = {
            let mut read_txn = idms.proxy_read().await;
            match read_txn.qs_read.consumer_get_state() {
                Ok(ruv_range) => ruv_range,
                Err(err) => {
                    error!(
                        ?err,
                        "consumer ruv range could not be accessed, unable to continue."
                    );
                    break;
                }
            }
        };

        if let Err(err) = w
            .send(ConsumerRequest::Incremental(consumer_ruv_range))
            .await
        {
            error!(?err, "consumer encode error, unable to continue.");
            break;
        }

        let changes = if let Some(codec_msg) = r.next().await {
            match codec_msg {
                Ok(SupplierResponse::Incremental(changes)) => {
                    // Success - return to bypass the error message.
                    changes
                }
                Ok(SupplierResponse::Pong) | Ok(SupplierResponse::Refresh(_)) => {
                    error!("Supplier Response contains invalid State");
                    break;
                }
                Err(err) => {
                    error!(?err, "consumer decode error, unable to continue.");
                    break;
                }
            }
        } else {
            error!("Connection closed");
            break;
        };

        // Now apply the changes if possible
        let consumer_state = {
            let ct = duration_from_epoch_now();
            let mut write_txn = idms.proxy_write(ct).await;
            match write_txn
                .qs_write
                .consumer_apply_changes(&changes)
                .and_then(|cs| write_txn.commit().map(|()| cs))
            {
                Ok(state) => state,
                Err(err) => {
                    error!(?err, "consumer was not able to apply changes.");
                    break;
                }
            }
        };

        match consumer_state {
            ConsumerState::Ok => {
                info!("Incremental Replication Success");
                // return to bypass the failure message.
                return;
            }
            ConsumerState::RefreshRequired => {
                if automatic_refresh {
                    warn!("Consumer is out of date and must be refreshed. This will happen *now*.");
                } else {
                    error!("Consumer is out of date and must be refreshed. You must manually resolve this situation.");
                    return;
                };
            }
        }

        if let Err(err) = w.send(ConsumerRequest::Refresh).await {
            error!(?err, "consumer encode error, unable to continue.");
            break;
        }

        let refresh = if let Some(codec_msg) = r.next().await {
            match codec_msg {
                Ok(SupplierResponse::Refresh(changes)) => {
                    // Success - return to bypass the error message.
                    changes
                }
                Ok(SupplierResponse::Pong) | Ok(SupplierResponse::Incremental(_)) => {
                    error!("Supplier Response contains invalid State");
                    break;
                }
                Err(err) => {
                    error!(?err, "consumer decode error, unable to continue.");
                    break;
                }
            }
        } else {
            error!("Connection closed");
            break;
        };

        // Now apply the refresh if possible
        let ct = duration_from_epoch_now();
        let mut write_txn = idms.proxy_write(ct).await;
        if let Err(err) = write_txn
            .qs_write
            .consumer_apply_refresh(&refresh)
            .and_then(|cs| write_txn.commit().map(|()| cs))
        {
            error!(?err, "consumer was not able to apply refresh.");
            break;
        }

        warn!("Replication refresh was successful.");
        return;
    }

    error!("Unable to complete replication successfully.");
}

async fn repl_task(
    origin: Url,
    client_key: PKey<Private>,
    client_cert: X509,
    supplier_cert: X509,
    max_frame_bytes: usize,
    task_poll_interval: Duration,
    mut task_rx: broadcast::Receiver<()>,
    automatic_refresh: bool,
    idms: Arc<IdmServer>,
) {
    if origin.scheme() != "repl" {
        error!("Replica origin is not repl:// - refusing to proceed.");
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

    // Assert the expected supplier certificate is correct and has a valid domain san
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
                    max_frame_bytes,
                    domain,
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

#[instrument(level = "info", skip_all)]
async fn handle_repl_conn(
    max_frame_bytes: usize,
    tcpstream: TcpStream,
    client_address: SocketAddr,
    tls_parms: SslAcceptor,
    idms: Arc<IdmServer>,
) {
    debug!(?client_address, "replication client connected 🛫");

    let mut tlsstream = match Ssl::new(tls_parms.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
    {
        Ok(ta) => ta,
        Err(err) => {
            error!(?err, "LDAP TLS setup error, disconnecting client");
            return;
        }
    };
    if let Err(err) = SslStream::accept(Pin::new(&mut tlsstream)).await {
        error!(?err, "LDAP TLS accept error, disconnecting client");
        return;
    };
    let (r, w) = tokio::io::split(tlsstream);
    let mut r = FramedRead::new(r, codec::SupplierCodec::new(max_frame_bytes));
    let mut w = FramedWrite::new(w, codec::SupplierCodec::new(max_frame_bytes));

    while let Some(codec_msg) = r.next().await {
        match codec_msg {
            Ok(ConsumerRequest::Ping) => {
                debug!("consumer requested ping");
                if let Err(err) = w.send(SupplierResponse::Pong).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Ok(ConsumerRequest::Incremental(consumer_ruv_range)) => {
                let mut read_txn = idms.proxy_read().await;

                let changes = match read_txn
                    .qs_read
                    .supplier_provide_changes(consumer_ruv_range)
                {
                    Ok(changes) => changes,
                    Err(err) => {
                        error!(?err, "supplier provide changes failed.");
                        break;
                    }
                };

                if let Err(err) = w.send(SupplierResponse::Incremental(changes)).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Ok(ConsumerRequest::Refresh) => {
                let mut read_txn = idms.proxy_read().await;

                let changes = match read_txn.qs_read.supplier_provide_refresh() {
                    Ok(changes) => changes,
                    Err(err) => {
                        error!(?err, "supplier provide refresh failed.");
                        break;
                    }
                };

                if let Err(err) = w.send(SupplierResponse::Refresh(changes)).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Err(err) => {
                error!(?err, "supplier decode error, unable to continue.");
                break;
            }
        }
    }

    debug!(?client_address, "replication client disconnected 🛬");
}

async fn repl_acceptor(
    listener: TcpListener,
    idms: Arc<IdmServer>,
    repl_config: ReplicationConfiguration,
    mut rx: broadcast::Receiver<CoreAction>,
    mut ctrl_rx: mpsc::Receiver<ReplCtrl>,
) {
    info!("Starting Replication Acceptor ...");
    // Persistent parts
    // These all probably need changes later ...
    let task_poll_interval = Duration::from_secs(10);
    let retry_timeout = Duration::from_secs(60);
    let max_frame_bytes = 268435456;

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
        info!("Starting replication reload ...");
        // Tell existing tasks to shutdown.
        // Note: We ignore the result here since an err can occur *if* there are
        // no tasks currently listening on the channel.
        info!("Stopping {} Replication Tasks ...", task_handles.len());
        debug_assert!(task_handles.len() >= task_tx.receiver_count());
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
            // Does this actually need to be a read in case we need to write
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

        info!(
            replication_cert_not_before = ?server_cert.not_before(),
            replication_cert_not_after = ?server_cert.not_after(),
        );

        let mut client_certs = Vec::new();

        // For each node in the map, either spawn a task to pull from that node,
        // or setup the node as allowed to pull from us.
        for (origin, node) in replication_node_map.iter() {
            // Setup client certs
            match node {
                RepNodeConfig::MutualPull {
                    partner_cert: consumer_cert,
                    automatic_refresh: _,
                }
                | RepNodeConfig::AllowPull { consumer_cert } => {
                    client_certs.push(consumer_cert.clone())
                }
                RepNodeConfig::Pull {
                    supplier_cert: _,
                    automatic_refresh: _,
                } => {}
            };

            match node {
                RepNodeConfig::MutualPull {
                    partner_cert: supplier_cert,
                    automatic_refresh,
                }
                | RepNodeConfig::Pull {
                    supplier_cert,
                    automatic_refresh,
                } => {
                    let task_rx = task_tx.subscribe();

                    let handle = tokio::spawn(repl_task(
                        origin.clone(),
                        server_key.clone(),
                        server_cert.clone(),
                        supplier_cert.clone(),
                        max_frame_bytes,
                        task_poll_interval,
                        task_rx,
                        *automatic_refresh,
                        idms.clone(),
                    ));

                    task_handles.push_back(handle);
                    debug_assert!(task_handles.len() == task_tx.receiver_count());
                }
                RepNodeConfig::AllowPull { consumer_cert: _ } => {}
            };
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
            // This is great to diagnose when spans are entered or present and they capture
            // things incorrectly.
            // eprintln!("🔥 C ---> {:?}", tracing::Span::current());
            let eventid = Uuid::new_v4();

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
                            let _span = debug_span!("supplier_accept_loop", uuid = ?eventid).entered();
                            if let Err(_) = respond.send(server_cert.clone()) {
                                warn!("Server certificate was requested, but requsetor disconnected");
                            } else {
                                trace!("Sent server certificate via control channel");
                            }
                        }
                        ReplCtrl::RenewCertificate {
                            respond
                        } => {
                            let span = debug_span!("supplier_accept_loop", uuid = ?eventid);
                            async {
                                debug!("renewing replication certificate ...");
                                // Renew the cert.
                                let res = {
                                    let ct = duration_from_epoch_now();
                                    let mut idms_prox_write = idms.proxy_write(ct).await;
                                    idms_prox_write
                                        .qs_write
                                        .supplier_renew_key_cert()
                                        .and_then(|res| idms_prox_write.commit().map(|()| res))
                                };

                                let success = res.is_ok();

                                if let Err(err) = res {
                                    error!(?err, "failed to renew server certificate");
                                }

                                if let Err(_) = respond.send(success) {
                                    warn!("Server certificate renewal was requested, but requsetor disconnected");
                                } else {
                                    trace!("Sent server certificate renewal status via control channel");
                                }
                            }
                            .instrument(span)
                            .await;

                            // Start a reload.
                            continue 'event;
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
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((tcpstream, client_socket_addr)) => {
                            let clone_idms = idms.clone();
                            let clone_tls_acceptor = tls_acceptor.clone();
                            // We don't care about the join handle here - once a client connects
                            // it sticks to whatever ssl settings it had at launch.
                            let _ = tokio::spawn(
                                handle_repl_conn(max_frame_bytes, tcpstream, client_socket_addr, clone_tls_acceptor, clone_idms)
                            );
                        }
                        Err(e) => {
                            error!("replication acceptor error, continuing -> {:?}", e);
                        }
                    }
                }
            } // end select
              // Continue to poll/loop
        }
    }
    // Shutdown child tasks.
    info!("Stopping {} Replication Tasks ...", task_handles.len());
    debug_assert!(task_handles.len() >= task_tx.receiver_count());
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

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate log;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use std::fs::metadata;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use bytes::{BufMut, BytesMut};
use futures::SinkExt;
use futures::StreamExt;
use libc::umask;
use std::error::Error;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time;
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};

use kanidm_client::KanidmClientBuilder;

use kanidm_unix_common::cache::CacheLayer;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse, TaskRequest, TaskResponse};

//=== the codec

type AsyncTaskRequest = (TaskRequest, oneshot::Sender<()>);

struct ClientCodec;

impl Decoder for ClientCodec {
    type Item = ClientRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_cbor::from_slice::<ClientRequest>(&src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<ClientResponse> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ClientResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send response -> {:?} ...", msg);
        let data = serde_cbor::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "CBOR encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

struct TaskCodec;

impl Decoder for TaskCodec {
    type Item = TaskResponse;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_cbor::from_slice::<TaskResponse>(&src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<TaskRequest> for TaskCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TaskRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send request -> {:?} ...", msg);
        let data = serde_cbor::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "CBOR encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl TaskCodec {
    fn new() -> Self {
        TaskCodec
    }
}

fn rm_if_exist(p: &str) {
    let _ = std::fs::remove_file(p).map_err(|e| {
        warn!("attempting to remove {:?} -> {:?}", p, e);
    });
}

async fn handle_task_client(
    stream: UnixStream,
    task_channel_tx: &Sender<AsyncTaskRequest>,
    task_channel_rx: &mut Receiver<AsyncTaskRequest>,
) -> Result<(), Box<dyn Error>> {
    // setup the codec
    let mut reqs = Framed::new(stream, TaskCodec::new());

    loop {
        // TODO wait on the channel OR the task handler, so we know
        // when it closes.
        let v = match task_channel_rx.recv().await {
            Some(v) => v,
            None => return Ok(()),
        };

        debug!("Sending Task -> {:?}", v.0);

        // Write the req to the socket.
        if let Err(_e) = reqs.send(v.0.clone()).await {
            // re-queue the event if not timed out.
            // This is indicated by the one shot being dropped.
            if !v.1.is_closed() {
                let _ = task_channel_tx
                    .send_timeout(v, Duration::from_millis(100))
                    .await;
            }
            // now return the error.
            return Err(Box::new(IoError::new(ErrorKind::Other, "oh no!")));
        }

        match reqs.next().await {
            Some(Ok(TaskResponse::Success)) => {
                debug!("Task was acknowledged and completed.");
                // Send a result back via the one-shot
                // Ignore if it fails.
                let _ = v.1.send(());
            }
            other => {
                error!("Error -> {:?}", other);
                return Err(Box::new(IoError::new(ErrorKind::Other, "oh no!")));
            }
        }
    }
}

async fn handle_client(
    sock: UnixStream,
    cachelayer: Arc<CacheLayer>,
    task_channel_tx: &Sender<AsyncTaskRequest>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted connection");

    let mut reqs = Framed::new(sock, ClientCodec::new());

    while let Some(Ok(req)) = reqs.next().await {
        let resp = match req {
            ClientRequest::SshKey(account_id) => {
                debug!("sshkey req");
                cachelayer
                    .get_sshkeys(account_id.as_str())
                    .await
                    .map(ClientResponse::SshKeys)
                    .unwrap_or_else(|_| {
                        error!("unable to load keys, returning empty set.");
                        ClientResponse::SshKeys(vec![])
                    })
            }
            ClientRequest::NssAccounts => {
                debug!("nssaccounts req");
                cachelayer
                    .get_nssaccounts()
                    .await
                    .map(ClientResponse::NssAccounts)
                    .unwrap_or_else(|_| {
                        error!("unable to enum accounts");
                        ClientResponse::NssAccounts(Vec::new())
                    })
            }
            ClientRequest::NssAccountByUid(gid) => {
                debug!("nssaccountbyuid req");
                cachelayer
                    .get_nssaccount_gid(gid)
                    .await
                    .map(ClientResponse::NssAccount)
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssAccountByName(account_id) => {
                debug!("nssaccountbyname req");
                cachelayer
                    .get_nssaccount_name(account_id.as_str())
                    .await
                    .map(ClientResponse::NssAccount)
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssGroups => {
                debug!("nssgroups req");
                cachelayer
                    .get_nssgroups()
                    .await
                    .map(ClientResponse::NssGroups)
                    .unwrap_or_else(|_| {
                        error!("unable to enum groups");
                        ClientResponse::NssGroups(Vec::new())
                    })
            }
            ClientRequest::NssGroupByGid(gid) => {
                debug!("nssgroupbygid req");
                cachelayer
                    .get_nssgroup_gid(gid)
                    .await
                    .map(ClientResponse::NssGroup)
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
            }
            ClientRequest::NssGroupByName(grp_id) => {
                debug!("nssgroupbyname req");
                cachelayer
                    .get_nssgroup_name(grp_id.as_str())
                    .await
                    .map(ClientResponse::NssGroup)
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
            }
            ClientRequest::PamAuthenticate(account_id, cred) => {
                debug!("pam authenticate");
                cachelayer
                    .pam_account_authenticate(account_id.as_str(), cred.as_str())
                    .await
                    .map(ClientResponse::PamStatus)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::PamAccountAllowed(account_id) => {
                debug!("pam account allowed");
                cachelayer
                    .pam_account_allowed(account_id.as_str())
                    .await
                    .map(ClientResponse::PamStatus)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::PamAccountBeginSession(account_id) => {
                debug!("pam account begin session");
                match cachelayer
                    .pam_account_beginsession(account_id.as_str())
                    .await
                {
                    Ok(Some(info)) => {
                        let (tx, rx) = oneshot::channel();

                        match task_channel_tx
                            .send_timeout(
                                (TaskRequest::HomeDirectory(info), tx),
                                Duration::from_millis(100),
                            )
                            .await
                        {
                            Ok(()) => {
                                // Now wait for the other end OR
                                // timeout.
                                match time::timeout_at(
                                    time::Instant::now() + Duration::from_millis(1000),
                                    rx,
                                )
                                .await
                                {
                                    Ok(Ok(_)) => {
                                        debug!("Task completed, returning to pam ...");
                                        ClientResponse::Ok
                                    }
                                    _ => {
                                        // Timeout or other error.
                                        ClientResponse::Error
                                    }
                                }
                            }
                            Err(_) => {
                                // We could not submit the req. Move on!
                                ClientResponse::Error
                            }
                        }
                    }
                    _ => ClientResponse::Error,
                }
            }
            ClientRequest::InvalidateCache => {
                debug!("invalidate cache");
                cachelayer
                    .invalidate()
                    .await
                    .map(|_| ClientResponse::Ok)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::ClearCache => {
                debug!("clear cache");
                cachelayer
                    .clear_cache()
                    .await
                    .map(|_| ClientResponse::Ok)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::Status => {
                debug!("status check");
                if cachelayer.test_connection().await {
                    ClientResponse::Ok
                } else {
                    ClientResponse::Error
                }
            }
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        debug!("flushed response!");
    }

    // Disconnect them
    debug!("Disconnecting client ...");
    Ok(())
}

#[tokio::main]
async fn main() {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
        eprintln!("Refusing to run - this process must not operate as root.");
        std::process::exit(1);
    }

    // ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    env_logger::init();

    let cfg_path = Path::new("/etc/kanidm/config");
    let cfg_path_str = match cfg_path.to_str() {
        Some(cps) => cps,
        None => {
            error!("Unable to turn cfg_path to str");
            std::process::exit(1);
        }
    };
    if cfg_path.exists() {
        let cfg_meta = match metadata(&cfg_path) {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to read metadata for {} - {:?}", cfg_path_str, e);
                std::process::exit(1);
            }
        };
        if !cfg_meta.permissions().readonly() {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                cfg_path_str
                );
        }

        if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                cfg_path_str
            );
        }
    }

    let unixd_path = Path::new("/etc/kanidm/unixd");
    let unixd_path_str = match unixd_path.to_str() {
        Some(cps) => cps,
        None => {
            error!("Unable to turn unixd_path to str");
            std::process::exit(1);
        }
    };
    if unixd_path.exists() {
        let unixd_meta = match metadata(&unixd_path) {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to read metadata for {} - {:?}", unixd_path_str, e);
                std::process::exit(1);
            }
        };
        if !unixd_meta.permissions().readonly() {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                unixd_path_str);
        }

        if unixd_meta.uid() == cuid || unixd_meta.uid() == ceuid {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                unixd_path_str
            );
        }
    }

    // setup
    let cb = match KanidmClientBuilder::new().read_options_from_optional_config(cfg_path) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse {}", cfg_path_str);
            std::process::exit(1);
        }
    };

    let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config(unixd_path) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse {}", unixd_path_str);
            std::process::exit(1);
        }
    };

    rm_if_exist(cfg.sock_path.as_str());
    rm_if_exist(cfg.task_sock_path.as_str());

    let cb = cb.connect_timeout(cfg.conn_timeout);

    let rsclient = match cb.build_async() {
        Ok(rsc) => rsc,
        Err(_e) => {
            error!("Failed to build async client");
            std::process::exit(1);
        }
    };

    // Check the pb path will be okay.
    if cfg.db_path != "" {
        let db_path = PathBuf::from(cfg.db_path.as_str());
        // We only need to check the parent folder path permissions as the db itself may not
        // exist yet.
        if let Some(db_parent_path) = db_path.parent() {
            if !db_parent_path.exists() {
                error!(
                    "Refusing to run, DB folder {} does not exist",
                    db_parent_path
                        .to_str()
                        .unwrap_or_else(|| "<db_parent_path invalid>")
                );
                std::process::exit(1);
            }

            let db_par_path_buf = db_parent_path.to_path_buf();

            let i_meta = match metadata(&db_par_path_buf) {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Unable to read metadata for {} - {:?}",
                        db_par_path_buf
                            .to_str()
                            .unwrap_or_else(|| "<db_par_path_buf invalid>"),
                        e
                    );
                    std::process::exit(1);
                }
            };

            if !i_meta.is_dir() {
                error!(
                    "Refusing to run - DB folder {} may not be a directory",
                    db_par_path_buf
                        .to_str()
                        .unwrap_or_else(|| "<db_par_path_buf invalid>")
                );
                std::process::exit(1);
            }
            if i_meta.permissions().readonly() {
                warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str()
                .unwrap_or_else(|| "<db_par_path_buf invalid>")
                );
            }

            if i_meta.mode() & 0o007 != 0 {
                warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str()
                .unwrap_or_else(|| "<db_par_path_buf invalid>")
                );
            }
        }
    }

    let cl_inner = match CacheLayer::new(
        cfg.db_path.as_str(), // The sqlite db path
        cfg.cache_timeout,
        rsclient,
        cfg.pam_allowed_login_groups.clone(),
        cfg.default_shell.clone(),
        cfg.home_prefix.clone(),
        cfg.home_attr,
        cfg.home_alias,
        cfg.uid_attr_map,
        cfg.gid_attr_map,
    )
    .await
    {
        Ok(c) => c,
        Err(_e) => {
            error!("Failed to build cache layer.");
            std::process::exit(1);
        }
    };

    let cachelayer = Arc::new(cl_inner);

    // Set the umask while we open the path for most clients.
    let before = unsafe { umask(0) };
    let listener = match UnixListener::bind(cfg.sock_path.as_str()) {
        Ok(l) => l,
        Err(_e) => {
            error!("Failed to bind unix socket.");
            std::process::exit(1);
        }
    };
    // Setup the root-only socket. Take away all others.
    let _ = unsafe { umask(0o0077) };
    let task_listener = match UnixListener::bind(cfg.task_sock_path.as_str()) {
        Ok(l) => l,
        Err(_e) => {
            error!("Failed to bind unix socket.");
            std::process::exit(1);
        }
    };

    // Undo it.
    let _ = unsafe { umask(before) };

    let (task_channel_tx, mut task_channel_rx) = channel(16);
    let task_channel_tx = Arc::new(task_channel_tx);

    let task_channel_tx_cln = task_channel_tx.clone();

    tokio::spawn(async move {
        loop {
            match task_listener.accept().await {
                Ok((socket, _addr)) => {
                    // Did it come from root?
                    if let Ok(ucred) = socket.peer_cred() {
                        if ucred.uid() == 0 {
                            // all good!
                        } else {
                            // move along.
                            debug!("Task handler not running as root, ignoring ...");
                            continue;
                        }
                    } else {
                        // move along.
                        debug!("Task handler not running as root, ignoring ...");
                        continue;
                    };
                    debug!("A task handler has connected.");
                    // It did? Great, now we can wait and spin on that one
                    // client.
                    if let Err(e) =
                        handle_task_client(socket, &task_channel_tx, &mut task_channel_rx).await
                    {
                        error!("Task client error occured; error = {:?}", e);
                    }
                    // If they DC we go back to accept.
                }
                Err(err) => {
                    error!("Task Accept error -> {:?}", err);
                }
            }
            // done
        }
    });

    // TODO: Setup a task that handles pre-fetching here.

    let server = async move {
        loop {
            let tc_tx = task_channel_tx_cln.clone();
            match listener.accept().await {
                Ok((socket, _addr)) => {
                    let cachelayer_ref = cachelayer.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(socket, cachelayer_ref.clone(), &tc_tx).await
                        {
                            error!("an error occured; error = {:?}", e);
                        }
                    });
                }
                Err(err) => {
                    error!("Accept error -> {:?}", err);
                }
            }
        }
    };

    info!("Server started ...");

    server.await;
}

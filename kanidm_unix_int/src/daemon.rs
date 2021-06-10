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

use std::{
    error::Error,
    fs::{self, metadata},
    io::{self, Error as IoError, ErrorKind},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use libc::umask;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::mpsc::{channel, Receiver, Sender},
    sync::oneshot,
    time,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

use kanidm_client::KanidmClientBuilder;

use kanidm_unix_common::{
    cache::CacheLayer,
    unix_config::KanidmUnixdConfig,
    unix_proto::{ClientRequest, ClientResponse, TaskRequest, TaskResponse},
};

//=== the codec

type AsyncTaskRequest = (TaskRequest, oneshot::Sender<()>);

struct ClientCodec;

impl Decoder for ClientCodec {
    type Item = ClientRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Why does this function return a result if we never get the `Err` variant?
        match serde_cbor::from_slice(&src) {
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
            IoError::new(ErrorKind::Other, "CBOR encode error")
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
        match serde_cbor::from_slice(&src) {
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
    type Error = IoError;

    fn encode(&mut self, msg: TaskRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send request -> {:?} ...", msg);
        let data = serde_cbor::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            IoError::new(ErrorKind::Other, "CBOR encode error")
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
    let _ = fs::remove_file(p).map_err(|e| {
        warn!("attempting to remove {:?} -> {:?}", p, e);
        // shouldn't it be "attempted to remove ..."
        // not "attemping"
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
                // This error msg lol
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

                if let Ok(Some(info)) = cachelayer
                    .pam_account_beginsession(account_id.as_str())
                    .await
                {
                    let (tx, rx) = oneshot::channel();

                    if let Ok(()) = task_channel_tx
                        .send_timeout(
                            (TaskRequest::HomeDirectory(info), tx),
                            Duration::from_millis(100),
                        )
                        .await
                    {
                        // Now wait for the other end OR
                        // timeout.
                        if let Ok(Ok(_)) =
                            time::timeout_at(time::Instant::now() + Duration::from_millis(1000), rx)
                                .await
                        {
                            debug!("Task completed, returning to pam ...");
                            ClientResponse::Ok
                        } else {
                            // Timeout or other error.
                            ClientResponse::Error
                        }
                    } else {
                        ClientResponse::Error
                    }
                } else {
                    ClientResponse::Error
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

    debug!("Profile -> {}", env!("KANIDM_PROFILE_NAME"));
    debug!("CPU Flags -> {}", env!("KANIDM_CPU_FLAGS"));

    let cfg_path = Path::new("/etc/kanidm/config");
    let cfg_path_str = cfg_path.to_str().unwrap_or_else(|| {
        error!("Unable to turn cfg_path to str");
        std::process::exit(1);
    });
    if cfg_path.exists() {
        let cfg_meta = metadata(&cfg_path).unwrap_or_else(|e| {
            error!("Unable to read metadata for {} - {:?}", cfg_path_str, e);
            // Is is safe to call this? Docs say that no destructors will be run...
            std::process::exit(1);
        });
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
    let unixd_path_str = unixd_path.to_str().unwrap_or_else(|| {
        error!("Unable to turn unixd_path to str");
        std::process::exit(1);
    });
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
    let cb = KanidmClientBuilder::new()
        .read_options_from_optional_config(cfg_path)
        .unwrap_or_else(|_| {
            error!("Failed to parse {}", cfg_path_str);
            std::process::exit(1);
        });

    let cfg = KanidmUnixdConfig::new()
        .read_options_from_optional_config(unixd_path)
        .unwrap_or_else(|_| {
            error!("Failed to parse {}", unixd_path_str);
            std::process::exit(1);
        });

    rm_if_exist(cfg.sock_path.as_str());
    rm_if_exist(cfg.task_sock_path.as_str());

    let cb = cb.connect_timeout(cfg.conn_timeout);

    let rsclient = cb.build_async().unwrap_or_else(|_e| {
        error!("Failed to build async client");
        std::process::exit(1);
    });

    // Check the pb path will be okay.
    if !cfg.db_path.is_empty() {
        let db_path = PathBuf::from(cfg.db_path.as_str());
        // We only need to check the parent folder path permissions as the db itself may not
        // exist yet.
        if let Some(db_parent_path) = db_path.parent() {
            if !db_parent_path.exists() {
                error!(
                    "Refusing to run, DB folder {} does not exist",
                    db_parent_path
                        .to_str()
                        .unwrap_or("<db_parent_path invalid>")
                );
                std::process::exit(1);
            }

            let db_par_path_buf = db_parent_path.to_path_buf();

            let i_meta = metadata(&db_par_path_buf).unwrap_or_else(|err| {
                error!(
                    "Unable to read metadata for {} - {:?}",
                    db_par_path_buf
                        .to_str()
                        .unwrap_or("<db_par_path_buf invalid>"),
                    err
                );
                std::process::exit(1);
            });

            if !i_meta.is_dir() {
                error!(
                    "Refusing to run - DB folder {} may not be a directory",
                    db_par_path_buf
                        .to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                );
                std::process::exit(1);
            }
            if i_meta.permissions().readonly() {
                warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!",
                    db_par_path_buf
                        .to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                );
            }

            if i_meta.mode() & 0o007 != 0 {
                warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...",
                db_par_path_buf
                    .to_str()
                    .unwrap_or("<db_par_path_buf invalid>")
                );
            }
        }
    }

    let cl_inner = CacheLayer::new(
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
    .unwrap_or_else(|_e| {
        error!("Failed to build cache layer.");
        std::process::exit(1);
    });

    let cachelayer = Arc::new(cl_inner);

    // Set the umask while we open the path for most clients.
    let before = unsafe { umask(0) };
    let listener = UnixListener::bind(cfg.sock_path.as_str()).unwrap_or_else(|_e| {
        error!("Failed to bind unix socket.");
        std::process::exit(1);
    });
    // Setup the root-only socket. Take away all others.
    let _ = unsafe { umask(0o0077) };

    let task_listener = UnixListener::bind(cfg.task_sock_path.as_str()).unwrap_or_else(|_e| {
        error!("Failed to bind unix socket.");
        std::process::exit(1);
    });

    // what is going on here??
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
                    match socket.peer_cred() {
                        Ok(ucred) if ucred.uid() == 0 => (), // all good!
                        _ => {
                            debug!("Task handler not running as root, ignoring ...");
                            continue;
                        }
                    }
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

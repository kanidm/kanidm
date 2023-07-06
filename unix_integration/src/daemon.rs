#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::error::Error;
use std::fs::metadata;
use std::io;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use clap::{Arg, ArgAction, Command};
use futures::{SinkExt, StreamExt};
use kanidm_client::KanidmClientBuilder;
use kanidm_proto::constants::DEFAULT_CLIENT_CONFIG_PATH;
use kanidm_unix_common::cache::CacheLayer;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_passwd::{parse_etc_group, parse_etc_passwd};
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse, TaskRequest, TaskResponse};

use libc::umask;
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use tokio::fs::File;
use tokio::io::AsyncReadExt; // for read_to_end()
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time;
use tokio_util::codec::{Decoder, Encoder, Framed};
use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use notify_debouncer_full::{new_debouncer, notify::RecursiveMode, notify::Watcher};

//=== the codec

type AsyncTaskRequest = (TaskRequest, oneshot::Sender<()>);

struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = ClientRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<ClientRequest>(src) {
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
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
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
    type Error = io::Error;
    type Item = TaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<TaskResponse>(src) {
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
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
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

/// Pass this a file path and it'll look for the file and remove it if it's there.
fn rm_if_exist(p: &str) {
    if Path::new(p).exists() {
        debug!("Removing requested file {:?}", p);
        let _ = std::fs::remove_file(p).map_err(|e| {
            error!(
                "Failure while attempting to attempting to remove {:?} -> {:?}",
                p, e
            );
        });
    } else {
        debug!("Path {:?} doesn't exist, not attempting to remove.", p);
    }
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

    trace!("Waiting for requests ...");
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
                                // Now wait for the other end OR timeout.
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

async fn process_etc_passwd_group(cachelayer: &CacheLayer) -> Result<(), Box<dyn Error>> {
    let mut file = File::open("/etc/passwd").await?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await?;

    let users = parse_etc_passwd(contents.as_slice()).map_err(|_| "Invalid passwd content")?;

    let mut file = File::open("/etc/group").await?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await?;

    let groups = parse_etc_group(contents.as_slice()).map_err(|_| "Invalid group content")?;

    let id_iter = users
        .iter()
        .map(|user| (user.name.clone(), user.uid))
        .chain(groups.iter().map(|group| (group.name.clone(), group.gid)));

    cachelayer.reload_nxset(id_iter).await;

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    let clap_args = Command::new("kanidm_unixd")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Kanidm Unix daemon")
        .arg(
            Arg::new("skip-root-check")
                .help("Allow running as root. Don't use this in production as it is risky!")
                .short('r')
                .long("skip-root-check")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("configtest")
                .help("Display the configuration and exit")
                .short('t')
                .long("configtest")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("unixd-config")
                .takes_value(true)
                .help("Set the unixd config file path")
                .short('u')
                .long("unixd-config")
                .default_value(DEFAULT_CONFIG_PATH)
                .env("KANIDM_UNIX_CONFIG")
                .action(ArgAction::StoreValue),
        )
        .arg(
            Arg::new("client-config")
                .takes_value(true)
                .help("Set the client config file path")
                .short('c')
                .long("client-config")
                .default_value(DEFAULT_CLIENT_CONFIG_PATH)
                .env("KANIDM_CLIENT_CONFIG")
                .action(ArgAction::StoreValue),
        )
        .get_matches();

    if clap_args.get_flag("debug") {
        std::env::set_var("RUST_LOG", "debug");
    }

    #[allow(clippy::expect_used)]
    tracing_forest::worker_task()
        .set_global(true)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| subscriber
            .with(EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .expect("Failed to init envfilter")
            )
        )
        .on(async {
            if clap_args.get_flag("skip-root-check") {
                warn!("Skipping root user check, if you're running this for testing, ensure you clean up temporary files.")
                // TODO: this wording is not great m'kay.
            } else if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
                error!("Refusing to run - this process must not operate as root.");
                return ExitCode::FAILURE
            };

            debug!("Profile -> {}", env!("KANIDM_PROFILE_NAME"));
            debug!("CPU Flags -> {}", env!("KANIDM_CPU_FLAGS"));

            let Some(cfg_path_str) = clap_args.get_one::<String>("client-config") else {
                error!("Failed to pull the client config path");
                return ExitCode::FAILURE
            };
            let cfg_path: PathBuf =  PathBuf::from(cfg_path_str);

            if !cfg_path.exists() {
                // there's no point trying to start up if we can't read a usable config!
                error!(
                    "Client config missing from {} - cannot start up. Quitting.",
                    cfg_path_str
                );
                return ExitCode::FAILURE
            } else {
                let cfg_meta = match metadata(&cfg_path) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Unable to read metadata for {} - {:?}", cfg_path_str, e);
                        return ExitCode::FAILURE
                    }
                };
                if !kanidm_lib_file_permissions::readonly(&cfg_meta) {
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

            let Some(unixd_path_str) = clap_args.get_one::<String>("unixd-config") else {
                error!("Failed to pull the unixd config path");
                return ExitCode::FAILURE
            };
            let unixd_path = PathBuf::from(unixd_path_str);

            if !unixd_path.exists() {
                // there's no point trying to start up if we can't read a usable config!
                error!(
                    "unixd config missing from {} - cannot start up. Quitting.",
                    unixd_path_str
                );
                return ExitCode::FAILURE
            } else {
                let unixd_meta = match metadata(&unixd_path) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Unable to read metadata for {} - {:?}", unixd_path_str, e);
                        return ExitCode::FAILURE
                    }
                };
                if !kanidm_lib_file_permissions::readonly(&unixd_meta) {
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
            let cb = match KanidmClientBuilder::new().read_options_from_optional_config(&cfg_path) {
                Ok(v) => v,
                Err(_) => {
                    error!("Failed to parse {}", cfg_path_str);
                    return ExitCode::FAILURE
                }
            };

            let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config(&unixd_path) {
                Ok(v) => v,
                Err(_) => {
                    error!("Failed to parse {}", unixd_path_str);
                    return ExitCode::FAILURE
                }
            };

            if clap_args.get_flag("configtest") {
                eprintln!("###################################");
                eprintln!("Dumping configs:\n###################################");
                eprintln!("kanidm_unixd config (from {:#?})", &unixd_path);
                eprintln!("{}", cfg);
                eprintln!("###################################");
                eprintln!("Client config (from {:#?})", &cfg_path);
                eprintln!("{}", cb);
                return ExitCode::SUCCESS;
            }

            debug!("🧹 Cleaning up sockets from previous invocations");
            rm_if_exist(cfg.sock_path.as_str());
            rm_if_exist(cfg.task_sock_path.as_str());


            // Check the db path will be okay.
            if !cfg.db_path.is_empty() {
                let db_path = PathBuf::from(cfg.db_path.as_str());
                // We only need to check the parent folder path permissions as the db itself may not exist yet.
                if let Some(db_parent_path) = db_path.parent() {
                    if !db_parent_path.exists() {
                        error!(
                            "Refusing to run, DB folder {} does not exist",
                            db_parent_path
                                .to_str()
                                .unwrap_or("<db_parent_path invalid>")
                        );
                        return ExitCode::FAILURE
                    }

                    let db_par_path_buf = db_parent_path.to_path_buf();

                    let i_meta = match metadata(&db_par_path_buf) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for {} - {:?}",
                                db_par_path_buf
                                    .to_str()
                                    .unwrap_or("<db_par_path_buf invalid>"),
                                e
                            );
                            return ExitCode::FAILURE
                        }
                    };

                    if !i_meta.is_dir() {
                        error!(
                            "Refusing to run - DB folder {} may not be a directory",
                            db_par_path_buf
                                .to_str()
                                .unwrap_or("<db_par_path_buf invalid>")
                        );
                        return ExitCode::FAILURE
                    }
                    if !kanidm_lib_file_permissions::readonly(&i_meta) {
                        warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                        );
                    }

                    if i_meta.mode() & 0o007 != 0 {
                        warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                        );
                    }
                }

                // check to see if the db's already there
                if db_path.exists() {
                    if !db_path.is_file() {
                        error!(
                            "Refusing to run - DB path {} already exists and is not a file.",
                            db_path.to_str().unwrap_or("<db_path invalid>")
                        );
                        return ExitCode::FAILURE
                    };

                    match metadata(&db_path) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for {} - {:?}",
                                db_path.to_str().unwrap_or("<db_path invalid>"),
                                e
                            );
                            return ExitCode::FAILURE
                        }
                    };
                    // TODO: permissions dance to enumerate the user's ability to write to the file? ref #456 - r2d2 will happily keep trying to do things without bailing.
                };
            }

            let cb = cb.connect_timeout(cfg.conn_timeout);

            let rsclient = match cb.build() {
                Ok(rsc) => rsc,
                Err(_e) => {
                    error!("Failed to build async client");
                    return ExitCode::FAILURE
                }
            };

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
                cfg.allow_local_account_override.clone(),
                &cfg.tpm_policy,
            )
            .await
            {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to build cache layer.");
                    return ExitCode::FAILURE
                }
            };

            let cachelayer = Arc::new(cl_inner);

            // Setup the root-only socket. Take away all other access bits.
            let before = unsafe { umask(0o0077) };
            let task_listener = match UnixListener::bind(cfg.task_sock_path.as_str()) {
                Ok(l) => l,
                Err(_e) => {
                    error!("Failed to bind UNIX socket {}", cfg.sock_path.as_str());
                    return ExitCode::FAILURE
                }
            };
            // Undo umask changes.
            let _ = unsafe { umask(before) };

            // Pre-process /etc/passwd and /etc/group for nxset
            if process_etc_passwd_group(&cachelayer).await.is_err() {
                error!("Failed to process system id providers");
                return ExitCode::FAILURE
            }

            // Setup the tasks socket first.
            let (task_channel_tx, mut task_channel_rx) = channel(16);
            let task_channel_tx = Arc::new(task_channel_tx);

            let task_channel_tx_cln = task_channel_tx.clone();

            // Start to build the worker tasks
            let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);
            let mut c_broadcast_rx = broadcast_tx.subscribe();
            let mut d_broadcast_rx = broadcast_tx.subscribe();

            let task_b = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = c_broadcast_rx.recv() => {
                            break;
                        }
                        accept_res = task_listener.accept() => {
                            match accept_res {
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

                                    tokio::select! {
                                        _ = d_broadcast_rx.recv() => {
                                            break;
                                        }
                                        // We have to check for signals here else this tasks waits forever.
                                        Err(e) = handle_task_client(socket, &task_channel_tx, &mut task_channel_rx) => {
                                            error!("Task client error occurred; error = {:?}", e);
                                        }
                                    }
                                    // If they DC we go back to accept.
                                }
                                Err(err) => {
                                    error!("Task Accept error -> {:?}", err);
                                }
                            }
                        }
                    }
                    // done
                }
                info!("Stopped task connector");
            });

            // TODO: Setup a task that handles pre-fetching here.

            let (inotify_tx, mut inotify_rx) = channel(4);

            let watcher =
            match new_debouncer(Duration::from_secs(2), None, move |_event| {
                let _ = inotify_tx.try_send(true);
            })
                .and_then(|mut debouncer| {
                    debouncer.watcher().watch(Path::new("/etc/passwd"), RecursiveMode::NonRecursive)
                        .map(|()| debouncer)
                })
                .and_then(|mut debouncer| debouncer.watcher().watch(Path::new("/etc/group"), RecursiveMode::NonRecursive)
                        .map(|()| debouncer)
                )

            {
                Ok(watcher) => {
                    watcher
                }
                Err(e) => {
                    error!("Failed to setup inotify {:?}",  e);
                    return ExitCode::FAILURE
                }
            };

            let mut c_broadcast_rx = broadcast_tx.subscribe();

            let inotify_cachelayer = cachelayer.clone();
            let task_c = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = c_broadcast_rx.recv() => {
                            break;
                        }
                        _ = inotify_rx.recv() => {
                            if process_etc_passwd_group(&inotify_cachelayer).await.is_err() {
                                error!("Failed to process system id providers");
                            }
                        }
                    }
                }
                info!("Stopped inotify watcher");
            });

            // Set the umask while we open the path for most clients.
            let before = unsafe { umask(0) };
            let listener = match UnixListener::bind(cfg.sock_path.as_str()) {
                Ok(l) => l,
                Err(_e) => {
                    error!("Failed to bind UNIX socket at {}", cfg.sock_path.as_str());
                    return ExitCode::FAILURE
                }
            };
            // Undo umask changes.
            let _ = unsafe { umask(before) };

            let task_a = tokio::spawn(async move {
                loop {
                    let tc_tx = task_channel_tx_cln.clone();

                    tokio::select! {
                        _ = broadcast_rx.recv() => {
                            break;
                        }
                        accept_res = listener.accept() => {
                            match accept_res {
                                Ok((socket, _addr)) => {
                                    let cachelayer_ref = cachelayer.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_client(socket, cachelayer_ref.clone(), &tc_tx).await
                                        {
                                            error!("handle_client error occurred; error = {:?}", e);
                                        }
                                    });
                                }
                                Err(err) => {
                                    error!("Error while handling connection -> {:?}", err);
                                }
                            }
                        }
                    }

                }
                info!("Stopped resolver");
            });

            info!("Server started ...");

            loop {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::alarm();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::hangup();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                }
            }
            info!("Signal received, sending down signal to tasks");
            // Send a broadcast that we are done.
            if let Err(e) = broadcast_tx.send(true) {
                error!("Unable to shutdown workers {:?}", e);
            }

            drop(watcher);

            let _ = task_a.await;
            let _ = task_b.await;
            let _ = task_c.await;

            ExitCode::SUCCESS
    })
    .await
    // TODO: can we catch signals to clean up sockets etc, especially handy when running as root
}

#![deny(warnings)]
#[macro_use]
extern crate log;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use std::fs::metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use bytes::{BufMut, BytesMut};
use futures::SinkExt;
use futures::StreamExt;
use libc::umask;
use std::error::Error;
use std::io;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};

use kanidm_client::KanidmClientBuilder;

use kanidm_unix_common::cache::CacheLayer;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

//=== the codec

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

fn rm_if_exist(p: &str) {
    let _ = std::fs::remove_file(p).map_err(|e| {
        warn!("attempting to remove {:?} -> {:?}", p, e);
    });
}

async fn handle_client(
    sock: UnixStream,
    cachelayer: Arc<CacheLayer>,
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
            ClientRequest::InvalidateCache => {
                debug!("invalidate cache");
                cachelayer
                    .invalidate()
                    .map(|_| ClientResponse::Ok)
                    .unwrap_or(ClientResponse::Error)
            }
            ClientRequest::ClearCache => {
                debug!("clear cache");
                cachelayer
                    .clear_cache()
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
    if cfg_path.exists() {
        let cfg_meta = match metadata(&cfg_path) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Unable to read metadata for {} - {:?}",
                    cfg_path.to_str().unwrap(),
                    e
                );
                std::process::exit(1);
            }
        };
        if !cfg_meta.permissions().readonly() {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                cfg_path.to_str().unwrap());
        }

        if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                cfg_path.to_str().unwrap()
            );
        }
    }

    let unixd_path = Path::new("/etc/kanidm/config");
    if unixd_path.exists() {
        let unixd_meta = match metadata(&unixd_path) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Unable to read metadata for {} - {:?}",
                    unixd_path.to_str().unwrap(),
                    e
                );
                std::process::exit(1);
            }
        };
        if !unixd_meta.permissions().readonly() {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                unixd_path.to_str().unwrap());
        }

        if unixd_meta.uid() == cuid || unixd_meta.uid() == ceuid {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                unixd_path.to_str().unwrap()
            );
        }
    }

    // setup
    let cb = match KanidmClientBuilder::new().read_options_from_optional_config(cfg_path) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse {}", cfg_path.to_str().unwrap());
            std::process::exit(1);
        }
    };

    let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config(unixd_path) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse {}", unixd_path.to_str().unwrap());
            std::process::exit(1);
        }
    };

    rm_if_exist(cfg.sock_path.as_str());

    let cb = cb.connect_timeout(cfg.conn_timeout);

    let rsclient = cb.build_async().expect("Failed to build async client");

    // Check the pb path will be okay.
    if cfg.db_path != "" {
        let db_path = PathBuf::from(cfg.db_path.as_str());
        // We only need to check the parent folder path permissions as the db itself may not
        // exist yet.
        if let Some(db_parent_path) = db_path.parent() {
            if !db_parent_path.exists() {
                error!(
                    "Refusing to run, DB folder {} does not exist",
                    db_parent_path.to_str().unwrap()
                );
                std::process::exit(1);
            }

            let db_par_path_buf = db_parent_path.to_path_buf();

            let i_meta = match metadata(&db_par_path_buf) {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Unable to read metadata for {} - {:?}",
                        db_par_path_buf.to_str().unwrap(),
                        e
                    );
                    std::process::exit(1);
                }
            };

            if !i_meta.is_dir() {
                error!(
                    "Refusing to run - DB folder {} may not be a directory",
                    db_par_path_buf.to_str().unwrap()
                );
                std::process::exit(1);
            }
            if i_meta.permissions().readonly() {
                warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str().unwrap());
            }

            if i_meta.mode() & 0o007 != 0 {
                warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str().unwrap());
            }
        }
    }

    let cachelayer = Arc::new(
        CacheLayer::new(
            cfg.db_path.as_str(), // The sqlite db path
            cfg.cache_timeout,
            rsclient,
            cfg.pam_allowed_login_groups.clone(),
            cfg.default_shell.clone(),
            cfg.home_prefix.clone(),
            cfg.home_attr,
            cfg.uid_attr_map,
            cfg.gid_attr_map,
        )
        .expect("Failed to build cache layer."),
    );

    // Set the umask while we open the path
    let before = unsafe { umask(0) };
    let mut listener = UnixListener::bind(cfg.sock_path.as_str()).unwrap();
    // Undo it.
    let _ = unsafe { umask(before) };

    let server = async move {
        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    let cachelayer_ref = cachelayer.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(socket, cachelayer_ref.clone()).await {
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

// This is the actix version, but on MacOS there is an issue where it can't flush the socket properly :(

//=== A connected client session
/*

struct ClientSession {
    framed: actix::io::FramedWrite<WriteHalf<UnixStream>, ClientCodec>,
}

impl Actor for ClientSession {
    type Context = Context<Self>;
}

impl actix::io::WriteHandler<io::Error> for ClientSession {}

impl StreamHandler<Result<ClientRequest, io::Error>> for ClientSession {
    fn handle(&mut self, msg: Result<ClientRequest, io::Error>, ctx: &mut Self::Context) {
        debug!("Processing -> {:?}", msg);
        match msg {
            Ok(ClientRequest::SshKey(account_id)) => {
                self.framed.write(ClientResponse::SshKeys(vec![]));
            }
            Err(e) => {
                println!("Encountered an IO error, disconnecting session -> {:?}", e);
                ctx.stop();
            }
        }
    }
}

impl ClientSession {
    fn new(framed: actix::io::FramedWrite<WriteHalf<UnixStream>, ClientCodec>) -> Self {
        ClientSession { framed: framed }
    }
}

//=== this is the accept server

struct AcceptServer;

impl Actor for AcceptServer {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "()")]
struct UdsConnect(pub UnixStream, pub SocketAddr);

impl Handler<UdsConnect> for AcceptServer {
    type Result = ();

    fn handle(&mut self, msg: UdsConnect, _: &mut Context<Self>) {
        debug!("Accepting new client ...");

        // TODO: Clone the DB actor handle here.
        ClientSession::create(move |ctx| {
            let (r, w) = tokio::io::split(msg.0);
            ClientSession::add_stream(FramedRead::new(r, ClientCodec), ctx);
            ClientSession::new(actix::io::FramedWrite::new(w, ClientCodec, ctx))
        });
    }
}

#[actix_rt::main]
async fn main() {
    // Setup logging
    ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    env_logger::init();

    rm_if_exist(DEFAULT_SOCK_PATH);
    let listener = Box::new(UnixListener::bind(DEFAULT_SOCK_PATH).expect("Failed to bind"));
    AcceptServer::create(|ctx| {
        ctx.add_message_stream(Box::leak(listener).incoming().map(|st| {
            let st = st.unwrap();
            let addr = st.peer_addr().unwrap();
            UdsConnect(st, addr)
        }));
        AcceptServer {}
    });
    println!("Running ...");
    tokio::signal::ctrl_c().await.unwrap();
    println!("Ctrl-C received, shutting down");
    System::current().stop();
}
*/

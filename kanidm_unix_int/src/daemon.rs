#[macro_use]
extern crate log;

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
use kanidm_unix_common::constants::{
    DEFAULT_CACHE_TIMEOUT, DEFAULT_CONN_TIMEOUT, DEFAULT_DB_PATH, DEFAULT_SOCK_PATH,
};
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

impl Encoder for ClientCodec {
    type Item = ClientResponse;
    type Error = io::Error;

    fn encode(&mut self, msg: ClientResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_cbor::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "CBOR encode error")
        })?;
        debug!("Attempting to send response -> {:?} ...", data);
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
        error!("attempting to remove {:?} -> {:?}", p, e);
        ()
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
                    .map(|r| ClientResponse::SshKeys(r))
                    .unwrap_or_else(|_| {
                        error!("unable to load keys, returning empty set.");
                        ClientResponse::SshKeys(vec![])
                    })
            }
            ClientRequest::NssAccounts => {
                debug!("nssaccounts req");
                cachelayer
                    .get_nssaccounts()
                    .map(|r| ClientResponse::NssAccounts(r))
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
                    .map(|acc| ClientResponse::NssAccount(acc))
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
                    .map(|acc| ClientResponse::NssAccount(acc))
                    .unwrap_or_else(|_| {
                        error!("unable to load account, returning empty.");
                        ClientResponse::NssAccount(None)
                    })
            }
            ClientRequest::NssGroups => {
                debug!("nssgroups req");
                cachelayer
                    .get_nssgroups()
                    .map(|r| ClientResponse::NssGroups(r))
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
                    .map(|grp| ClientResponse::NssGroup(grp))
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
                    .map(|grp| ClientResponse::NssGroup(grp))
                    .unwrap_or_else(|_| {
                        error!("unable to load group, returning empty.");
                        ClientResponse::NssGroup(None)
                    })
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
    ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    env_logger::init();
    rm_if_exist(DEFAULT_SOCK_PATH);

    // setup
    let cb = KanidmClientBuilder::new()
        .read_options_from_optional_config("/etc/kanidm/config")
        .expect("Failed to parse /etc/kanidm/config");

    let cb = cb.connect_timeout(DEFAULT_CONN_TIMEOUT);

    let rsclient = cb.build_async().expect("Failed to build async client");

    let cachelayer = Arc::new(
        CacheLayer::new(
            DEFAULT_DB_PATH, // The sqlite db path
            DEFAULT_CACHE_TIMEOUT,
            rsclient,
        )
        .expect("Failed to build cache layer."),
    );

    // Set the umask while we open the path
    let before = unsafe { umask(0) };
    let mut listener = UnixListener::bind(DEFAULT_SOCK_PATH).unwrap();
    // Undo it.
    let _ = unsafe { umask(before) };

    let server = async move {
        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    let cachelayer_ref = cachelayer.clone();
                    tokio::spawn(
                        async move {
                            if let Err(e) = handle_client(socket, cachelayer_ref.clone()).await {
                                error!("an error occured; error = {:?}", e);
                            }
                        },
                    );
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

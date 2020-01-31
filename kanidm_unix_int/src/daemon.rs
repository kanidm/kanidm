#[macro_use]
extern crate log;

use actix::prelude::*;
use tokio::io::WriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::FramedRead;
use tokio_util::codec::{Decoder, Encoder};
use futures::StreamExt;
use std::os::unix::net::SocketAddr;
use std::io;
use bytes::{Buf, BufMut, BytesMut};

use kanidm_unix_common::constants::DEFAULT_SOCK_PATH;
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
            _ => {
                Ok(None)
            }
        }
    }
}

impl Encoder for ClientCodec {
    type Item = ClientResponse;
    type Error = io::Error;

    fn encode(
        &mut self,
        msg: ClientResponse,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let data = serde_cbor::to_vec(&msg)
            .map_err(|e| {
                error!("socket encoding error -> {:?}", e);
                io::Error::new(io::ErrorKind::Other, "CBOR encode error")
            })?;
        debug!("Attempting to send response -> {:?} ...", data);
        dst.put(data.as_slice());
        Ok(())
    }
}


//=== A connected client session

struct ClientSession {
    framed: actix::io::FramedWrite<WriteHalf<UnixStream>, ClientCodec>
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
                error!("Encountered an IO error -> {:?}", e);
            }
        }
    }
}

impl ClientSession {
    fn new(framed: actix::io::FramedWrite<WriteHalf<UnixStream>, ClientCodec>) -> Self {
        ClientSession {
            framed: framed
        }
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
            let (r,w) = tokio::io::split(msg.0);
            ClientSession::add_stream(FramedRead::new(r, ClientCodec), ctx);
            ClientSession::new(actix::io::FramedWrite::new(w, ClientCodec, ctx))
        });
    }
}

fn rm_if_exist(p: &str) {
    std::fs::remove_file(p);
}

#[actix_rt::main]
async fn main() {
    // Setup logging
    ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    env_logger::init();

    rm_if_exist(DEFAULT_SOCK_PATH);
    let listener = Box::new(UnixListener::bind(DEFAULT_SOCK_PATH).expect("Failed to bind"));
    AcceptServer::create(|ctx| {
        ctx.add_message_stream(
            Box::leak(listener)
                .incoming()
                .map(|st| {
                    let st = st.unwrap();
                    let addr = st.peer_addr().unwrap();
                    UdsConnect(st, addr)
                })
        );
        AcceptServer {}
    });
    println!("Running ...");
    tokio::signal::ctrl_c().await.unwrap();
    println!("Ctrl-C received, shutting down");
    System::current().stop();
}

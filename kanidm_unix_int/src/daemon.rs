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
        unimplemented!();
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
        unimplemented!();
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
        unimplemented!();
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

        // TODO: Clone the DB actor handle here.
        ClientSession::create(move |ctx| {
            let (r,w) = tokio::io::split(msg.0);
            ClientSession::add_stream(FramedRead::new(r, ClientCodec), ctx);
            ClientSession::new(actix::io::FramedWrite::new(w, ClientCodec, ctx))
        });
    }
}

#[actix_rt::main]
async fn main() {
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

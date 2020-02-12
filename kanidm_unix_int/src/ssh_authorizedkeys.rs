#[macro_use]
extern crate log;

use log::debug;
use structopt::StructOpt;

use bytes::{BufMut, BytesMut};
use futures::executor::block_on;
use futures::SinkExt;
use futures::StreamExt;
use std::error::Error;
use std::io::Error as IoError;
use std::io::ErrorKind;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};

use kanidm_unix_common::constants::DEFAULT_SOCK_PATH;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

struct ClientCodec;

impl Decoder for ClientCodec {
    type Item = ClientResponse;
    type Error = IoError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_cbor::from_slice::<ClientResponse>(&src) {
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
    type Item = ClientRequest;
    type Error = IoError;

    fn encode(&mut self, msg: ClientRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_cbor::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            IoError::new(ErrorKind::Other, "CBOR encode error")
        })?;
        debug!("Attempting to send request -> {:?} ...", data);
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

#[derive(Debug, StructOpt)]
struct ClientOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt()]
    account_id: String,
}

async fn call_daemon(path: &str, req: ClientRequest) -> Result<ClientResponse, Box<dyn Error>> {
    let stream = UnixStream::connect(path).await?;

    let mut reqs = Framed::new(stream, ClientCodec::new());

    reqs.send(req).await?;
    reqs.flush().await?;

    match reqs.next().await {
        Some(Ok(res)) => {
            debug!("Response -> {:?}", res);
            Ok(res)
        }
        _ => {
            error!("Error");
            Err(Box::new(IoError::new(ErrorKind::Other, "oh no!")))
        }
    }
}

#[tokio::main]
async fn main() {
    let opt = ClientOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    debug!("Starting authorized keys tool ...");
    let req = ClientRequest::SshKey(opt.account_id.clone());

    match block_on(call_daemon(DEFAULT_SOCK_PATH, req)) {
        Ok(r) => {
            debug!("Ok -> {:?}", r);
        }
        Err(e) => {
            error!("Error -> {:?}", e);
        }
    }
}

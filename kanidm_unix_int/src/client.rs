use bytes::{BufMut, BytesMut};
use futures::SinkExt;
use futures::StreamExt;
use std::error::Error;
use std::io::Error as IoError;
use std::io::ErrorKind;
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};

use crate::unix_proto::{ClientRequest, ClientResponse};

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

impl Encoder<ClientRequest> for ClientCodec {
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

pub async fn call_daemon(path: &str, req: ClientRequest) -> Result<ClientResponse, Box<dyn Error>> {
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

pub fn call_daemon_blocking(
    path: &str,
    req: ClientRequest,
) -> Result<ClientResponse, Box<dyn Error>> {
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Box::new)?;
    rt.block_on(call_daemon(path, req))
}

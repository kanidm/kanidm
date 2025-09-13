use crate::constants::DEFAULT_CONN_TIMEOUT;
use crate::json_codec::JsonCodec;
use crate::unix_proto::{ClientRequest, ClientResponse};
use bytes::BytesMut;
use std::error::Error;
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime};
use tokio_util::codec::{Decoder, Encoder};

pub use std::os::unix::net::UnixStream;

type ClientCodec = JsonCodec<ClientResponse, ClientRequest>;

pub struct DaemonClientBlocking {
    stream: UnixStream,
    codec: ClientCodec,
    default_timeout: u64,
}

impl From<UnixStream> for DaemonClientBlocking {
    fn from(stream: UnixStream) -> Self {
        DaemonClientBlocking {
            stream,
            codec: ClientCodec::default(),
            default_timeout: DEFAULT_CONN_TIMEOUT,
        }
    }
}

impl DaemonClientBlocking {
    pub fn new(path: &str, default_timeout: u64) -> Result<DaemonClientBlocking, Box<dyn Error>> {
        debug!(%path);

        let stream = UnixStream::connect(path)
            .map_err(|e| {
                error!(
                    "Unix socket stream setup error while connecting to {} -> {:?}",
                    path, e
                );
                e
            })
            .map_err(Box::new)?;

        Ok(DaemonClientBlocking {
            stream,
            codec: ClientCodec::default(),
            default_timeout,
        })
    }

    pub fn call_and_wait(
        &mut self,
        req: ClientRequest,
        timeout: Option<u64>,
    ) -> Result<ClientResponse, Box<dyn Error>> {
        let timeout = Duration::from_secs(timeout.unwrap_or(self.default_timeout));

        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| {
                error!(
                    ?err,
                    "Unix socket stream setup error while setting read timeout",
                );
                Box::new(err)
            })?;

        self.stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| {
                error!(
                    ?err,
                    "Unix socket stream setup error while setting write timeout",
                );
                Box::new(err)
            })?;

        // We want this to be blocking so that we wait for data to be ready
        self.stream.set_nonblocking(false).map_err(|err| {
            error!(
                ?err,
                "Unix socket stream setup error while setting nonblocking=false",
            );
            Box::new(err)
        })?;

        let mut data = BytesMut::new();

        self.codec.encode(req, &mut data).map_err(Box::new)?;

        self.stream
            .write_all(&data)
            .and_then(|_| self.stream.flush())
            .map_err(|e| {
                error!("stream write error -> {:?}", e);
                e
            })
            .map_err(Box::new)?;

        // Now wait on the response.
        data.clear();
        let start = SystemTime::now();
        let mut read_started = false;

        loop {
            let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
            if durr > timeout {
                error!("Socket timeout");
                // timed out, not enough activity.
                return Err(Box::new(io::Error::other("Timeout")));
            }

            let mut buffer = [0; 8192];

            // Would be a lot easier if we had peek ...
            // https://github.com/rust-lang/rust/issues/76923
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    if read_started {
                        debug!("read_started true, no bytes read");
                        // We're done, no more bytes. This will now
                        // fall through to the codec decode to double
                        // check this assertion.
                    } else {
                        debug!("Waiting ...");
                        // Still can wait ...
                        continue;
                    }
                }
                Ok(count) => {
                    read_started = true;
                    debug!("read {count} bytes");
                    data.extend_from_slice(&buffer[..count]);
                }
                Err(e) => {
                    error!("Stream read failure from {:?} -> {:?}", &self.stream, e);
                    // Failure!
                    return Err(Box::new(e));
                }
            }

            match self.codec.decode(&mut data) {
                // A whole frame is ready and present.
                Ok(Some(cr)) => return Ok(cr),
                // Need more data
                Ok(None) => continue,
                // Failed to decode for some reason
                Err(e) => return Err(Box::new(e)),
            }
        }
    }
}

use crate::constants::DEFAULT_CONN_TIMEOUT;
use crate::json_codec::JsonCodec;
use crate::unix_proto::{ClientRequest, ClientResponse};
use bytes::BytesMut;
use std::error::Error;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::codec::{Decoder, Encoder};

pub use std::os::unix::net::UnixStream;

type ClientCodec = JsonCodec<ClientResponse, ClientRequest>;

#[derive(Clone)]
pub struct DaemonClientBlocking {
    inner: Arc<Mutex<DaemonClientBlockingInner>>,
}

struct DaemonClientBlockingInner {
    stream: UnixStream,
    codec: ClientCodec,
    default_timeout: u64,
    reconnect: bool,
}

impl From<UnixStream> for DaemonClientBlocking {
    fn from(stream: UnixStream) -> Self {
        DaemonClientBlocking {
            inner: Arc::new(Mutex::new(DaemonClientBlockingInner {
                stream,
                codec: ClientCodec::default(),
                default_timeout: DEFAULT_CONN_TIMEOUT,
                reconnect: false,
            })),
        }
    }
}

impl DaemonClientBlocking {
    pub fn new(path: &str, default_timeout: u64) -> Result<DaemonClientBlocking, Box<dyn Error>> {
        // Setup a subscriber incase one isn't setup.
        if cfg!(feature = "client_sync_tracing") {
            use tracing_subscriber::prelude::*;
            use tracing_subscriber::{filter::LevelFilter, fmt};

            let fmt_layer = fmt::layer().with_target(false);
            let filter_layer = LevelFilter::WARN;

            let _ = tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .try_init();
        }

        trace!(%path);

        let stream = UnixStream::connect(path).map_err(|err| {
            error!(
                ?err, %path,
                "Unix socket stream setup error",
            );
            Box::new(err)
        })?;

        Ok(DaemonClientBlocking {
            inner: Arc::new(Mutex::new(DaemonClientBlockingInner {
                stream,
                codec: ClientCodec::default(),
                default_timeout,
                reconnect: false,
            })),
        })
    }

    pub fn call_and_wait(
        &self,
        req: ClientRequest,
        timeout: Option<u64>,
    ) -> Result<ClientResponse, Box<dyn Error + '_>> {
        let mut guard = self.inner.lock().map_err(|err| {
            error!(?err, "critical, daemon client mutex has been poisoned!!!");
            Box::new(err)
        })?;

        if guard.reconnect {
            let peer_addr = guard.stream.peer_addr().map_err(|err| {
                error!(
                    ?err,
                    "critical, stream has no peer address, unable to reconnect!!!"
                );
                Box::new(err)
            })?;

            let mut new_stream = UnixStream::connect_addr(&peer_addr).map_err(|err| {
                error!(?err, ?peer_addr, "Unix socket stream setup error",);
                Box::new(err)
            })?;

            debug!("Reconnection complete.");

            std::mem::swap(&mut guard.stream, &mut new_stream);
            guard.reconnect = false;
        }

        guard.call_and_wait(req, timeout).inspect_err(|_| {
            debug!("error occured during communication, will reconnect ...");
            guard.reconnect = true;
        })
    }
}

impl DaemonClientBlockingInner {
    fn call_and_wait(
        &mut self,
        req: ClientRequest,
        timeout: Option<u64>,
    ) -> Result<ClientResponse, Box<dyn Error>> {
        let timeout = Duration::from_secs(timeout.unwrap_or(self.default_timeout));

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

        self.codec.encode(req, &mut data).map_err(|err| {
            error!(?err, "codec encode error");
            Box::new(err)
        })?;

        self.stream
            .write_all(&data)
            .and_then(|_| self.stream.flush())
            .map_err(|err| {
                error!(?err, "stream write error");
                Box::new(err)
            })?;

        // Set our read timeout
        self.stream.set_read_timeout(Some(timeout)).map_err(|err| {
            error!(
                ?err,
                "Unix socket stream setup error while setting read timeout",
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

        trace!(read_timeout = ?self.stream.read_timeout(), write_timeout = ?self.stream.write_timeout());

        // Now wait on the response.
        data.clear();
        let start = Instant::now();
        let mut read_started = false;

        loop {
            trace!("read loop");
            let durr = Instant::now().duration_since(start);
            if durr > timeout {
                error!("Socket timeout");
                // timed out, not enough activity.
                return Err(Box::new(io::Error::other("Timeout")));
            }

            let mut buffer = [0; 16 * 1024];

            // Would be a lot easier if we had peek ...
            // https://github.com/rust-lang/rust/issues/76923
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    if read_started {
                        trace!("read_started true, no bytes read");
                        // We're done, no more bytes. This will now
                        // fall through to the codec decode to double
                        // check this assertion.
                    } else {
                        trace!("Waiting ...");
                        // Still can wait ...
                        continue;
                    }
                }
                Ok(count) => {
                    read_started = true;
                    trace!("read {count} bytes");
                    data.extend_from_slice(&buffer[..count]);
                    if count == buffer.len() {
                        // Whole buffer, read again
                        continue;
                    }
                    // Not a whole buffer, probably complete.
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    warn!("read from UDS would block, try again.");
                    // std::thread::sleep(Duration::from_millis(1));
                    std::thread::yield_now();
                    continue;
                }
                Err(err) => {
                    error!(?err, err_kind = ?err.kind(), "Stream read failure from {:?}", &self.stream);
                    // Failure!
                    return Err(Box::new(err));
                }
            }

            match self.codec.decode(&mut data) {
                // A whole frame is ready and present.
                Ok(Some(cr)) => {
                    trace!("read loop - ok");
                    return Ok(cr);
                }
                // Need more data
                Ok(None) => {
                    trace!("need more");
                    continue;
                }
                // Failed to decode for some reason
                Err(err) => {
                    error!(?err, "failed to decode response");
                    return Err(Box::new(err));
                }
            }
        }
    }
}

use std::error::Error;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use std::time::{Duration, SystemTime};

use crate::unix_proto::{ClientRequest, ClientResponse};

const TIMEOUT: u64 = 2000;

pub fn call_daemon_blocking(
    path: &str,
    req: ClientRequest,
) -> Result<ClientResponse, Box<dyn Error>> {
    let mut stream = UnixStream::connect(path)
        .and_then(|socket| socket.set_nonblocking(true).map(|_| socket))
        .map_err(|e| {
            error!("stream setup error -> {:?}", e);
            e
        })
        .map_err(Box::new)?;

    let data = serde_cbor::to_vec(&req).map_err(|e| {
        error!("socket encoding error -> {:?}", e);
        Box::new(IoError::new(ErrorKind::Other, "CBOR encode error"))
    })?;
    //  .map_err(Box::new)?;

    stream
        .write_all(data.as_slice())
        .and_then(|_| stream.flush())
        .map_err(|e| {
            error!("stream write error -> {:?}", e);
            e
        })
        .map_err(Box::new)?;

    // Now wait on the response.
    let start = SystemTime::now();
    let timeout = Duration::from_millis(TIMEOUT);
    let mut read_started = false;
    let mut data = Vec::with_capacity(1024);

    loop {
        let mut buffer = [0; 1024];
        // Would be a lot easier if we had peek ...
        // https://github.com/rust-lang/rust/issues/76923
        match stream.read(&mut buffer) {
            Ok(0) => {
                if read_started {
                    debug!("read_started true, we have completed");
                    // We're done, no more bytes.
                    break;
                } else {
                    let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
                    if durr > timeout {
                        debug!("Timeout");
                        // timed out, no activity.
                        break;
                    } else {
                        debug!("Waiting ...");
                        // Still can wait ...
                        continue;
                    }
                }
            }
            Ok(count) => {
                data.extend_from_slice(&buffer);
                if count == 1024 {
                    debug!("Filled 1024 bytes, looping ...");
                    // We have filled the buffer, we need to copy and loop again.
                    read_started = true;
                    continue;
                } else {
                    debug!("Filled {} bytes, complete", count);
                    // We have a partial read, so we are complete.
                    break;
                }
            }
            Err(e) => {
                error!("Steam read failure -> {:?}", e);
                // Failure!
                return Err(Box::new(e));
            }
        }
    }

    // Now attempt to decode.
    let cr = serde_cbor::from_slice::<ClientResponse>(data.as_slice()).map_err(|e| {
        error!("socket encoding error -> {:?}", e);
        Box::new(IoError::new(ErrorKind::Other, "CBOR encode error"))
    })?;

    Ok(cr)
}

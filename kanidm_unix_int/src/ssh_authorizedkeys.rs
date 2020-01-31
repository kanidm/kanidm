#[macro_use]
extern crate log;

use log::debug;
use structopt::StructOpt;

use std::os::unix::net::UnixStream;
use std::io::Write;
use std::io::Read;
use std::time::Duration;

use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};
use kanidm_unix_common::constants::DEFAULT_SOCK_PATH;


#[derive(Debug, StructOpt)]
struct ClientOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt()]
    account_id: String,
}

fn main() {
    let opt = ClientOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    debug!("Starting authorized keys tool ...");

    // Connect to the uds
    let mut socket = match UnixStream::connect(DEFAULT_SOCK_PATH) {
        Ok(sock) => sock,
        Err(e) => {
            error!("Unable to open socket -> {:?}", e);
            return
        }
    };

    // Send the request
    let req = ClientRequest::SshKey(
        opt.account_id.clone()
    );

    let req_bytes = match serde_cbor::to_vec(&req) {
        Ok(bytes) => {
            debug!("Prepared request ...");
            bytes
        }
        Err(e) => {
            error!("Unable to serialise request -> {:?}", e);
            return
        }
    };

    debug!("Request bytes -> {:?}", req_bytes);

    socket.set_write_timeout(Some(Duration::new(5, 0)))
        .expect("Couldn't set write timeout");

    socket.set_nonblocking(false)
        .expect("Unable to configure socket to block");

    match socket.write_all(req_bytes.as_slice()) {
        Ok(_) => {
            debug!("Wrote request  ...");
        }
        Err(e) => {
            error!("Unable to write request -> {:?}", e);
            return
        }
    };

    debug!("Begin read ...");

    // Block on response?
    let mut buffer = Vec::new();
    match socket.read_to_end(&mut buffer) {
        Ok(count) =>
            debug!("Read {:?} bytes", count),
        Err(e) => {
            error!("Unable to read response -> {:?}", e);
            return
        }
    }

    println!("{:?}", buffer);
}


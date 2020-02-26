#[macro_use]
extern crate log;

use log::debug;
use structopt::StructOpt;

use futures::executor::block_on;

use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

#[derive(Debug, StructOpt)]
struct ClientOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "D", long = "name")]
    account_id: String,
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

    debug!("Starting cache invalidate tool ...");

    let cfg = KanidmUnixdConfig::new()
        .read_options_from_optional_config("/etc/kanidm/unixd")
        .expect("Failed to parse /etc/kanidm/unixd");

    let password = rpassword::prompt_password_stderr("Enter unix password: ").unwrap();

    let req = ClientRequest::Authenticate(opt.account_id.clone(), password);

    match block_on(call_daemon(cfg.sock_path.as_str(), req)) {
        Ok(r) => match r {
            ClientResponse::Ok => info!("auth success!"),
            ClientResponse::Failed => info!("auth failed"),
            _ => {
                error!("Error: unexpected response -> {:?}", r);
            }
        },
        Err(e) => {
            error!("Error -> {:?}", e);
        }
    }
}

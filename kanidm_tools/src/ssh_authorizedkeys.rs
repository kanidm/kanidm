extern crate structopt;
use kanidm_client::KanidmClient;
use std::path::PathBuf;
use structopt::StructOpt;

extern crate env_logger;
#[macro_use]
extern crate log;

#[derive(Debug, StructOpt)]
struct ClientOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "H", long = "url")]
    addr: String,
    #[structopt(short = "D", long = "name")]
    username: String,
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    ca_path: Option<PathBuf>,
    #[structopt()]
    account_id: String,
}

// For now we lift a few things from the main.rs to use.
//
// usage: AuthorizedKeysCommand /usr/sbin/kanidm_ssh_authorizedkeys %u -H URL -D anonymous -C /etc/kanidm/ca.pem
//
fn main() {
    let opt = ClientOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    let ca_path: Option<&str> = opt.ca_path.as_ref().map(|p| p.to_str().unwrap());
    let client = KanidmClient::new(opt.addr.as_str(), ca_path);

    let r = if opt.username == "anonymous" {
        client.auth_anonymous()
    } else {
        let password = rpassword::prompt_password_stderr("Enter password: ").unwrap();
        client.auth_simple_password(opt.username.as_str(), password.as_str())
    };

    if r.is_err() {
        eprintln!("Error during authentication phase: {:?}", r);
        std::process::exit(1);
    }

    let pkeys = client
        .idm_account_get_ssh_pubkeys(opt.account_id.as_str())
        .unwrap();

    for pkey in pkeys {
        println!("{}", pkey)
    }
}

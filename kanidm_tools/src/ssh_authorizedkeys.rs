use std::path::PathBuf;

use kanidm_client::KanidmClientBuilder;

use log::debug;
use shellexpand;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct ClientOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "H", long = "url")]
    addr: Option<String>,
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

    let config_path: String = shellexpand::tilde("~/.config/kanidm").into_owned();
    debug!("Attempting to use config {}", "/etc/kanidm/config");
    let client_builder = KanidmClientBuilder::new()
        .read_options_from_optional_config("/etc/kanidm/config")
        .and_then(|cb| {
            debug!("Attempting to use config {}", config_path);
            cb.read_options_from_optional_config(config_path)
        })
        .expect("Failed to parse config (if present)");

    let client_builder = match &opt.addr {
        Some(a) => client_builder.address(a.to_string()),
        None => client_builder,
    };

    let ca_path: Option<&str> = opt.ca_path.as_ref().map(|p| p.to_str().unwrap());
    let client_builder = match ca_path {
        Some(p) => client_builder
            .add_root_certificate_filepath(p)
            .expect("Failed to access CA file"),
        None => client_builder,
    };

    let client = client_builder
        .build()
        .expect("Failed to build client instance");

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

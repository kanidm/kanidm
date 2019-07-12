extern crate actix;
extern crate env_logger;

extern crate rsidm;

use rsidm::config::Configuration;
use rsidm::core::create_server_core;

fn main() {
    // Read our config (if any)
    let config = Configuration::new();

    // Configure the server logger. This could be adjusted based on what config
    // says.
    ::std::env::set_var("RUST_LOG", "actix_web=info,rsidm=info");
    env_logger::init();

    let sys = actix::System::new("rsidm-server");

    create_server_core(config);
    let _ = sys.run();
}

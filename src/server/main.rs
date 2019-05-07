extern crate actix;

extern crate rsidm;


use rsidm::config::Configuration;
use rsidm::core::create_server_core;

fn main() {
    // read the config (if any?)
    // How do we make the config accesible to all threads/workers? clone it?
    // Make it an Arc<Config>?

    // FIXME: Pass config to the server core
    let config = Configuration::new();
    let sys = actix::System::new("rsidm-server");

    create_server_core(config);
    let _ = sys.run();
}

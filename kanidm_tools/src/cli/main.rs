use kanidm_cli::ClientOpt;
use structopt::StructOpt;

fn main() {
    let opt = ClientOpt::from_args();

    if opt.debug() {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    opt.exec()
}

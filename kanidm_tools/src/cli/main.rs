#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use kanidm_cli::KanidmClientOpt;
use structopt::StructOpt;

fn main() {
    let opt = KanidmClientOpt::from_args();

    if opt.debug() {
        ::std::env::set_var(
            "RUST_LOG",
            "kanidm=debug,kanidm_client=debug,webauthn=debug",
        );
    }
    tracing_subscriber::fmt::init();

    opt.exec()
}

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]

use clap::Parser;
use kanidm_cli::KanidmClientParser;
use std::thread;
use tokio::runtime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

fn main() {
    let opt = KanidmClientParser::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = if opt.commands.debug() {
        match EnvFilter::try_new("kanidm=debug,kanidm_client=debug,webauthn=debug,kanidm_cli=debug")
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR! Unable to start tracing {:?}", e);
                return;
            }
        }
    } else {
        match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::new("kanidm_client=warn,kanidm_cli=warn"),
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let par_count = thread::available_parallelism()
        .expect("Failed to determine available parallelism")
        .get();

    let rt = runtime::Builder::new_current_thread()
        // We configure this as it's used by the badlist pre-processor
        .max_blocking_threads(par_count)
        .enable_all()
        .build()
        .expect("Failed to initialise tokio runtime!");

    tracing::debug!("Using {} worker threads", par_count);

    rt.block_on(async { opt.commands.exec().await });
}

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
use std::process::ExitCode;
use std::thread;
use tokio::runtime;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

async fn signal_handler(opt: KanidmClientParser) -> ExitCode {
    // We need a signal handler to deal with a few things that can occur during runtime, especially
    // sigpipe on linux.

    let mut signal_quit = signal(SignalKind::quit()).expect("Invalid Signal");
    let mut signal_term = signal(SignalKind::terminate()).expect("Invalid Signal");
    let mut signal_pipe = signal(SignalKind::pipe()).expect("Invalid Signal");

    tokio::select! {
        _ = opt.commands.exec() => {
            ExitCode::SUCCESS
        }
        _ = signal_quit.recv() => {
            ExitCode::SUCCESS
        }
        _ = signal_term.recv() => {
            ExitCode::SUCCESS
        }
        _ = signal_pipe.recv() => {
            ExitCode::SUCCESS
        }
    }
}

fn main() -> ExitCode {
    let opt = KanidmClientParser::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = if opt.commands.debug() {
        match EnvFilter::try_new("kanidm=debug,kanidm_client=debug,webauthn=debug,kanidm_cli=debug")
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR! Unable to start tracing {:?}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .parse_lossy("kanidm_client=warn,kanidm_cli=info"),
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

    #[cfg(debug_assertions)]
    tracing::debug!("Using {} worker threads", par_count);

    rt.block_on(signal_handler(opt))
}

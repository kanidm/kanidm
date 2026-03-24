use clap::Parser;
use std::path::PathBuf;

mod bootstrap;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, env = "KANIDM_RLM_CONFIG")]
    config: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let debug = std::env::var_os("DEBUG").is_some();

    if let Err(error) = bootstrap::run(cli.config.as_deref(), debug) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

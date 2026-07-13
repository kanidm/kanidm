use clap::Parser;
use std::path::PathBuf;

mod bootstrap;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(short, long, env = "DEBUG")]
    debug: bool,
    #[arg(long, env = "KANIDM_RLM_CONFIG")]
    config: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    if let Err(error) = bootstrap::run(cli.config.as_deref(), cli.debug) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

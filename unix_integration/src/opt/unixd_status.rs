#[derive(Debug, Parser)]
struct UnixdStatusOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

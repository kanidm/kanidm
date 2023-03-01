#[derive(Debug, Parser)]
struct CacheInvalidateOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

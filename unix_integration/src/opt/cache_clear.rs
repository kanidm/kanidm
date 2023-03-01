#[derive(Debug, Parser)]
struct CacheClearOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    version: bool,
    #[clap(long)]
    really: bool,
}

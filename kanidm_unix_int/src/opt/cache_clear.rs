#[derive(Debug, Parser)]
struct CacheClearOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap(long)]
    really: bool,
}

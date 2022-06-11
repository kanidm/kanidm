#[derive(Debug, Parser)]
struct CacheInvalidateOpt {
    #[clap(short, long)]
    debug: bool,
}

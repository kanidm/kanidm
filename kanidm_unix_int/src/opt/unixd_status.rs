#[derive(Debug, Parser)]
struct UnixdStatusOpt {
    #[clap(short, long)]
    debug: bool,
}

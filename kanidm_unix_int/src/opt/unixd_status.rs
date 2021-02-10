#[derive(Debug, StructOpt)]
struct UnixdStatusOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
}


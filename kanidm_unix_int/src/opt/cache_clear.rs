#[derive(Debug, StructOpt)]
struct CacheClearOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(long = "really")]
    really: bool,
}



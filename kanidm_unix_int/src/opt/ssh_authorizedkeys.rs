
#[derive(Debug, StructOpt)]
struct SshAuthorizedOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt()]
    account_id: String,
}

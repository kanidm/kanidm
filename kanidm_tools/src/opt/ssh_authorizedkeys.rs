
#[derive(Debug, StructOpt)]
struct SshAuthorizedOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "H", long = "url")]
    addr: Option<String>,
    #[structopt(short = "D", long = "name")]
    username: String,
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    ca_path: Option<PathBuf>,
    #[structopt()]
    account_id: String,
}

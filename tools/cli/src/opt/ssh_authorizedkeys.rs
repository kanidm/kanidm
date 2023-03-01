#[derive(Debug, Parser)]
struct SshAuthorizedOpt {
    #[clap(short, long = "debug")]
    debug: bool,
    #[clap(short = 'H', long = "url")]
    addr: Option<String>,
    #[clap(short = 'D', long = "name")]
    username: String,
    #[clap(parse(from_os_str), short = 'C', long = "ca")]
    ca_path: Option<PathBuf>,
    account_id: String,
}

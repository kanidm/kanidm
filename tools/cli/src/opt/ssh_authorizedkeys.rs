#[derive(Debug, Parser)]
#[command(version)]
pub(crate) struct SshAuthorizedOpt {
    #[clap(short, long = "debug")]
    debug: bool,
    #[clap(short = 'H', long = "url")]
    addr: Option<String>,
    #[clap(short = 'D', long = "name")]
    username: String,
    #[clap(value_parser, short = 'C', long = "ca")]
    ca_path: Option<PathBuf>,
    account_id: String,
}

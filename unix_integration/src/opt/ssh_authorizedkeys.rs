#[derive(Debug, Parser)]
struct SshAuthorizedOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap()]
    account_id: String,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

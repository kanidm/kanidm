#[derive(Debug, Parser)]
struct SshAuthorizedOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap()]
    account_id: String,
}

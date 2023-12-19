#[derive(Debug, Parser)]
#[command(name = "kanidm_ssh_authorizedkeys")]
struct SshAuthorizedOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap()]
    account_id: Option<String>,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

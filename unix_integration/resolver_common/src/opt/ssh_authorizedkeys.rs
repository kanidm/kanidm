use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "kanidm_ssh_authorizedkeys")]
pub struct SshAuthorizedOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap()]
    account_id: Option<String>,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

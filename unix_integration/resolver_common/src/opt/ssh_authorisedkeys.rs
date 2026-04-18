use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "kanidm_ssh_authorizedkeys")]
pub struct SshAuthorisedKeysOpt {
    #[clap(short, long)]
    pub debug: bool,
    #[clap()]
    pub account_id: Option<String>,
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    pub version: bool,
}

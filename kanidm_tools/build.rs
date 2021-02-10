use std::env;
use std::path::PathBuf;

use structopt::clap::Shell;
use structopt::StructOpt;

include!("src/opt/ssh_authorizedkeys.rs");
include!("src/opt/badlist_preprocess.rs");
include!("src/opt/kanidm.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys_direct",
        Shell::Bash,
        outdir.clone(),
    );
    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys_direct",
        Shell::Zsh,
        outdir.clone(),
    );

    BadlistProcOpt::clap().gen_completions(
        "kanidm_badlist_preprocess",
        Shell::Bash,
        outdir.clone(),
    );
    BadlistProcOpt::clap().gen_completions("kanidm_badlist_preprocess", Shell::Zsh, outdir.clone());

    KanidmClientOpt::clap().gen_completions("kanidm", Shell::Bash, outdir.clone());
    KanidmClientOpt::clap().gen_completions("kanidm", Shell::Zsh, outdir);
}

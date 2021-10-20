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

    let comp_dir = PathBuf::from(outdir)
        .ancestors()
        .skip(2)
        .next()
        .map(|p| p.join("completions"))
        .expect("Unable to process completions path");

    if !comp_dir.exists() {
        std::fs::create_dir(&comp_dir).expect("Unable to create completions dir");
    }

    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys_direct",
        Shell::Bash,
        comp_dir.clone(),
    );
    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys_direct",
        Shell::Zsh,
        comp_dir.clone(),
    );

    BadlistProcOpt::clap().gen_completions(
        "kanidm_badlist_preprocess",
        Shell::Bash,
        comp_dir.clone(),
    );
    BadlistProcOpt::clap().gen_completions(
        "kanidm_badlist_preprocess",
        Shell::Zsh,
        comp_dir.clone(),
    );

    KanidmClientOpt::clap().gen_completions("kanidm", Shell::Bash, comp_dir.clone());
    KanidmClientOpt::clap().gen_completions("kanidm", Shell::Zsh, comp_dir);
}

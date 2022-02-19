#![allow(dead_code)]
use std::env;

use structopt::clap::Shell;
use structopt::StructOpt;

use std::path::PathBuf;

include!("src/opt/ssh_authorizedkeys.rs");
include!("src/opt/cache_invalidate.rs");
include!("src/opt/cache_clear.rs");
include!("src/opt/unixd_status.rs");

fn main() {
    profiles::apply_profile();

    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    let comp_dir = PathBuf::from(outdir)
        .ancestors()
        .nth(2)
        .map(|p| p.join("completions"))
        .expect("Unable to process completions path");

    if !comp_dir.exists() {
        std::fs::create_dir(&comp_dir).expect("Unable to create completions dir");
    }

    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys",
        Shell::Bash,
        comp_dir.clone(),
    );
    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys",
        Shell::Zsh,
        comp_dir.clone(),
    );

    CacheInvalidateOpt::clap().gen_completions(
        "kanidm_cache_invalidate",
        Shell::Bash,
        comp_dir.clone(),
    );
    CacheInvalidateOpt::clap().gen_completions(
        "kanidm_cache_invalidate",
        Shell::Zsh,
        comp_dir.clone(),
    );

    CacheClearOpt::clap().gen_completions("kanidm_cache_clear", Shell::Bash, comp_dir.clone());
    CacheClearOpt::clap().gen_completions("kanidm_cache_clear", Shell::Zsh, comp_dir.clone());

    UnixdStatusOpt::clap().gen_completions("kanidm_unixd_status", Shell::Bash, comp_dir.clone());
    UnixdStatusOpt::clap().gen_completions("kanidm_unixd_status", Shell::Zsh, comp_dir);
}

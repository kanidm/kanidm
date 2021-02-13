use std::env;

use structopt::clap::Shell;
use structopt::StructOpt;

include!("src/opt/ssh_authorizedkeys.rs");
include!("src/opt/cache_invalidate.rs");
include!("src/opt/cache_clear.rs");
include!("src/opt/unixd_status.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys",
        Shell::Bash,
        outdir.clone(),
    );
    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys",
        Shell::Zsh,
        outdir.clone(),
    );

    CacheInvalidateOpt::clap().gen_completions(
        "kanidm_cache_invalidate",
        Shell::Bash,
        outdir.clone(),
    );
    CacheInvalidateOpt::clap().gen_completions(
        "kanidm_cache_invalidate",
        Shell::Zsh,
        outdir.clone(),
    );

    CacheClearOpt::clap().gen_completions("kanidm_cache_clear", Shell::Bash, outdir.clone());
    CacheClearOpt::clap().gen_completions("kanidm_cache_clear", Shell::Zsh, outdir.clone());

    UnixdStatusOpt::clap().gen_completions("kanidm_unixd_status", Shell::Bash, outdir.clone());
    UnixdStatusOpt::clap().gen_completions("kanidm_unixd_status", Shell::Zsh, outdir);
}

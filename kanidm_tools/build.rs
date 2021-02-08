use std::env;
use std::path::PathBuf;

use structopt::clap::Shell;
use structopt::StructOpt;

include!("src/opt/ssh_authorizedkeys.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    SshAuthorizedOpt::clap().gen_completions(
        "ssh_authorizedkeys_direct",
        Shell::Bash,
        outdir.clone(),
    );
    SshAuthorizedOpt::clap().gen_completions(
        "ssh_authorizedkeys_direct",
        Shell::Zsh,
        outdir.clone(),
    );

    println!("{:?}", outdir);
}

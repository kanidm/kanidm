#[macro_use]
extern crate serde_derive;

use std::env;

use std::path::PathBuf;
use structopt::clap::Shell;
use structopt::StructOpt;

include!("src/lib/audit_loglevel.rs");
include!("src/server/opt.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    KanidmdOpt::clap().gen_completions("kanidmd", Shell::Bash, outdir.clone());
    KanidmdOpt::clap().gen_completions("kanidmd", Shell::Zsh, outdir.clone());
}

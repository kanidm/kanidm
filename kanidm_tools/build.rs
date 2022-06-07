#![allow(dead_code)]

use std::env;
use std::path::PathBuf;

use clap::{Args, IntoApp, Parser, Subcommand};
use clap_complete::{generate_to, Shell};

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
        .nth(2)
        .map(|p| p.join("completions"))
        .expect("Unable to process completions path");

    if !comp_dir.exists() {
        std::fs::create_dir(&comp_dir).expect("Unable to create completions dir");
    }

    generate_to(
        Shell::Bash,
        &mut SshAuthorizedOpt::command(),
        "kanidm_ssh_authorizedkeys_direct",
        comp_dir.clone(),
    );
    generate_to(
        Shell::Zsh,
        &mut SshAuthorizedOpt::command(),
        "kanidm_ssh_authorizedkeys_direct",
        comp_dir.clone(),
    );

    generate_to(
        Shell::Bash,
        &mut BadlistProcOpt::command(),
        "kanidm_badlist_preprocess",
        comp_dir.clone(),
    );
    generate_to(
        Shell::Zsh,
        &mut BadlistProcOpt::command(),
        "kanidm_badlist_preprocess",
        comp_dir.clone(),
    );

    generate_to(
        Shell::Bash,
        &mut KanidmClientParser::command(),
        "kanidm",
        comp_dir.clone(),
    );
    generate_to(
        Shell::Zsh,
        &mut KanidmClientParser::command(),
        "kanidm",
        comp_dir,
    );
}

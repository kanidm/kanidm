#![allow(dead_code)]
use std::env;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use clap_complete::{generate_to, Shell};

include!("src/opt/ssh_authorizedkeys.rs");
include!("src/opt/tool.rs");

fn main() {
    profiles::apply_profile();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!("cargo:rerun-if-changed=src/opt/tool.rs");
    println!("cargo:rerun-if-changed=src/opt/ssh_authorizedkeys.rs");
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

    for shell in [Shell::Bash, Shell::Fish, Shell::Zsh] {
        generate_to(
            shell,
            &mut SshAuthorizedOpt::command(),
            "kanidm_ssh_authorizedkeys",
            comp_dir.clone(),
        )
        .ok();

        generate_to(
            shell,
            &mut KanidmUnixParser::command(),
            "kanidm_unix",
            comp_dir.clone(),
        )
        .ok();
    }
}

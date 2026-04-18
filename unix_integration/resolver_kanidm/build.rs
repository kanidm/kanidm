#![allow(dead_code)]
use std::env;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};

use sparkle_resolver_common::opt::{KanidmUnixParser, SshAuthorisedKeysOpt};

fn main() {
    profiles::apply_profile();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
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

    for shell in [Shell::Bash, Shell::Elvish, Shell::Fish, Shell::Zsh] {
        generate_to(
            shell,
            &mut SshAuthorisedKeysOpt::command(),
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

#![allow(dead_code)]

use std::env;
use std::io::Error;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use clap_complete::{generate_to, Shell};
use url::Url;
use uuid::Uuid;

include!("src/opt/ssh_authorizedkeys.rs");
include!("src/opt/kanidm.rs");

fn main() -> Result<(), Error> {
    profiles::apply_profile();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!("cargo:rerun-if-changed=src/opt/kanidm.rs");
    println!("cargo:rerun-if-changed=src/opt/ssh_authorizedkeys.rs");
    let outdir = match env::var_os("OUT_DIR") {
        None => return Ok(()),
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
            "kanidm_ssh_authorizedkeys_direct",
            comp_dir.clone(),
        )?;

        generate_to(
            shell,
            &mut KanidmClientParser::command(),
            "kanidm",
            comp_dir.clone(),
        )?;
    }
    Ok(())
}

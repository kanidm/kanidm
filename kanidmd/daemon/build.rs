#![allow(dead_code)]

use std::env;
use std::path::PathBuf;

use clap::{Args, IntoApp, Parser, Subcommand};
use clap_complete::{generate_to, Shell};
use serde::{Deserialize, Serialize};

include!("../idm/src/audit_loglevel.rs");
include!("src/opt.rs");

fn main() {
    profiles::apply_profile();

    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    // Will be the form /Volumes/ramdisk/rs/debug/build/kanidm-8aadc4b0821e9fe7/out
    // We want to get to /Volumes/ramdisk/rs/debug/completions
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
        &mut KanidmdParser::command(),
        "kanidmd",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut KanidmdParser::command(),
        "kanidmd",
        comp_dir,
    )
    .ok();
}

#![allow(dead_code)]

use std::env;
use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{generate_to, Shell};

include!("src/opt.rs");

fn main() {
    profiles::apply_profile();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!("cargo:rerun-if-changed=src/opt.rs");
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

    for shell in [Shell::Bash, Shell::Fish, Shell::Zsh] {
        generate_to(
            shell,
            &mut KanidmdParser::command(),
            "kanidmd",
            comp_dir.clone(),
        )
        .ok();
    }
}

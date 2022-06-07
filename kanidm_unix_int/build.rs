#![allow(dead_code)]
use std::env;

use clap::{IntoApp, Parser};
use clap_complete::{generate_to, Shell};

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

    generate_to(
        Shell::Bash,
        &mut SshAuthorizedOpt::command(),
        "kanidm_ssh_authorizedkeys",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut SshAuthorizedOpt::command(),
        "kanidm_ssh_authorizedkeys",
        comp_dir.clone(),
    )
    .ok();

    generate_to(
        Shell::Zsh,
        &mut CacheInvalidateOpt::command(),
        "kanidm_cache_invalidate",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Bash,
        &mut CacheInvalidateOpt::command(),
        "kanidm_cache_invalidate",
        comp_dir.clone(),
    )
    .ok();

    generate_to(
        Shell::Bash,
        &mut CacheClearOpt::command(),
        "kanidm_cache_clear",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut CacheClearOpt::command(),
        "kanidm_cache_clear",
        comp_dir.clone(),
    )
    .ok();

    generate_to(
        Shell::Bash,
        &mut UnixdStatusOpt::command(),
        "kanidm_unixd_status",
        comp_dir.clone(),
    )
    .ok();
    generate_to(
        Shell::Zsh,
        &mut UnixdStatusOpt::command(),
        "kanidm_unixd_status",
        comp_dir.clone(),
    )
    .ok();
}

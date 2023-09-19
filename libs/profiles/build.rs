use std::path::PathBuf;
use std::{env, fs};

use base64::{engine::general_purpose, Engine as _};

// We do this here so it's only actually run and checked once.
fn determine_git_rev() -> Option<String> {
    let path = PathBuf::from("../../");
    let repo = match gix::open(path) {
        Ok(repo) => repo,
        Err(_) => return None,
    };
    let mut head = repo.head().ok()?;
    let commit = head.peel_to_commit_in_place().ok()?;
    let mut commit_id = commit.id().to_string();
    // Now we actually want to trim this to only 10 chars?
    commit_id.truncate(10);
    Some(commit_id)
}

fn main() {
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");

    let profile = env::var("KANIDM_BUILD_PROFILE").unwrap_or_else(|_| "developer".to_string());

    let profile_path: PathBuf = ["./", format!("{}.toml", profile).as_str()]
        .iter()
        .collect();

    let data =
        fs::read(&profile_path).unwrap_or_else(|_| panic!("Failed to read {:?}", profile_path));

    let contents = general_purpose::STANDARD.encode(data);

    if let Some(commit_rev) = determine_git_rev() {
        println!("cargo:rustc-env=KANIDM_PKG_COMMIT_REV={}", commit_rev);
    }

    println!("cargo:rerun-if-changed={}", profile_path.to_str().unwrap());

    println!("cargo:rustc-env=KANIDM_BUILD_PROFILE={}", profile);
    println!("cargo:rustc-env=KANIDM_BUILD_PROFILE_TOML={}", contents);
}

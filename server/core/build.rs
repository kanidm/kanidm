use std::path::{Path, PathBuf};

/// Work out where the workspace dir is
fn workspace_dir() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

/// Determine the git rev, we do this here so it's only actually run and checked once at build time.
fn determine_git_rev() -> Option<String> {
    let repo = match gix::open(workspace_dir()) {
        Ok(repo) => repo,
        Err(_) => {
            return None;
        }
    };
    let mut head = repo.head().ok()?;
    let commit = head.peel_to_commit_in_place().ok()?;
    let mut commit_id = commit.id().to_string();
    // Now we actually want to trim this to only 10 chars?
    commit_id.truncate(10);
    Some(commit_id)
}

fn main() {
    profiles::apply_profile();
    println!("cargo:rerun-if-changed=build.rs");

    // Set a build-time environment variable to the current git commit hash, so we can use it for cache-busting
    if let Some(commit_rev) = determine_git_rev() {
        println!("cargo:rustc-env=KANIDM_PKG_COMMIT_REV={}", commit_rev);
    }
}

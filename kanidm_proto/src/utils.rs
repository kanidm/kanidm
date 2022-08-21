/// Shows the version string and current git commit status at build
pub fn show_version(name: &str) {
    println!("{}", get_version(name));
}

pub fn get_version(name: &str) -> String {
    let version = env!("CARGO_PKG_VERSION");
    #[cfg(not(target_family = "wasm"))]
    match last_git_commit::LastGitCommit::new().build() {
        Ok(value) => format!("{} {} {}", name, version, value.id().short()),
        Err(_) => format!("{} {}", name, version),
    }
    #[cfg(target_family = "wasm")]
    format!("{} {}", name, version)
}

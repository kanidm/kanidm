/// Shows the version string and current git commit status at build
pub fn show_version(name: &str) {
    println!("{}", get_version(name));
}

pub fn get_version(name: &str) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let lgc = match last_git_commit::LastGitCommit::new().build() {
        Ok(value) => value.id().short(),
        Err(_) => String::from("Unknown git commit"),
    };

    format!("{} {} ({})", name, version, lgc)
}

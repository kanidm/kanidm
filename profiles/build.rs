use std::path::PathBuf;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");

    let profile = env::var("KANIDM_BUILD_PROFILE").unwrap_or_else(|_| "developer".to_string());

    let profile_path: PathBuf = ["./", format!("{}.toml", profile).as_str()]
        .iter()
        .collect();

    let data =
        fs::read(&profile_path).unwrap_or_else(|_| panic!("Failed to read {:?}", profile_path));

    let contents = base64::encode(data);

    println!("cargo:rerun-if-changed={}", profile_path.to_str().unwrap());

    println!("cargo:rustc-env=KANIDM_BUILD_PROFILE={}", profile);
    println!("cargo:rustc-env=KANIDM_BUILD_PROFILE_TOML={}", contents);
}

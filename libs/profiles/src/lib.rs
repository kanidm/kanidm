use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use std::env;

// To debug why a rebuild is requested.
// CARGO_LOG=cargo::core::compiler::fingerprint=info cargo ...

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
enum CpuOptLevel {
    apple_m1,
    none,
    native,
    neon_v8,
    x86_64_legacy, // don't use this it's the oldest and worst. unless you've got a really old CPU, in which case, sorry?
    x86_64_v2,
    x86_64_v3,
}

impl Default for CpuOptLevel {
    fn default() -> Self {
        if cfg!(target_arch = "x86_64") {
            CpuOptLevel::x86_64_v2
        } else if cfg!(target_arch = "aarch64") && cfg!(target_os = "macos") {
            CpuOptLevel::apple_m1
        /*
        } else if cfg!(target_arch = "aarch64") && cfg!(target_os = "linux") {
            // Disable neon_v8 on linux - this has issues on non-apple hardware and on
            // opensuse/distro builds.
            CpuOptLevel::neon_v8
        */
        } else {
            CpuOptLevel::none
        }
    }
}

impl std::fmt::Display for CpuOptLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            CpuOptLevel::apple_m1 => write!(f, "apple_m1"),
            CpuOptLevel::none => write!(f, "none"),
            CpuOptLevel::native => write!(f, "native"),
            CpuOptLevel::neon_v8 => write!(f, "neon_v8"),
            CpuOptLevel::x86_64_legacy => write!(f, "x86_64"),
            CpuOptLevel::x86_64_v2 => write!(f, "x86_64_v2"),
            CpuOptLevel::x86_64_v3 => write!(f, "x86_64_v3"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileConfig {
    web_ui_pkg_path: String,
    #[serde(default)]
    cpu_flags: CpuOptLevel,
    admin_bind_path: String,
    default_config_path: String,
    default_unix_shell_path: String,
}

pub fn apply_profile() {
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE_TOML");

    // transform any requested paths for our server. We do this by reading
    // our profile that we have been provided.
    let profile = env!("KANIDM_BUILD_PROFILE");
    let contents = env!("KANIDM_BUILD_PROFILE_TOML");

    let data = general_purpose::STANDARD
        .decode(contents)
        .unwrap_or_else(|_| panic!("Failed to parse profile - {} - {}", profile, contents));

    let profile_cfg: ProfileConfig = toml::from_slice(&data)
        .unwrap_or_else(|_| panic!("Failed to parse profile - {} - {}", profile, contents));

    // We have to setup for our pkg version to be passed into things correctly
    // now. This relies on the profile build.rs to get the commit rev if present, but
    // we combine it with the local package version
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    println!("cargo:rerun-if-env-changed=KANIDM_PKG_COMMIT_REV");

    let version = env!("CARGO_PKG_VERSION");
    if let Some(commit_rev) = option_env!("KANIDM_PKG_COMMIT_REV") {
        println!(
            "cargo:rustc-env=KANIDM_PKG_VERSION={} {}",
            version, commit_rev
        );
    } else {
        println!("cargo:rustc-env=KANIDM_PKG_VERSION={}", version);
    };

    match profile_cfg.cpu_flags {
        CpuOptLevel::apple_m1 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=apple_m1"),
        CpuOptLevel::none => {}
        CpuOptLevel::native => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=native"),
        CpuOptLevel::neon_v8 => {
            println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-features=+neon,+fp-armv8")
        }
        CpuOptLevel::x86_64_legacy => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=x86-64"),
        CpuOptLevel::x86_64_v2 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=x86-64-v2"),
        CpuOptLevel::x86_64_v3 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=x86-64-v3"),
    }
    println!("cargo:rustc-env=KANIDM_PROFILE_NAME={}", profile);
    println!("cargo:rustc-env=KANIDM_CPU_FLAGS={}", profile_cfg.cpu_flags);
    println!(
        "cargo:rustc-env=KANIDM_WEB_UI_PKG_PATH={}",
        profile_cfg.web_ui_pkg_path
    );
    println!(
        "cargo:rustc-env=KANIDM_ADMIN_BIND_PATH={}",
        profile_cfg.admin_bind_path
    );
    println!(
        "cargo:rustc-env=KANIDM_DEFAULT_CONFIG_PATH={}",
        profile_cfg.default_config_path
    );
    println!(
        "cargo:rustc-env=KANIDM_DEFAULT_UNIX_SHELL_PATH={}",
        profile_cfg.default_unix_shell_path
    );
}

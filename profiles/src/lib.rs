use std::env;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
enum CpuOptLevel {
    none,
    native,
    neon_v8,
    x86_64_v2,
    x86_64_v3,
}

impl Default for CpuOptLevel {
    fn default() -> Self {
        if cfg!(target_arch = "x86_64") {
            CpuOptLevel::x86_64_v2
        } else if cfg!(target_arch = "aarch64") {
            CpuOptLevel::neon_v8
        } else {
            CpuOptLevel::none
        }
    }
}

impl std::fmt::Display for CpuOptLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            CpuOptLevel::none => write!(f, "none"),
            CpuOptLevel::native => write!(f, "native"),
            CpuOptLevel::neon_v8 => write!(f, "neon_v8"),
            CpuOptLevel::x86_64_v2 => write!(f, "x86_64_v2"),
            CpuOptLevel::x86_64_v3 => write!(f, "x86_64_v3"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProfileConfig {
    web_ui_pkg_path: String,
    #[serde(default)]
    cpu_flags: CpuOptLevel,
}

pub fn apply_profile() {
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE_TOML");

    // transform any requested paths for our server. We do this by reading
    // our profile that we have been provided.
    let profile = env!("KANIDM_BUILD_PROFILE");
    let contents = env!("KANIDM_BUILD_PROFILE_TOML");

    let data = base64::decode(contents)
        .unwrap_or_else(|_| panic!("Failed to parse profile - {} - {}", profile, contents));

    let profile_cfg: ProfileConfig = toml::from_slice(&data)
        .unwrap_or_else(|_| panic!("Failed to parse profile - {} - {}", profile, contents));

    match profile_cfg.cpu_flags {
        CpuOptLevel::none => {}
        CpuOptLevel::native => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=native"),
        CpuOptLevel::neon_v8 => {
            println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-features=+neon,+fp-armv8")
        }
        CpuOptLevel::x86_64_v2 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=x86-64-v2"),
        CpuOptLevel::x86_64_v3 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=x86-64-v3"),
    }
    println!("cargo:rustc-env=KANIDM_PROFILE_NAME={}", profile);
    println!("cargo:rustc-env=KANIDM_CPU_FLAGS={}", profile_cfg.cpu_flags);
    println!(
        "cargo:rustc-env=KANIDM_WEB_UI_PKG_PATH={}",
        profile_cfg.web_ui_pkg_path
    );
}

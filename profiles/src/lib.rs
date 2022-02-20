use rustc_version::{version, Version};
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
enum CpuOptLevel {
    none,
    native,
    x86_64_v1,
    x86_64_v3,
}

impl std::fmt::Display for CpuOptLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            CpuOptLevel::none => write!(f, "none"),
            CpuOptLevel::native => write!(f, "native"),
            CpuOptLevel::x86_64_v1 => write!(f, "x86_64_v1"),
            CpuOptLevel::x86_64_v3 => write!(f, "x86_64_v3"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProfileConfig {
    web_ui_pkg_path: String,
    cpu_flags: CpuOptLevel,
}

pub fn apply_profile() {
    println!("cargo:rerun-if-env-changed=KANIDM_RUST_MSRV");
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");
    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE_TOML");

    // check to see if the rust version matches the rust minimum version we require for this build
    let rust_minver = env!("KANIDM_RUST_MSRV");
    let required_rust_ver = Version::parse(&rust_minver.replace("\n", "")).unwrap();
    println!("Rust version:     {}", version().unwrap());
    println!("Required version: {}", required_rust_ver);
    if version().unwrap() < required_rust_ver {
        panic!("This crate requires rustc >= {}, quitting.", rust_minver);
    }

    // transform any requested paths for our server. We do this by reading
    // our profile that we have been provided.
    let profile = env!("KANIDM_BUILD_PROFILE");
    let contents = env!("KANIDM_BUILD_PROFILE_TOML");

    let data = base64::decode(contents)
        .unwrap_or_else(|_| panic!("Failed to parse profile - {} - {}", profile, contents));

    let profile_cfg: ProfileConfig = toml::from_slice(&data)
        .unwrap_or_else(|_| panic!("Failed to parse profile - {} - {}", profile, contents));

    /*
     *  x86-64: CMOV, CMPXCHG8B, FPU, FXSR, MMX, FXSR, SCE, SSE, SSE2
     *  x86-64-v2: (close to Nehalem) CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSE4.1, SSE4.2, SSSE3
     *  x86-64-v3: (close to Haswell) AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE
     */

    match profile_cfg.cpu_flags {
        CpuOptLevel::none => {}
        CpuOptLevel::native => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=native"),
        CpuOptLevel::x86_64_v1 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-feature=+cmov,+cx8,+fxsr,+mmx,+sse,+sse2"),
        CpuOptLevel::x86_64_v3 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-feature=+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+cx16,+sahf,+popcnt,+sse3,+sse4.1,+sse4.2,+avx,+avx2,+bmi,+bmi2,+f16c,+fma,+lzcnt,+movbe,+xsave"),
    }
    println!("cargo:rustc-env=KANIDM_PROFILE_NAME={}", profile);
    println!("cargo:rustc-env=KANIDM_CPU_FLAGS={}", profile_cfg.cpu_flags);
    println!(
        "cargo:rustc-env=KANIDM_WEB_UI_PKG_PATH={}",
        profile_cfg.web_ui_pkg_path
    );
}

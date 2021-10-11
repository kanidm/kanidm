#[macro_use]
extern crate serde_derive;

use std::env;

use std::fs::{read_to_string, File};
use std::io::Read;

use std::path::PathBuf;
use structopt::clap::Shell;
use structopt::StructOpt;

use rustc_version::{version, Version};

include!("src/lib/audit_loglevel.rs");
include!("src/server/opt.rs");

include!("../profiles/syntax.rs");

fn main() {
    // check to see if the rust version matches the rust minimum version we require for this build
    let rust_minver = match read_to_string("../RUST_MSRV") {
        Ok(value) => value,
        Err(error) => panic!("Couldn't load RUST_MSRV: {:?}", error),
    };
    let required_rust_ver = Version::parse(&rust_minver.replace("\n", "")).unwrap();
    println!("Rust version:     {}", version().unwrap());
    println!("Required version: {}", required_rust_ver);
    if version().unwrap() <= required_rust_ver {
        panic!("This crate requires rustc >= {}, quitting.", rust_minver);
    }

    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    // Will be the form /Volumes/ramdisk/rs/debug/build/kanidm-8aadc4b0821e9fe7/out
    // We want to get to /Volumes/ramdisk/rs/debug/completions
    let comp_dir = PathBuf::from(outdir)
        .ancestors()
        .skip(2)
        .next()
        .map(|p| p.join("completions"))
        .expect("Unable to process completions path");

    if !comp_dir.exists() {
        std::fs::create_dir(&comp_dir).expect("Unable to create completions dir");
    }

    KanidmdOpt::clap().gen_completions("kanidmd", Shell::Bash, comp_dir.clone());
    KanidmdOpt::clap().gen_completions("kanidmd", Shell::Zsh, comp_dir);

    // transform any requested paths for our server. We do this by reading
    // our profile that we have been provided.

    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");
    let profile = env::var("KANIDM_BUILD_PROFILE").unwrap_or_else(|_| "developer".to_string());

    let profile_path: PathBuf = ["../profiles", format!("{}.toml", profile).as_str()]
        .iter()
        .collect();

    println!("cargo:rerun-if-changed={}", profile_path.to_str().unwrap());

    let mut f =
        File::open(&profile_path).unwrap_or_else(|_| panic!("Failed to open {:?}", profile_path));

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .unwrap_or_else(|_| panic!("Failed to read {:?}", profile_path));

    let profile_cfg: ProfileConfig = toml::from_str(contents.as_str())
        .unwrap_or_else(|_| panic!("Failed to parse {:?}", profile_path));

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

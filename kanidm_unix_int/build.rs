#[macro_use]
extern crate serde_derive;

use std::env;

use structopt::clap::Shell;
use structopt::StructOpt;

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

include!("src/opt/ssh_authorizedkeys.rs");
include!("src/opt/cache_invalidate.rs");
include!("src/opt/cache_clear.rs");
include!("src/opt/unixd_status.rs");

include!("../profiles/syntax.rs");

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys",
        Shell::Bash,
        outdir.clone(),
    );
    SshAuthorizedOpt::clap().gen_completions(
        "kanidm_ssh_authorizedkeys",
        Shell::Zsh,
        outdir.clone(),
    );

    CacheInvalidateOpt::clap().gen_completions(
        "kanidm_cache_invalidate",
        Shell::Bash,
        outdir.clone(),
    );
    CacheInvalidateOpt::clap().gen_completions(
        "kanidm_cache_invalidate",
        Shell::Zsh,
        outdir.clone(),
    );

    CacheClearOpt::clap().gen_completions("kanidm_cache_clear", Shell::Bash, outdir.clone());
    CacheClearOpt::clap().gen_completions("kanidm_cache_clear", Shell::Zsh, outdir.clone());

    UnixdStatusOpt::clap().gen_completions("kanidm_unixd_status", Shell::Bash, outdir.clone());
    UnixdStatusOpt::clap().gen_completions("kanidm_unixd_status", Shell::Zsh, outdir);

    println!("cargo:rerun-if-env-changed=KANIDM_BUILD_PROFILE");
    let profile = env::var("KANIDM_BUILD_PROFILE").unwrap_or_else(|_| "developer".to_string());

    let profile_path: PathBuf = ["../profiles", format!("{}.toml", profile).as_str()]
        .iter()
        .collect();

    println!("cargo:rerun-if-changed={}", profile_path.to_str().unwrap());

    let mut f = File::open(&profile_path)
        .unwrap_or_else(|_| panic!("Failed to open build profile {:?}", profile_path));

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .unwrap_or_else(|_| panic!("Failed to read build profile {:?}", profile_path));

    let profile_cfg: ProfileConfig = toml::from_str(contents.as_str())
        .unwrap_or_else(|_| panic!("Failed to parse build profile {:?}", profile_path));

    match profile_cfg.cpu_flags {
        CpuOptLevel::none => {}
        CpuOptLevel::native => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-cpu=native"),
        CpuOptLevel::x86_64_v1 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-feature=+cmov,+cx8,+fxsr,+mmx,+sse,+sse2"),
        CpuOptLevel::x86_64_v3 => println!("cargo:rustc-env=RUSTFLAGS=-Ctarget-feature=+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+cx16,+sahf,+popcnt,+sse3,+sse4.1,+sse4.2,+avx,+avx2,+bmi,+bmi2,+f16c,+fma,+lzcnt,+movbe,+xsave"),
    }
    println!("cargo:rustc-env=KANIDM_PROFILE_NAME={}", profile);
    println!("cargo:rustc-env=KANIDM_CPU_FLAGS={}", profile_cfg.cpu_flags);
}

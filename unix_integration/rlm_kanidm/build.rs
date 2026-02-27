use std::env;
use std::path::PathBuf;

fn normalize_include_dir(dir: PathBuf) -> PathBuf {
    let path = dir.to_string_lossy();
    if path.ends_with("/freeradius") || path.ends_with("/freeradius-devel") {
        if let Some(parent) = dir.parent() {
            return parent.to_path_buf();
        }
    }
    dir
}

fn main() {
    if env::var_os("CARGO_FEATURE_FREERADIUS_MODULE").is_none() {
        return;
    }

    println!("cargo:rerun-if-changed=src/freeradius_module.c");
    println!("cargo:rerun-if-env-changed=FREERADIUS_INCLUDE_DIR");
    println!("cargo:rustc-link-arg=-Wl,--export-dynamic-symbol=rlm_kanidm");
    println!("cargo:rustc-link-arg=-Wl,--export-dynamic-symbol=rlm_kanidm_module_anchor");

    let mut build = cc::Build::new();
    build.file("src/freeradius_module.c");
    build.warnings(false);

    let mut include_dirs: Vec<PathBuf> = Vec::new();

    if let Ok(include_dir) = env::var("FREERADIUS_INCLUDE_DIR") {
        include_dirs.push(normalize_include_dir(PathBuf::from(include_dir)));
    }

    let fallback_paths: [&str; 1] = ["/tmp/freeradius-src/freeradius-server-release/src"];

    for path in fallback_paths {
        include_dirs.push(normalize_include_dir(PathBuf::from(path)));
        include_dirs.push(PathBuf::from(path));
    }

    include_dirs.sort();
    include_dirs.dedup();
    let mut found_include = false;
    for dir in include_dirs {
        if dir.exists() {
            build.include(&dir);
            found_include = true;
        }
    }

    if !found_include {
        panic!(
            "freeradius headers not found. Set FREERADIUS_INCLUDE_DIR or install freeradius-devel headers "
        );
    }

    build.compile("rlm_kanidm_freeradius");
}

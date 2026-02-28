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
    println!("cargo:rerun-if-env-changed=FREERADIUS_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FREERADIUS_MODULE");

    if env::var_os("CARGO_FEATURE_FREERADIUS_MODULE").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));

    let mut include_dirs: Vec<PathBuf> = Vec::new();

    if let Ok(include_dir) = env::var("FREERADIUS_INCLUDE_DIR") {
        include_dirs.push(normalize_include_dir(PathBuf::from(&include_dir)));
        include_dirs.push(PathBuf::from(include_dir));
    }

    for path in [
        "/tmp/freeradius-src/freeradius-server-release/src",
        "/tmp/freeradius-src/freeradius-server-release/src/include",
    ] {
        include_dirs.push(normalize_include_dir(PathBuf::from(path)));
        include_dirs.push(PathBuf::from(path));
    }

    include_dirs.sort();
    include_dirs.dedup();

    let found_include_dirs: Vec<PathBuf> = include_dirs
        .iter()
        .filter(|dir| dir.exists())
        .cloned()
        .collect();

    if found_include_dirs.is_empty() {
        let searched = include_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        panic!(
            "freeradius headers not found. Set FREERADIUS_INCLUDE_DIR. searched include roots: {searched}"
        );
    }

    let wrapper_header = std::fs::read_to_string("freeradius_wrapper.h")
        .expect("failed to read freewradius_wrapper.h");

    let mut builder = bindgen::Builder::default()
        .header_contents("freeradius_wrapper.h", &wrapper_header)
        .allowlist_type("rlm_kanidm_conf_parser_t")
        .allowlist_type("rlm_kanidm_module_t")
        .allowlist_type("rlm_kanidm_.*_t")
        .allowlist_type("rlm_rcode_t")
        .allowlist_type("REQUEST")
        .allowlist_type("RADIUS_PACKET")
        .allowlist_type("VALUE_PAIR")
        .allowlist_type("DICT_ATTR")
        .allowlist_type("vp_cursor_t")
        .allowlist_function("fr_cursor_init")
        .allowlist_function("fr_cursor_next")
        .allowlist_function("vp_prints_value")
        .allowlist_function("fr_pair_make")
        .allowlist_var("RLM_KANIDM_.*")
        .allowlist_item("RLM_MODULE_.*")
        .derive_debug(false)
        .derive_default(false)
        .derive_partialeq(false)
        .layout_tests(false);

    for dir in &found_include_dirs {
        builder = builder
            .clang_arg("-idirafter")
            .clang_arg(dir.to_string_lossy());
    }

    let bindings = builder.generate().unwrap_or_else(|err| {
        let searched = found_include_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        panic!("unable to generate FreeRADIUS bindings: {err}. include roots: {searched}")
    });

    bindings
        .write_to_file(out_dir.join("freeradius_bindings.rs"))
        .expect("unable to write freeradius bindings");
}

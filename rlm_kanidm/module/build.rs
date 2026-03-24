use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=FREERADIUS_INCLUDE_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));

    let wrapper_header = include_str!("./include/freeradius_wrapper.h");

    let builder = bindgen::Builder::default()
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

    let bindings = builder.generate().expect("Failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("freeradius_bindings.rs"))
        .expect("unable to write freeradius bindings");
}

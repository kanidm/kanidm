use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EXTERN_FREERADIUS_MODULE");

    if env::var_os("CARGO_FEATURE_EXTERN_FREERADIUS_MODULE").is_none() {
        return;
    }

    cc::Build::new()
        .file("src/rlm_kanidm.c")
        .link_lib_modifier("+whole-archive")
        .compile("rlm_kanidm");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));

    let wrapper_header = include_str!("./include/freeradius_wrapper.h");

    let builder = bindgen::Builder::default()
        .header_contents("freeradius_wrapper.h", wrapper_header)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .allowlist_type("conf_part")
        .allowlist_item("fr_cursor_init")
        .allowlist_item("fr_cursor_next")
        .allowlist_item("fr_pair_make")
        .allowlist_item("fr_token_t")
        .allowlist_type("module_t")
        .allowlist_type("packetmethod")
        .allowlist_item("rlm_components")
        .allowlist_item("rlm_rcodes")
        .allowlist_item("rlm_rcode_t")
        .allowlist_item("vp_cursor_t")
        .allowlist_item("vp_prints_value")
        .allowlist_type("CONF_PARSER")
        .allowlist_item("DICT_ATTR")
        .allowlist_item("PW_TYPE")
        .allowlist_item("RADIUS_PACKET")
        .allowlist_item("REQUEST")
        .allowlist_item("RLM_MODULE_.*")
        .allowlist_item("RLM_TYPE_THREAD_SAFE")
        .allowlist_item("RLM_MODULE_INIT")
        .allowlist_item("VALUE_PAIR")
        .derive_debug(false)
        .derive_default(false)
        .derive_partialeq(false)
        .layout_tests(false);

    let bindings = builder.generate().expect("Failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("freeradius_bindings.rs"))
        .expect("unable to write freeradius bindings");
}

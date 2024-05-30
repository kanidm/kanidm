use std::env;

fn main() {
    // Allows openssl3 as a cfg flag
    println!("cargo::rustc-check-cfg=cfg(openssl3)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_VERSION_NUMBER");

    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x3000_0000 {
            println!("cargo:rustc-cfg=openssl3");
        }
    }
}

// include!("src/lib/audit_loglevel.rs");

use std::env;

fn main() {
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x3000_0000 {
            println!("cargo:rustc-cfg=openssl3");
        }
    }
}

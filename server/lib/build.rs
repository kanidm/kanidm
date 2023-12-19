// include!("src/lib/audit_loglevel.rs");

use hashbrown::HashMap;

use std::env;

fn main() {
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x3000_0000 {
            println!("cargo:rustc-cfg=openssl3");
        }
    }

    profiles::apply_profile();

    // check we don't have duplicate UUIDs
    let uuid_filename = format!(
        "{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "src/constants/uuids.rs"
    );
    let constants = std::fs::read_to_string(uuid_filename).unwrap();
    let mut uuids: HashMap<String, usize> = HashMap::new();
    let uuid_finder = regex::Regex::new(r#"uuid!\(\"([^\"]+)"#).unwrap();

    for line in constants.lines() {
        if let Some(caps) = uuid_finder.captures(line) {
            let uuid = caps.get(1).unwrap().as_str();
            let count = uuids.entry(uuid.to_string()).or_insert(0);
            *count += 1;
        }
    }
    for (uuid, count) in uuids {
        if count > 1 {
            panic!("duplicate UUID: {}", uuid);
        }
    }
}

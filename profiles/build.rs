fn main() {
    println!("cargo:rerun-if-changed=RUST_MSRV");
    println!("cargo:rerun-if-changed=developer.toml");
    println!("cargo:rerun-if-changed=container_generic.toml");
    println!("cargo:rerun-if-changed=container_x86_64_v3.toml");
    println!("cargo:rerun-if-changed=release_suse_generic.toml");
    println!("cargo:rerun-if-changed=release_suse_x86_64.toml");
}

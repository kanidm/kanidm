fn main() {
    profiles::apply_profile();
    println!("cargo:rerun-if-changed=build.rs");
}

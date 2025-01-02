
fn main() {
    println!("cargo::rerun-if-changed=src/freebsd_nss.c");

    cc::Build::new().file("src/freebsd_nss.c")
        .static_flag(true)
        .link_lib_modifier("+whole-archive")
        .compile("freebsd_nss");

    // println!("cargo::rustc-link-arg=-Wl,-Bstatic");
    // println!("cargo::rustc-link-arg=-Wl,--no-as-needed");
    // println!("cargo::rustc-link-arg=-Wl,--whole-archive-a");
    // println!("cargo::rustc-link-arg=-lfreebsd_nss");
}


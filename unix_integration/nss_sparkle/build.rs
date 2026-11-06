fn main() {
    #[cfg(target_os = "freebsd")]
    {
        println!("cargo::rerun-if-changed=src/freebsd_nss.c");

        cc::Build::new()
            .file("src/freebsd_nss.c")
            // No longer required
            // .static_flag(true)
            .link_lib_modifier("+whole-archive")
            .compile("freebsd_nss");
    }
}

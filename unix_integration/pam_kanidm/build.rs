fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // ignore errors here since older versions of pam do not ship the pkg-config `pam.pc` file.
    // Not setting anything here will fall back on just blindly linking with `-lpam`,
    // which will work on environments with libpam.so, but no pkg-config file.
    let _ = pkg_config::Config::new()
        .atleast_version("1.3.0")
        .probe("pam");
}

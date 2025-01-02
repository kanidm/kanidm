#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]


#[cfg(target_os = "freebsd")]
/// BSD nss is quite different to that of linux (rather, glibc). As a result of this
/// FreeBSD kindly offers us wrappers to allow compatability of the two. But to
/// do this we need a .c file to include the macros and export tables, as well as
/// handling the variadic args (which rust doesn't).
///
/// The issue is that even though we link our static archive, rust won't export any
/// of the symbols from it *unless* a rust source file actually consumes at least
/// one of them. This means we can't just link to our .a and have it do the work,
/// we need to wrap and expose this shim function to convince rust to actually
/// link to the archive
///
/// https://github.com/rust-lang/rust/issues/78827
mod bsd_nss_compat {
    use std::ffi::c_void;

    extern "C" {
        pub fn _nss_module_register(a: *mut c_void, b: *mut c_void, c: *mut c_void);
    }

    #[no_mangle]
    pub extern "C" fn nss_module_register(a: *mut c_void, b: *mut c_void, c: *mut c_void) {
        unsafe { _nss_module_register(a, b, c) }
    }
}


#[cfg(target_family = "unix")]
#[macro_use]
extern crate libnss;

#[cfg(target_family = "unix")]
mod hooks;

#[cfg(target_family = "unix")]
pub(crate) mod core;

#[cfg(test)]
mod tests;

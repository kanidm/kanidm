/// Macro to generate the `extern "C"` entrypoint bindings needed by PAM
///
/// You can call `pam_hooks!(SomeType);` for any type that implements `PamHooks`
///
/// ## Examples:
///
/// Here is full example of a PAM module that would authenticate and authorize everybody:
///
/// ```
/// #[macro_use] extern crate pam;
///
/// use pam::module::{PamHooks, PamHandle};
/// use pam::constants::{PamResultCode, PamFlag};
/// use std::ffi::CStr;
///
/// # fn main() {}
/// struct MyPamModule;
/// pam_hooks!(MyPamModule);
///
/// impl PamHooks for MyPamModule {
///    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
///        println!("Everybody is authenticated!");
///        PamResultCode::PAM_SUCCESS
///    }
///
///    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
///        println!("Everybody is authorized!");
///        PamResultCode::PAM_SUCCESS
///    }
/// }
/// ```
#[macro_export]
macro_rules! pam_hooks {
    ($ident:ident) => {
        pub use self::pam_hooks_scope::*;
        mod pam_hooks_scope {
            use std::ffi::CStr;
            use std::os::raw::{c_char, c_int};
            use $crate::pam::constants::{PamFlag, PamResultCode};
            use $crate::pam::module::{PamHandle, PamHooks};

            fn extract_argv<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a CStr> {
                (0..argc)
                    .map(|o| unsafe { CStr::from_ptr(*argv.offset(o as isize) as *const c_char) })
                    .collect()
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_acct_mgmt(
                pamh: &PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::acct_mgmt(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_authenticate(
                pamh: &PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_authenticate(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_chauthtok(
                pamh: &PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_chauthtok(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_close_session(
                pamh: &PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_close_session(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_open_session(
                pamh: &PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_open_session(pamh, args, flags)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_setcred(
                pamh: &PamHandle,
                flags: PamFlag,
                argc: c_int,
                argv: *const *const c_char,
            ) -> PamResultCode {
                let args = extract_argv(argc, argv);
                super::$ident::sm_setcred(pamh, args, flags)
            }
        }
    };
}

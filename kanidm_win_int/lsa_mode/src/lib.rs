use windows::Win32::{Foundation::*, Security::Authentication::Identity::*};
use authentication_pkg as auth_pkg;

mod authentication_pkg;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn SpLsaModeInitialize(
    lsaversion: u32,
    packageversion: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    unsafe {
        let mut tbl_ref = *(*pptables);
        tbl_ref.InitializePackage = Some(auth_pkg::ap_initialise_pkg);
        tbl_ref.LogonUserA = Some(auth_pkg::ap_logon_user);
        tbl_ref.CallPackage = Some(auth_pkg::ap_call_package);
        tbl_ref.LogonTerminated = Some(auth_pkg::ap_logon_terminated);
        tbl_ref.CallPackageUntrusted = Some(auth_pkg::ap_call_package_untrusted);
        tbl_ref.CallPackagePassthrough = Some(auth_pkg::ap_call_package_passthrough);
        tbl_ref.LogonUserExA = Some(auth_pkg::ap_logon_user_ex);
        tbl_ref.LogonUserEx2 = Some(auth_pkg::ap_logon_user_ex2);
    }

    NTSTATUS(0x0)
}

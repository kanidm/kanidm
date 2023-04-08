use crate::{auth_pkg::GLOBAL_AUTHENTICATION_PACKAGE, security_pkg::GLOBAL_SECURITY_PACKAGE};
use std::ffi::c_void;
use windows::Win32::{
    Foundation::{LUID, NTSTATUS, STATUS_UNSUCCESSFUL, UNICODE_STRING},
    Security::Authentication::Identity::{
        LSA_DISPATCH_TABLE, LSA_SECPKG_FUNCTION_TABLE, LSA_TOKEN_INFORMATION_TYPE,
        SECPKG_PARAMETERS, SECPKG_PRIMARY_CRED, SECPKG_SUPPLEMENTAL_CRED, SECURITY_LOGON_TYPE,
    },
    System::Kernel::STRING,
};

pub extern "system" fn ap_initialise_pkg(
    package_id: u32,
    dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    out_pkg_name: *mut *mut STRING,
) -> NTSTATUS {
    unsafe {
        GLOBAL_AUTHENTICATION_PACKAGE.initialise_package(package_id, dispatch_table, out_pkg_name)
    }
}

pub extern "system" fn ap_logon_user(
    client_request: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    authentication_info: *const c_void,
    client_authentication_base: *const c_void,
    authentication_info_base: u32,
    out_profile_buffer: *mut *mut c_void,
    out_profile_buffer_length: *mut u32,
    out_logon_id: *mut LUID,
    out_substatus: *mut i32,
    out_token_info_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    out_token_info: *mut *mut c_void,
    out_account_name: *mut *mut UNICODE_STRING,
    out_authenticating_authority: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        GLOBAL_AUTHENTICATION_PACKAGE.logon_user(
            client_request,
            logon_type,
            authentication_info,
            client_authentication_base,
            authentication_info_base,
            out_profile_buffer,
            out_profile_buffer_length,
            out_logon_id,
            out_substatus,
            out_token_info_type,
            out_token_info,
            out_account_name,
            out_authenticating_authority,
        )
    }
}

// Security Packages
pub extern "system" fn sp_initialise(
    package_id: usize,
    params: *const SECPKG_PARAMETERS,
    func_table: *const LSA_SECPKG_FUNCTION_TABLE,
) -> NTSTATUS {
    unsafe { GLOBAL_SECURITY_PACKAGE.initialise_package(package_id, params, func_table) }
}

pub extern "system" fn sp_shutdown() -> NTSTATUS {
    unsafe { GLOBAL_SECURITY_PACKAGE.shutdown_package() }
}

// For some reason, this is one of the few functions which must have a specific name
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn SpAcceptCredentials(
    logon_type: SECURITY_LOGON_TYPE,
    account_name: *const UNICODE_STRING,
    primary_creds: *const SECPKG_PRIMARY_CRED,
    supplementary_creds: *const SECPKG_SUPPLEMENTAL_CRED,
) -> NTSTATUS {
    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };

    rt.block_on(unsafe {
        GLOBAL_SECURITY_PACKAGE.accept_credentials(
            logon_type,
            account_name,
            primary_creds,
            supplementary_creds,
        )
    })
}

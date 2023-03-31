use std::ffi::c_void;
use windows::Win32::{Security::Authentication::Identity::{LSA_DISPATCH_TABLE, SECURITY_LOGON_TYPE, LSA_TOKEN_INFORMATION_TYPE}, Foundation::{NTSTATUS, LUID, UNICODE_STRING}, System::Kernel::STRING};

use crate::auth_pkg::GLOBAL_AUTHENTICATION_PACKAGE;

pub extern "system" fn ap_initialise_pkg(
    package_id: u32,
    dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    out_pkg_name: *mut *mut STRING,
) -> NTSTATUS {
    unsafe {
        GLOBAL_AUTHENTICATION_PACKAGE.initialise_package(
            package_id,
            dispatch_table,
            out_pkg_name,
        )
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

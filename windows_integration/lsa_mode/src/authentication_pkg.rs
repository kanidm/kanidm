use std::ffi::c_void;
use windows::core::PSTR;
use windows::Win32::{Foundation::*, Security::Authentication::Identity::*, System::Kernel::*};

struct AuthPkg {
    /// The authentication package id assigned by the local security authority
    api: Option<u32>,
    /// The lsa dispatch table
    ldt: Option<*const LSA_DISPATCH_TABLE>,
}

static mut AUTH_PKG: AuthPkg = AuthPkg {
    api: None,
    ldt: None,
};

pub extern "system" fn ap_initialise_pkg(
    auth_pkg_id: u32,
    lsa_dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    auth_pkg_name: *mut *mut STRING,
) -> NTSTATUS {
    let mut pkg_name = env!("CARGO_PKG_NAME").to_owned();
    let pkg_name_len = match u16::try_from(pkg_name.len()) {
        Ok(len) => len,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };

    let ap_name = STRING {
        Length: pkg_name_len,
        MaximumLength: pkg_name_len,
        Buffer: PSTR(pkg_name.as_mut_ptr()),
    };

    unsafe {
        **auth_pkg_name = ap_name;
        AUTH_PKG.ldt = Some(lsa_dispatch_table);
        AUTH_PKG.api = Some(auth_pkg_id);
    }

    STATUS_SUCCESS
}

pub extern "system" fn ap_logon_user(
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    auth_info: *const c_void,
    client_auth_base: *const c_void,
    auth_info_length: u32,
    profile_buffer: *mut *mut c_void,
    profile_buffer_length: *mut u32,
    logon_id: *mut LUID,
    substatus: *mut i32,
    token_info_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    token_info: *mut *mut c_void,
    account_name: *mut *mut UNICODE_STRING,
    auth_authority: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_call_package(
    client_req: *const *const c_void,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_length: u32,
    protocol_return_buffer: *mut *mut c_void,
    return_buffer_length: *mut u32,
    protcol_status: *mut i32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_call_package_untrusted(
    client_req: *const *const c_void,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_length: u32,
    protocol_return_buffer: *mut *mut c_void,
    return_buffer_length: *mut u32,
    protcol_status: *mut i32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_call_package_passthrough(
    client_req: *const *const c_void,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_length: u32,
    protocol_return_buffer: *mut *mut c_void,
    return_buffer_length: *mut u32,
    protcol_status: *mut i32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_logon_terminated(logon_id: *const LUID) {}

pub extern "system" fn ap_logon_user_ex(
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    auth_info: *const c_void,
    client_auth_base: *const c_void,
    auth_info_length: u32,
    profile_buffer: *mut *mut c_void,
    profile_buffer_length: *mut u32,
    logon_id: *mut LUID,
    substatus: *mut i32,
    token_info_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    token_info: *mut *mut c_void,
    account_name: *mut *mut UNICODE_STRING,
    auth_authority: *mut *mut UNICODE_STRING,
    machinename: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_logon_user_ex2(
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_size: u32,
    profile_buffer: *mut *mut c_void,
    profile_buffer_size: *mut u32,
    logon_id: *mut LUID,
    substatus: *mut i32,
    token_info_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    token_info: *mut *mut c_void,
    account_name: *mut *mut UNICODE_STRING,
    auth_authority: *mut *mut UNICODE_STRING,
    machinename: *mut *mut UNICODE_STRING,
    primary_credentials: *mut SECPKG_PRIMARY_CRED,
    supplemental_credentials: *mut *mut SECPKG_SUPPLEMENTAL_CRED_ARRAY,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_post_logon_user(
    post_logon_user_info: *const SECPKG_POST_LOGON_USER_INFO,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_logon_user_ex3(
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_size: u32,
    surrogate_logon: *mut SECPKG_SURROGATE_LOGON,
    profile_buffer: *mut *mut c_void,
    profile_buffer_size: *mut u32,
    logon_id: *mut LUID,
    substatus: *mut i32,
    token_info_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    token_info: *mut *mut c_void,
    account_name: *mut *mut UNICODE_STRING,
    auth_authority: *mut *mut UNICODE_STRING,
    machine_name: *mut *mut UNICODE_STRING,
    primary_creds: *mut SECPKG_PRIMARY_CRED,
    supplemtal_creds: *mut *mut SECPKG_SUPPLEMENTAL_CRED_ARRAY,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_pre_logon_user_surrogate(
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_size: u32,
    surrogate_logon: *mut SECPKG_SURROGATE_LOGON,
    substatus: *mut i32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn ap_post_logon_user_surrogate(
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_size: u32,
    surrogate_logon: *const SECPKG_SURROGATE_LOGON,
    profile_buffer: *const c_void,
    profile_buffer_size: u32,
    logon_id: *const LUID,
    status: NTSTATUS,
    substatus: NTSTATUS,
    token_info_type: LSA_TOKEN_INFORMATION_TYPE,
    token_info: *const c_void,
    account_name: *const UNICODE_STRING,
    auth_authority: *const UNICODE_STRING,
    machine_name: *const UNICODE_STRING,
    primary_creds: *const SECPKG_PRIMARY_CRED,
    supplemental_creds: *const SECPKG_SUPPLEMENTAL_CRED_ARRAY,
) -> NTSTATUS {
    STATUS_SUCCESS
}

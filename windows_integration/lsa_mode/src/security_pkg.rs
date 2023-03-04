use std::ffi::c_void;

use windows::{
    core::GUID,
    Win32::{Foundation::*, Security::Authentication::Identity::*},
};

pub extern "system" fn sp_initialise(
    pkg_id: usize,
    parameters: *const SECPKG_PARAMETERS,
    func_table: *const LSA_SECPKG_FUNCTION_TABLE,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_shutdown() -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_info(pkg_info: *mut SecPkgInfoA) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_accept_credentials(
    logon_type: SECURITY_LOGON_TYPE,
    account_name: *const UNICODE_STRING,
    primary_creds: *const SECPKG_PRIMARY_CRED,
    supplemental_creds: *const SECPKG_SUPPLEMENTAL_CRED,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_acquire_credentials_handle(
    principal_name: *const UNICODE_STRING,
    creds_use_flags: u32,
    logon_id: *const LUID,
    auth_data: *const c_void,
    get_key_func: *const c_void,
    get_key_arg: *const c_void,
    cred_handle: *mut usize,
    expire_time: *mut i64,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_query_credentials_attributes(
    cred_handle: usize,
    cred_attribute: u32,
    buffer: *mut c_void,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_free_credentials_handle(cred_handle: usize) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_save_credentials(cred_size: usize, creds: *const SecBuffer) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_credentials(cred_handle: usize, creds: *mut SecBuffer) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_delete_credentials(
    cred_handle: usize,
    creds: *const SecBuffer,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_init_lsa_mode_context(
    cred_handle: usize,
    ctx_handle: usize,
    target_handle: *const UNICODE_STRING,
    ctx_reqs: u32,
    target_data_rep: u32,
    input_buffers: *const SecBufferDesc,
    new_ctx_handle: *mut usize,
    output_buffers: *mut SecBufferDesc,
    ctx_attributes: *mut u32,
    expire_time: *mut i64,
    mapped_ctx: *mut BOOLEAN,
    ctx_data: *mut SecBuffer,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_accept_lsa_mode_context(
    cred_handle: usize,
    ctx_handle: usize,
    input_buffer: *const SecBufferDesc,
    ctx_reqs: u32,
    target_data_rep: u32,
    new_ctx_handle: *mut usize,
    output_buffers: *mut SecBufferDesc,
    ctx_attributes: *mut u32,
    expire_time: *mut i64,
    mapped_ctx: *mut BOOLEAN,
    ctx_data: *mut SecBuffer,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_delete_ctx(ctx_handle: usize) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_apply_control_token(
    ctx_handle: usize,
    control_token: *const SecBufferDesc,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_user_info(
    logon_id: *const LUID,
    flags: u32,
    user_data: *mut *mut SECURITY_USER_DATA,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_extended_info(
    class: SECPKG_EXTENDED_INFORMATION_CLASS,
    pp_info: *mut *mut SECPKG_EXTENDED_INFORMATION,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_query_ctx_attributes(
    ctx_handle: usize,
    ctx_attribute: u32,
    buffer: *mut c_void,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_add_creds(
    cred_handle: usize,
    principal_name: *const UNICODE_STRING,
    pkg: *const UNICODE_STRING,
    cred_use_flags: u32,
    auth_data: *const c_void,
    get_key_func: *const c_void,
    get_key_arg: *const c_void,
    expire_time: *mut i64,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_set_extended_info(
    class: SECPKG_EXTENDED_INFORMATION_CLASS,
    info: *const SECPKG_EXTENDED_INFORMATION,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_set_ctx_attributes(
    ctx_handle: usize,
    ctx_attribute: u32,
    buffer: *const c_void,
    buffer_size: u32,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_change_account_password(
    domain_name: *const UNICODE_STRING,
    account_name: *const UNICODE_STRING,
    old_password: *const UNICODE_STRING,
    new_password: *const UNICODE_STRING,
    impersonating: BOOLEAN,
    output: *mut SecBufferDesc,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_query_metadata(
    cred_handle: usize,
    target_name: *const UNICODE_STRING,
    ctx_reqs: u32,
    metadata_length: *mut u32,
    metadata: *mut *mut u8,
    ctx_handle: *mut usize,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_exchange_metadata(
    cred_handle: usize,
    target_name: *const UNICODE_STRING,
    ctx_requirements: u32,
    metadata_length: u32,
    metadata: *const u8,
    ctx_handle: *mut usize,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_cred_ui_ctx(
    ctx_handle: usize,
    cred_type: *const GUID,
    flat_cred_ui_ctx_length: *mut u32,
    flat_cred_ui_ctx: *mut *mut u8,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_update_creds(
    ctx_handle: usize,
    cred_type: *const GUID,
    flat_cred_ui_ctx_length: u32,
    flat_cred_ui_ctx: *const u8,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_validate_target_info(
    client_req: *const *const c_void,
    protocol_submit_buffer: *const c_void,
    client_buffer_base: *const c_void,
    submit_buffer_length: u32,
    target_info: *const SECPKG_TARGETINFO,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_remote_cred_guard_logon_buffer(
    cred_handle: usize,
    ctx_handle: usize,
    target_name: *const UNICODE_STRING,
    redirected_logon_handle: *mut HANDLE,
    callback: *mut PLSA_REDIRECTED_LOGON_CALLBACK,
    cleanup_callback: *mut PLSA_REDIRECTED_LOGON_CLEANUP_CALLBACK,
    logon_buffer_size: *mut u32,
    logon_buffer: *mut *mut c_void,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_remote_cred_guard_supplemental_creds(
    cred_handle: usize,
    target_name: *const UNICODE_STRING,
    redirected_logon_handle: *mut HANDLE,
    callback: *mut PLSA_REDIRECTED_LOGON_CALLBACK,
    cleanup_callback: *mut PLSA_REDIRECTED_LOGON_CLEANUP_CALLBACK,
    supplemental_cred_size: *mut u32,
    supplemental_cred: *mut *mut c_void,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

pub extern "system" fn sp_get_tbal_supplemental_creds(
    logon_id: LUID,
    supplemental_cred_size: *mut u32,
    supplemental_creds: *mut *mut c_void,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

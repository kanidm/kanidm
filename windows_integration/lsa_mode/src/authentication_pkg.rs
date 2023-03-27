use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use tracing::{error, warn};
use windows::core::PSTR;
use windows::Win32::{Foundation::*, Security::Authentication::Identity::*, System::Kernel::*};

struct AuthPkg {
    /// The authentication package id assigned by the local security authority
    package_id: Option<Arc<u32>>,
    /// The lsa dispatch table
    dispatch_table: Option<Arc<&'static LSA_DISPATCH_TABLE>>,
}

impl AuthPkg {
    pub fn init_pkg(
        self: &mut Self,
        auth_pkg_id: u32,
        lsa_dispatch_table: *const LSA_DISPATCH_TABLE,
        auth_pkg_name: *mut *mut STRING,
    ) -> NTSTATUS {
        // Check if we've already setup a dispatch table
        if self.dispatch_table.is_some() {
            error!("dispatch table already exists");

            // Error out as these already existing imply that this function has already been called
            // Hence the Authentication package is trying to be initialised more than once
            return STATUS_UNSUCCESSFUL;
        }

        // Because const ptrs has issues with static mut, we just want a ref instead
        let lsa_dt = unsafe {
            match lsa_dispatch_table.as_ref() {
                Some(dt) => dt,
                None => {
                    error!("failed to get lsa dispatch table as ref");
                    return STATUS_UNSUCCESSFUL;
                }
            }
        };

        let am_lsa_dt = Arc::new(lsa_dt);
        self.dispatch_table = Some(am_lsa_dt);

        if self.package_id.is_some() {
            error!("package id already exists");
            return STATUS_UNSUCCESSFUL;
        }

        self.package_id = Some(Arc::new(auth_pkg_id));

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
        }

        STATUS_SUCCESS
    }

    pub fn logon_user(
        self: &mut Self,
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
}

static mut AUTH_PKG: AuthPkg = AuthPkg {
    package_id: None,
    dispatch_table: None,
};

pub extern "system" fn ap_initialise_pkg(
    auth_pkg_id: u32,
    lsa_dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    auth_pkg_name: *mut *mut STRING,
) -> NTSTATUS {
    unsafe { AUTH_PKG.init_pkg(auth_pkg_id, lsa_dispatch_table, auth_pkg_name) }
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
    unsafe {
        AUTH_PKG.logon_user(
            client_req,
            logon_type,
            auth_info,
            client_auth_base,
            auth_info_length,
            profile_buffer,
            profile_buffer_length,
            logon_id,
            substatus,
            token_info_type,
            token_info,
            account_name,
            auth_authority,
        )
    }
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

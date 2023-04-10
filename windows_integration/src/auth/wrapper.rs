use once_cell::sync::Lazy;
use std::{ffi::c_void, time::SystemTime};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::*,
        Security::{Authentication::Identity::*, Credentials::STATUS_LOGON_FAILURE},
        System::Kernel::*,
    },
};

use super::package::{AuthError, AuthPackage, AuthInfo};

static mut AUTH_PACKAGE: Lazy<AuthPackage> = Lazy::new(|| AuthPackage::new());

#[tokio::main]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApInitializePackage(
    package_id: u32,
    dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    out_package_name: *mut *mut STRING,
) -> NTSTATUS {
    let tbl_ref = unsafe {
        match dispatch_table.as_ref() {
            Some(dt) => dt,
            None => return STATUS_UNSUCCESSFUL,
        }
    };
    let tbl = tbl_ref.to_owned();

    let init_result = unsafe { AUTH_PACKAGE.init(package_id, tbl).await };

    if let Ok(mut package_name) = init_result {
        let package_name_win = STRING {
            Buffer: PSTR(package_name.as_mut_ptr()),
            Length: package_name.len() as u16,
            MaximumLength: package_name.len() as u16,
        };

        unsafe {
            *(*out_package_name) = package_name_win;
        }
    } else {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS_SUCCESS
}

#[tokio::main]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApLogonUser(
    _: *const *const c_void,
    _: SECURITY_LOGON_TYPE,
    auth_info: *const c_void,     // Cast to own Auth Info type
    _: *const c_void, // Pointer to auth_info
    _: u32,
    out_prof_buf: *mut *mut c_void, // Cast to own profile buffer
    out_prof_buf_len: *mut u32,
    out_logon_id: *mut LUID,
    out_substatus: *mut i32,
    out_token_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    out_token: *mut *mut c_void,
    out_account: *mut *mut UNICODE_STRING,
    out_authority: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
    let logon_creds_ptr: *const AuthInfo = auth_info.cast();
    let logon_creds = unsafe {
        match logon_creds_ptr.as_ref() {
            Some(lc) => lc,
            None => return STATUS_UNSUCCESSFUL,
        }
    };
    let username = unsafe {
        match logon_creds.username.Buffer.to_string() {
            Ok(uname) => uname,
            Err(_) => return STATUS_UNSUCCESSFUL,
        }
    };
    let password = unsafe {
        match logon_creds.password.Buffer.to_string() {
            Ok(pw) => pw,
            Err(_) => return STATUS_UNSUCCESSFUL,
        }
    };

    let profile_buffer = unsafe {
        match AUTH_PACKAGE.logon_user(username, password).await {
            Ok(tok) => tok,
            Err(e) => {
                return match e {
                    AuthError::AuthenticationFailed => STATUS_LOGON_FAILURE,
                    _ => STATUS_UNSUCCESSFUL,
                }
            }
        }
    };

    STATUS_SUCCESS
}

#[tokio::main]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApCallPackage(
    client_req: *const *const c_void,
    submit_buf: *const c_void,     // Cast to own Protocol Submit Buffer
    submit_buf_loc: *const c_void, // Pointer to submit_buf
    submit_buf_len: u32,
    out_return_buf: *mut *mut c_void, // Cast to own return buffer
    out_return_buf_len: *mut u32,
    out_status: *mut i32, // NTSTATUS
) -> NTSTATUS {
    STATUS_SUCCESS
}

#[tokio::main]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApLogonTerminated(logon_id: *const LUID) {}

#[tokio::main]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApCallPackageUntrusted(
    client_req: *const *const c_void,
    submit_buf: *const c_void,     // Cast to own Protocol Submit Buffer
    submit_buf_loc: *const c_void, // Pointer to submit_buf
    submit_buf_len: u32,
    out_return_buf: *mut *mut c_void, // Cast to own return buffer
    out_return_buf_len: *mut u32,
    out_status: *mut i32, // NTSTATUS
) -> NTSTATUS {
    STATUS_SUCCESS
}

#[tokio::main]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApCallPackagePassthrough(
    client_req: *const *const c_void,
    submit_buf: *const c_void,     // Cast to own Protocol Submit Buffer
    submit_buf_loc: *const c_void, // Pointer to submit_buf
    submit_buf_len: u32,
    out_return_buf: *mut *mut c_void, // Cast to own return buffer
    out_return_buf_len: *mut u32,
    out_status: *mut i32, // NTSTATUS
) -> NTSTATUS {
    STATUS_SUCCESS
}

use std::ffi::c_void;
use windows::{Win32::{Foundation::*, Security::Authentication::Identity::*, System::Kernel::*}, core::PSTR};

use super::package::AuthPackage;

static mut AUTH_PACKAGE: AuthPackage = AuthPackage {
    package_id: None,
    dispatch_table: None,
    client: None,
};

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
    client_req: *const *const c_void,
    logon_type: SECURITY_LOGON_TYPE,
    auth_info: *const c_void,     // Cast to own Auth Info type
    auth_info_loc: *const c_void, // Pointer to auth_info
    auth_info_len: u32,
    out_prof_buf: *mut *mut c_void, // Cast to own profile buffer
    out_prof_buf_len: *mut u32,
    out_logon_id: *mut LUID,
    out_substatus: *mut i32,
    token_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    token: *mut *mut c_void,
    account: *mut *mut UNICODE_STRING,
    authority: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
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



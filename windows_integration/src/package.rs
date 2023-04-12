use std::ffi::c_void;

use crate::{client::KanidmWindowsClient, PROGRAM_DIR};
use once_cell::sync::Lazy;
use tracing::{event, Level, span};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::*,
        Security::{Authentication::Identity::*, Credentials::STATUS_LOGON_FAILURE},
        System::Kernel::*,
    },
};

pub(crate) static mut KANIDM_WINDOWS_CLIENT: Lazy<Option<KanidmWindowsClient>> = Lazy::new(|| {
    let client = match KanidmWindowsClient::new(&format!("{}/authlib_client.toml", PROGRAM_DIR)) {
        Ok(client) => client,
        Err(e) => {
            event!(Level::ERROR, "Failed to create new KanidmWindowsClient");
            event!(Level::INFO, "KanidmWindowsClientError {:?}", e);

            return None;
        }
    };

    Some(client)
});
static mut AP_DISPATCH_TABLE: Option<LSA_DISPATCH_TABLE> = None;
static mut AP_PACKAGE_ID: u32 = 0;

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApInitializePackage(
    package_id: u32,
    dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    out_package_name: *mut *mut STRING,
) -> NTSTATUS {
	let apips = span!(Level::INFO, "Initialising Kanidm Authentication Package").entered();
    let mut package_name = env!("CARGO_PKG_NAME").to_owned();
    let package_name_win = STRING {
        Buffer: PSTR(package_name.as_mut_ptr()),
        Length: package_name.len() as u16,
        MaximumLength: package_name.len() as u16,
    };
	let dt_ref = match unsafe { dispatch_table.as_ref() } {
		Some(dt) => dt,
		None => {
			event!(Level::ERROR, "Failed to get reference to the LSA Dispatch Table");
			return STATUS_UNSUCCESSFUL;
		},
	};
    unsafe { 
		*(*out_package_name) = package_name_win;
		AP_DISPATCH_TABLE = Some(dt_ref.to_owned());
		AP_PACKAGE_ID = package_id;
	}

	if unsafe { KANIDM_WINDOWS_CLIENT.is_none() } {
		event!(Level::ERROR, "Kanidm Windows Client did not initialise correctly");
		return STATUS_UNSUCCESSFUL;
	}

	apips.exit();
    STATUS_SUCCESS
}

#[tokio::main(flavor = "current_thread")]
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
    STATUS_SUCCESS
}

#[tokio::main(flavor = "current_thread")]
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

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApLogonTerminated(logon_id: *const LUID) {}

#[tokio::main(flavor = "current_thread")]
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

#[tokio::main(flavor = "current_thread")]
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

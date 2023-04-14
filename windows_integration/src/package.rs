use std::{ffi::c_void, mem::size_of, ptr::null_mut};

use crate::{
    client::{KanidmWindowsClient, KanidmWindowsClientError},
    mem::{allocate_mem, MemoryAllocationError},
    structs::{AuthInfo, ProfileBuffer},
    PROGRAM_DIR,
};
use once_cell::sync::Lazy;
use tracing::{event, span, Level};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::*,
        Security::{
            AllocateLocallyUniqueId, Authentication::Identity::*,
            Credentials::STATUS_LOGON_FAILURE, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
        },
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
static mut SP_PACKAGE_ID: usize = 0;
static mut SP_SECPKG_PARAMS: Option<SECPKG_PARAMETERS> = None;
static mut SP_FUNC_TABLE: Option<LSA_SECPKG_FUNCTION_TABLE> = None;

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
            event!(
                Level::ERROR,
                "Failed to get reference to the LSA Dispatch Table"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    let alloc_package_name = match allocate_mem(package_name_win, &dt_ref.AllocateLsaHeap) {
        Ok(ptr) => ptr,
        Err(e) => match e {
            MemoryAllocationError::NoAllocFunc => {
                event!(Level::ERROR, "Missing lsa allocation function");
                return STATUS_UNSUCCESSFUL;
            }
            MemoryAllocationError::AllocFuncFailed => {
                event!(Level::ERROR, "Failed to allocate package name");
                return STATUS_UNSUCCESSFUL;
            }
        },
    };

    unsafe {
        *out_package_name = alloc_package_name;
        AP_DISPATCH_TABLE = Some(dt_ref.to_owned());
        AP_PACKAGE_ID = package_id;
    }

    if unsafe { KANIDM_WINDOWS_CLIENT.is_none() } {
        event!(
            Level::ERROR,
            "Kanidm Windows Client did not initialise correctly"
        );
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
    auth_info_ptr: *const c_void, // Cast to own Auth Info type
    _: *const c_void,             // Pointer to auth_info
    _: u32,
    out_prof_buf: *mut *mut c_void, // Cast to own profile buffer
    out_prof_buf_len: *mut u32,
    out_logon_id: *mut LUID,
    out_substatus: *mut i32,
    out_token_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    out_token: *mut *mut c_void,
    out_account: *mut *mut UNICODE_STRING,
    _: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
    let auth_info: *const AuthInfo = auth_info_ptr.cast();

    unsafe {
        *(*out_account) = (*auth_info).username; // out_account must always be set regardless of return value
    }

    let username = match unsafe { (*auth_info).username.Buffer.to_string() } {
        Ok(uname) => uname,
        Err(_) => {
            event!(Level::ERROR, "Failed to convert username to string");
            return STATUS_UNSUCCESSFUL;
        }
    };
    let password = match unsafe { (*auth_info).password.Buffer.to_string() } {
        Ok(pw) => pw,
        Err(_) => {
            event!(Level::ERROR, "Failed to convert password to string");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let client = unsafe { KANIDM_WINDOWS_CLIENT.as_ref().unwrap() };
    let token = match client.logon_user(&username, &password).await {
        Ok(token) => token,
        Err(_) => {
            event!(Level::INFO, "{} failed authentication", username);
            return STATUS_LOGON_FAILURE;
        }
    };

    let profile_buff = ProfileBuffer { token: token };
    let out_prof_buf_conv: *mut *mut ProfileBuffer = out_prof_buf.cast();
    let logon_id: *mut LUID = null_mut();

    unsafe {
        match AllocateLocallyUniqueId(logon_id) {
            BOOL(0) => (), // Success
            _ => {
                event!(Level::ERROR, "Failed to allocate logon id for {}", username);
            }
        }
    }

    let out_token_conv: *mut *mut LSA_TOKEN_INFORMATION_NULL = out_token.cast();
    let mut token_groups = TOKEN_GROUPS {
        GroupCount: 0,
        Groups: [SID_AND_ATTRIBUTES::default(); 1],
    };
    let token_info = LSA_TOKEN_INFORMATION_NULL {
        ExpirationTime: i64::MAX,
        Groups: &mut token_groups as *mut TOKEN_GROUPS,
    };

    let dispatch_table = unsafe { AP_DISPATCH_TABLE.as_ref().unwrap() };
    let alloc_profile_buf = match allocate_mem(profile_buff, &dispatch_table.AllocateLsaHeap) {
        Ok(pb) => pb,
        Err(e) => match e {
            MemoryAllocationError::NoAllocFunc => {
                event!(Level::ERROR, "Missing lsa allocation function");
                return STATUS_UNSUCCESSFUL;
            }
            MemoryAllocationError::AllocFuncFailed => {
                event!(Level::ERROR, "Failed to allocate profile buffer");
                return STATUS_UNSUCCESSFUL;
            }
        },
    };
    let alloc_token_info = match allocate_mem(token_info, &dispatch_table.AllocateLsaHeap) {
        Ok(ti) => ti,
        Err(e) => match e {
            MemoryAllocationError::NoAllocFunc => {
                event!(Level::ERROR, "Missing lsa allocation function");
                return STATUS_UNSUCCESSFUL;
            }
            MemoryAllocationError::AllocFuncFailed => {
                event!(Level::ERROR, "Failed to allocate token info");
                return STATUS_UNSUCCESSFUL;
            }
        },
    };

    unsafe {
        *out_prof_buf_conv = alloc_profile_buf;
        *out_prof_buf_len = size_of::<ProfileBuffer>() as u32;
        *out_logon_id = logon_id.read();
        *out_substatus = 0;
        *out_token_type = LsaTokenInformationNull;
        *out_token_conv = alloc_token_info;
    }

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

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn SpInitialize(
    package_id: usize,
    params_ptr: *const SECPKG_PARAMETERS,
    func_table_ptr: *const LSA_SECPKG_FUNCTION_TABLE,
) -> NTSTATUS {
    let params = match unsafe { params_ptr.as_ref() } {
        Some(params) => params.to_owned(),
        None => {
            event!(Level::ERROR, "Failed to convert params to reference");
            return STATUS_UNSUCCESSFUL;
        }
    };
    let func_table = match unsafe { func_table_ptr.as_ref() } {
        Some(func_table) => func_table.to_owned(),
        None => {
            event!(
                Level::ERROR,
                "Failed to convert function table to reference"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    unsafe {
        SP_PACKAGE_ID = package_id;
        SP_SECPKG_PARAMS = Some(params);
        SP_FUNC_TABLE = Some(func_table);
    }

    /*
    ! Until the client has most of the functions implemented,
    ! we return unsuccessful so the LSA unloads the client and doesn't call it
    */
    // STATUS_SUCCESSFUL
    STATUS_UNSUCCESSFUL
}

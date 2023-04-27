use std::{ffi::c_void, ptr::null_mut, time::{SystemTime, UNIX_EPOCH}, mem::size_of};

use crate::{
    client::{KanidmWindowsClient, KanidmWindowsClientError},
    mem::{allocate_mem_client, allocate_mem_lsa, MemoryAllocationError},
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
            Credentials::STATUS_LOGON_FAILURE, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_USER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES , TOKEN_OWNER, TOKEN_DEFAULT_DACL, ACL, TOKEN_USER_CLAIMS, TOKEN_DEVICE_CLAIMS, TOKEN_PRIVILEGES_ATTRIBUTES,
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

    let alloc_package_name = match allocate_mem_lsa(package_name_win, &dt_ref.AllocateLsaHeap) {
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

// TODO: Figure out structs which currently use ::default()
#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApLogonUser(
    client_req: *const *const c_void,
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
    let auth_info: &AuthInfo = unsafe { (*auth_info_ptr.cast::<*const AuthInfo>()).as_ref().unwrap() };

    unsafe {
        *(*out_account) = auth_info.username;
    }

    let dispatch_table = match unsafe { AP_DISPATCH_TABLE.as_ref() } {
        Some(dt) => dt,
        None => {
            span!(Level::ERROR, "Failed to get the LSA's dispatch table as a reference");
            return STATUS_UNSUCCESSFUL;
        }
    };

    // * Set mandatory fields
    {
        /* 
            Since the dispatch table exists, we re-set the return account which is allocated to the LSA's memory space
         */
        let username_ptr = match allocate_mem_lsa(auth_info.username, &dispatch_table.AllocateLsaHeap) {
            Ok(ptr) => ptr,
            Err(_) => {
                span!(Level::ERROR, "Failed to allocate username to LSA heap");
                return STATUS_UNSUCCESSFUL;
            },
        };

        unsafe {
            *out_account = username_ptr;
        }
    }

    // * Get username & password as rust strings
    let username = match unsafe { auth_info.username.Buffer.to_string() } {
        Ok(un) => un,
        Err(_) => {
            event!(Level::ERROR, "Failed to convert username to string");
            return STATUS_UNSUCCESSFUL;
        }
    };
    
    let password = match unsafe { auth_info.password.Buffer.to_string() } {
        Ok(pw) => pw,
        Err(_) => {
            event!(Level::ERROR, "Failed to convert password to string");
            return STATUS_UNSUCCESSFUL;
        }
    };

    // * Get token from kanidm server
    let client = unsafe { KANIDM_WINDOWS_CLIENT.as_ref().unwrap() };
    let token = match client.logon_user(&username, &password).await {
        Ok(token) => token,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };

    // * Prepare & return profile buffer
    let profile_buffer = ProfileBuffer {
        token: token,
    };
    let profile_buffer_ptr = match allocate_mem_client(profile_buffer, &dispatch_table.AllocateClientBuffer, client_req) {
        Ok(ptr) => ptr,
        Err(_) => {
            span!(Level::ERROR, "Failed to allocate the profile buffer to the client's memory space");
            return STATUS_UNSUCCESSFUL;
        },
    };
    
    {
        let return_ptr = out_prof_buf.cast::<*mut ProfileBuffer>();

        unsafe {
            *out_prof_buf_len = size_of::<ProfileBuffer>() as u32;
            *return_ptr = profile_buffer_ptr;
        }
    }

    // * Generate LUID
    let luid_ptr = null_mut::<LUID>();

    match unsafe { AllocateLocallyUniqueId(luid_ptr) } {
        BOOL(0) => {
            event!(Level::ERROR, "Failed to allocate unique id");
            return STATUS_UNSUCCESSFUL;
        },
        _ => (),
    };

    unsafe {
        *out_logon_id = *luid_ptr;
    }

    // * Prepare & return token
    // Set expiry time
    let current_time = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_secs() as i64,
        Err(_) => {
            event!(Level::ERROR, "Failed to get current unix timestamp");
            return STATUS_UNSUCCESSFUL;
        }
    };
    let expiry_time = current_time + (18 * 60 * 60);

    // Set user & group token
    let user_token = TOKEN_USER {
        User: SID_AND_ATTRIBUTES::default(),
    };
    let group_token = TOKEN_GROUPS {
        GroupCount: 0,
        Groups: [SID_AND_ATTRIBUTES::default(); 1],
    };
    let primary_group_token = TOKEN_PRIMARY_GROUP {
        PrimaryGroup: PSID::default(),
    };

    let group_token_ptr = null_mut::<TOKEN_GROUPS>();

    unsafe {
        *group_token_ptr = group_token;
    }

    // Set privileges token
    let luid_attributes = LUID_AND_ATTRIBUTES {
        Luid: unsafe { *luid_ptr },
        Attributes: TOKEN_PRIVILEGES_ATTRIBUTES::default(),
    };
    let privileges_token = TOKEN_PRIVILEGES {
        PrivilegeCount: 0,
        Privileges: [luid_attributes; 1],
    };
    let privileges_token_ptr = null_mut::<TOKEN_PRIVILEGES>();

    unsafe {
        *privileges_token_ptr = privileges_token;
    }

    // Set owner token
    let owner_token = TOKEN_OWNER {
        Owner: PSID::default(),
    };

    // Set default dacl token
    let acl = ACL {
        AclRevision: 1,
        Sbz1: 0,
        AclSize: 0,
        AceCount: 0,
        Sbz2: 0,
    };
    let acl_ptr = null_mut::<ACL>();

    unsafe {
        *acl_ptr = acl;
    }

    let dacl_token = TOKEN_DEFAULT_DACL {
        DefaultDacl: acl_ptr,
    };

    // Set user & device claims token
    let user_claims_token = TOKEN_USER_CLAIMS {
        UserClaims: null_mut(),
    };
    let device_claims_token = TOKEN_DEVICE_CLAIMS {
        DeviceClaims: null_mut(),
    };

    // Set device groups token
    let device_groups_token = TOKEN_GROUPS {
        GroupCount: 0,
        Groups: [SID_AND_ATTRIBUTES::default(); 1],
    };
    let device_groups_token_ptr = null_mut::<TOKEN_GROUPS>();

    unsafe {
        *device_groups_token_ptr = device_groups_token;
    }

    // Create logon token
    let logon_token = LSA_TOKEN_INFORMATION_V3 {
        ExpirationTime: expiry_time,
        User: user_token,
        Groups: group_token_ptr,
        PrimaryGroup: primary_group_token,
        Privileges: privileges_token_ptr,
        Owner: owner_token,
        DefaultDacl: dacl_token,
        UserClaims: user_claims_token,
        DeviceClaims: device_claims_token,
        DeviceGroups: device_groups_token_ptr,
    };

    // Set logon token
    let logon_token_ptr = match allocate_mem_lsa(logon_token, &dispatch_table.AllocateLsaHeap) {
        Ok(ptr) => ptr,
        Err(_) => {
            event!(Level::ERROR, "Failed to allocate logon token");
            return STATUS_UNSUCCESSFUL;
        }
    };

    {
        let return_ptr = out_token.cast::<*mut LSA_TOKEN_INFORMATION_V3>();

        unsafe {
            *out_token_type = LsaTokenInformationV3;
            *return_ptr = logon_token_ptr;
        }
    }

    // Set return status
    unsafe {
        *out_substatus = 0;
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

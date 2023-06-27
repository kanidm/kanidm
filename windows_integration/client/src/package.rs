use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UnixUserToken;
use kanidm_windows::{AuthPkgError, AuthPkgRequest, AuthPkgResponse, AuthenticateAccountResponse};
use once_cell::sync::Lazy;
use tracing::{event, span, Level};

use windows::core::PSTR;
use windows::Win32::Foundation::{
    BOOL, LUID, NTSTATUS, PSID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};
use windows::Win32::Security::Authentication::Identity::{
    LsaTokenInformationV3, LSA_DISPATCH_TABLE, LSA_SECPKG_FUNCTION_TABLE,
    LSA_TOKEN_INFORMATION_TYPE, LSA_TOKEN_INFORMATION_V3, SECPKG_PARAMETERS, SECURITY_LOGON_TYPE,
};
use windows::Win32::Security::{
    AllocateLocallyUniqueId, ACL, LUID_AND_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_DEFAULT_DACL,
    TOKEN_DEVICE_CLAIMS, TOKEN_GROUPS, TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES,
    TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_USER, TOKEN_USER_CLAIMS,
};
use windows::Win32::System::Kernel::STRING;

use crate::mem::{allocate_mem_client, allocate_mem_lsa, MemoryAllocationError};
use crate::structs::{AuthInfo, LogonId, ProfileBuffer};
use crate::PROGRAM_DIR;

pub(crate) static mut KANIDM_CLIENT: Lazy<KanidmClient> = Lazy::new(|| {
    let config_path = format!("{}/authlib_client.toml", PROGRAM_DIR);

    KanidmClientBuilder::new()
        .read_options_from_optional_config(config_path)
        .unwrap_or_else(|_| std::process::exit(1))
        .build()
        .unwrap_or_else(|_| std::process::exit(1))
});
static mut AP_DISPATCH_TABLE: Option<LSA_DISPATCH_TABLE> = None;
static mut AP_PACKAGE_ID: u32 = 0;
static mut AP_LOGON_IDS: Lazy<HashMap<LogonId, UnixUserToken>> = Lazy::new(HashMap::new);
static mut SP_PACKAGE_ID: usize = 0;
static mut SP_SECPKG_PARAMS: Option<SECPKG_PARAMETERS> = None;
static mut SP_FUNC_TABLE: Option<LSA_SECPKG_FUNCTION_TABLE> = None;

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn ApInitialisePackage(
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

    let alloc_package_name =
        match unsafe { allocate_mem_lsa(package_name_win, &dt_ref.AllocateLsaHeap) } {
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

    apips.exit();
    STATUS_SUCCESS
}

// TODO: Figure out structs which currently use ::default()
#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn ApLogonUser(
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
    let auth_info: &AuthInfo =
        unsafe { (*auth_info_ptr.cast::<*const AuthInfo>()).as_ref().unwrap() };

    unsafe {
        *(*out_account) = auth_info.username;
    }

    let dispatch_table = match unsafe { AP_DISPATCH_TABLE.as_ref() } {
        Some(dt) => dt,
        None => {
            span!(
                Level::ERROR,
                "Failed to get the LSA's dispatch table as a reference"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    // * Set mandatory fields
    {
        // Since the dispatch table exists, we re-set the return account which is allocated to the LSA's memory space
        let username_ptr = match unsafe {
            allocate_mem_lsa(auth_info.username, &dispatch_table.AllocateLsaHeap)
        } {
            Ok(ptr) => ptr,
            Err(_) => {
                span!(Level::ERROR, "Failed to allocate username to LSA heap");
                return STATUS_UNSUCCESSFUL;
            }
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

    let client = match Lazy::get(unsafe { &KANIDM_CLIENT }) {
        Some(client) => client,
        None => {
            event!(Level::ERROR, "Failed to get a reference to kanidm client");
            return STATUS_UNSUCCESSFUL;
        }
    };

    // * Get token from kanidm server
    let token = match client
        .idm_account_unix_cred_verify(&username, &password)
        .await
    {
        Ok(token) => match token {
            Some(token) => token,
            None => {
                event!(Level::ERROR, "Kanidm Client did not return a token");
                return STATUS_UNSUCCESSFUL;
            }
        },
        Err(_) => return STATUS_UNSUCCESSFUL,
    };

    // * Prepare & return profile buffer
    let profile_buffer = ProfileBuffer {
        token: token.clone(),
    };
    let profile_buffer_ptr = match unsafe {
        allocate_mem_client(
            profile_buffer,
            &dispatch_table.AllocateClientBuffer,
            client_req,
        )
    } {
        Ok(ptr) => ptr,
        Err(_) => {
            span!(
                Level::ERROR,
                "Failed to allocate the profile buffer to the client's memory space"
            );
            return STATUS_UNSUCCESSFUL;
        }
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

    if let BOOL(0) = unsafe { AllocateLocallyUniqueId(luid_ptr) } {
        event!(Level::ERROR, "Failed to allocate unique id");
        return STATUS_UNSUCCESSFUL;
    }

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
    let logon_token_ptr =
        match unsafe { allocate_mem_lsa(logon_token, &dispatch_table.AllocateLsaHeap) } {
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

        // Save the Logon ID
        let logon_id = LogonId::from(*luid_ptr);
        AP_LOGON_IDS.insert(logon_id, token);
    }

    STATUS_SUCCESS
}

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn ApCallPackage(
    client_req: *const *const c_void,
    submit_buf: *const c_void, // Cast to own Protocol Submit Buffer
    _: *const c_void,          // Pointer to submit_buf
    _: u32,
    out_return_buf: *mut *mut c_void, // Cast to own return buffer
    out_return_buf_len: *mut u32,
    out_status: *mut i32, // NTSTATUS
) -> NTSTATUS {
    let dispatch_table = match unsafe { AP_DISPATCH_TABLE.as_ref() } {
        Some(dt) => dt,
        None => {
            span!(
                Level::ERROR,
                "Failed to get the LSA's dispatch table as a reference"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    let client = match Lazy::get(unsafe { &KANIDM_CLIENT }) {
        Some(client) => client,
        None => {
            event!(Level::ERROR, "Failed to get a reference to kanidm client");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let request_ptr = submit_buf.cast::<AuthPkgRequest>();
    let request = match unsafe { request_ptr.as_ref() } {
        Some(req) => req,
        None => return STATUS_UNSUCCESSFUL,
    };

    let response = match request {
        AuthPkgRequest::AuthenticateAccount(auth_request) => {
            let logon_result = client
                .idm_account_unix_cred_verify(&auth_request.id, &auth_request.password)
                .await;

            AuthPkgResponse::AuthenticateAccount(match logon_result {
                Ok(token_opt) => match token_opt {
                    Some(token) => AuthenticateAccountResponse {
                        status: Ok(()),
                        token: Some(token),
                    },
                    None => AuthenticateAccountResponse {
                        status: Err(AuthPkgError::AuthenticationFailed),
                        token: None,
                    },
                },
                Err(_) => AuthenticateAccountResponse {
                    status: Err(AuthPkgError::AuthenticationFailed),
                    token: None,
                },
            })
        }
    };
    let response_ptr = match unsafe {
        allocate_mem_client(response, &dispatch_table.AllocateClientBuffer, client_req)
    } {
        Ok(ptr) => ptr,
        Err(_) => {
            span!(Level::ERROR, "Failed to allocate response");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let out_return_buf_ptr = out_return_buf.cast::<*mut AuthPkgResponse>();

    unsafe {
        *out_return_buf_ptr = response_ptr;
        *out_return_buf_len = size_of::<AuthPkgResponse>() as u32;
        *out_status = 0i32;
    }

    STATUS_SUCCESS
}

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn ApLogonTerminated(luid: *const LUID) {
    unsafe {
        let logon_id = LogonId::from(*luid);
        AP_LOGON_IDS.remove(&logon_id);
    }
}

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn SpInitialise(
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

    STATUS_SUCCESS
}

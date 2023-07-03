use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};

use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UnixUserToken;
use kanidm_windows::{
    AuthPkgError, AuthPkgRequest, AuthPkgResponse, AuthenticateAccountResponse,
    AuthenticationInformation,
};
use once_cell::sync::Lazy;
use tracing::{event, span, Level};

use windows::core::{PSTR, PWSTR};
use windows::Win32::Foundation::{
    BOOL, BOOLEAN, FALSE, HANDLE, LUID, NTSTATUS, PSID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, TRUE,
    UNICODE_STRING,
};
use windows::Win32::Security::Authentication::Identity::{
    LsaTokenInformationV3, SecNameFlat, LSA_DISPATCH_TABLE, LSA_SECPKG_FUNCTION_TABLE,
    LSA_TOKEN_INFORMATION_TYPE, LSA_TOKEN_INFORMATION_V1, LSA_TOKEN_INFORMATION_V3,
    SECPKG_NAME_TYPE, SECPKG_PARAMETERS, SECURITY_LOGON_TYPE, LsaTokenInformationV2,
};
use windows::Win32::Security::Credentials::{STATUS_LOGON_FAILURE, STATUS_NO_SUCH_USER};
use windows::Win32::Security::{
    AllocateLocallyUniqueId, GetTokenInformation, SecurityImpersonation, TokenUser, ACL,
    LUID_AND_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_DEFAULT_DACL, TOKEN_DEVICE_CLAIMS, TOKEN_GROUPS,
    TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_SOURCE,
    TOKEN_USER, TOKEN_USER_CLAIMS, TokenGroups, TokenPrimaryGroup, TokenPrivileges, TokenOwner, TokenDefaultDacl,
};
use windows::Win32::System::Kernel::STRING;
use windows::Win32::System::SystemInformation::GetLocalTime;

use crate::convert::{rust_to_unicode, unicode_to_rust};
use crate::mem::{allocate_mem_client, allocate_mem_lsa, MemoryAllocationError};
use crate::structs::LogonId;
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

fn error_then_return(msg: &str) -> NTSTATUS {
    event!(Level::ERROR, msg);
    STATUS_UNSUCCESSFUL
}

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

    let alloc_lsa_heap = match &dt_ref.AllocateLsaHeap {
        Some(func) => func,
        None => {
            event!(Level::ERROR, "AP: Failed to get LSA heap allocation function");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let alloc_package_name =
        match unsafe { allocate_mem_lsa(package_name_win, alloc_lsa_heap) } {
            Ok(ptr) => ptr,
            Err(e) => match e {
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

    STATUS_SUCCESS
}

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn ApLogonUser(
    _client_req: *const *const c_void,
    _security_logon_type: SECURITY_LOGON_TYPE,
    authentication_information: *const c_void,
    _client_authentication_base: *const c_void,
    _authentication_information_length: u32,
    _profile_buffer: *mut *mut c_void,
    _profile_buffer_length: *mut u32,
    mut logon_id: *mut LUID,
    mut substatus: *mut i32,
    mut token_information_type: *mut LSA_TOKEN_INFORMATION_TYPE,
    token_information: *mut *mut c_void,
    account_name: *mut *mut UNICODE_STRING,
    authenticating_authority: *mut *mut UNICODE_STRING,
) -> NTSTATUS {
    event!(Level::INFO, "AP: Starting logon process for unknown user");

    // * Get needed global vars
    let secpkg_dispatch_table = match unsafe { SP_FUNC_TABLE } {
        Some(tbl) => tbl,
        None => {
            return error_then_return("AP: Failed to obtain reference to the LSA dispatch table")
        }
    };
    let kanidm_client = match Lazy::get(unsafe { &KANIDM_CLIENT }) {
        Some(client) => client,
        None => {
            return error_then_return("AP: Failed to obtain reference to the kanidm client");
        }
    };

    let authentication_information = authentication_information.cast::<AuthenticationInformation>();

    if authentication_information.is_null() {
        return error_then_return("AP: Authentication information provided is null");
    }

    let provided_credentials = unsafe { authentication_information.read() };
    let username = match unicode_to_rust(provided_credentials.username) {
        Some(str) => str,
        None => return STATUS_UNSUCCESSFUL,
    };
    let password = match unicode_to_rust(provided_credentials.password) {
        Some(str) => str,
        None => return STATUS_UNSUCCESSFUL,
    };

    let upn_name = format!("{}@{}", username, kanidm_client.get_url());
    let upn_name_win = rust_to_unicode(upn_name);
    let upn_name_win_ptr = &upn_name_win as *const UNICODE_STRING;

    match kanidm_client
        .idm_account_unix_cred_verify(&*username, &*password)
        .await
    {
        Ok(_) => event!(Level::INFO, "AP: Successfully logged on {}", username),
        Err(ClientError::AuthenticationFailed) => {
            event!(Level::INFO, "AP: {} failed credential check", username);
            return STATUS_LOGON_FAILURE;
        }
        Err(_) => {
            let msg = format!("AP: Failed to authenticate user {}", username);
            return error_then_return(&*msg);
        }
    };

    // Logon ID
    let logon_id_new: *mut LUID = null_mut();

    if let TRUE = unsafe { AllocateLocallyUniqueId(logon_id_new) } {
        return error_then_return("AP: Failed to allocate logon id");
    }

    // Expiry Time
    let current_time = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => time,
        Err(_) => return error_then_return("AP: Failed to get the current time"),
    };
    let expiry_time = current_time.as_secs() as i64 + (24 * 60 * 60);

    // User Handle
    let open_sam_user = match secpkg_dispatch_table.OpenSamUser {
        Some(func) => func,
        None => return error_then_return("AP: Failed to get reference to LSA OpenSamUser"),
    };

    let user_handle_ptr: *mut *mut c_void = null_mut();
    let sam_return_value = unsafe {
        open_sam_user(
            upn_name_win_ptr,
            SecNameFlat,
            null(),
            BOOLEAN(0),
            0,
            user_handle_ptr,
        )
    };

    let user_handle = unsafe { user_handle_ptr.cast::<*mut HANDLE>().read().read() };

    if sam_return_value == STATUS_NO_SUCH_USER {
        // TODO: Create new user
    }

    // Token Information
    let user_token: *mut c_void = null_mut();
    let groups_token: *mut c_void = null_mut();
    let primary_group_token: *mut c_void = null_mut();
    let privileges_token: *mut c_void = null_mut();
    let owner_token: *mut c_void = null_mut();
    let default_dacl_token: *mut c_void = null_mut();

    if unsafe { GetTokenInformation(user_handle, TokenUser, Some(user_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get user token");
    }

    if unsafe { GetTokenInformation(user_handle, TokenGroups, Some(groups_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get groups token");
    }

    if unsafe { GetTokenInformation(user_handle, TokenPrimaryGroup, Some(primary_group_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get primary group token");
    }

    if unsafe { GetTokenInformation(user_handle, TokenPrivileges, Some(privileges_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get privileges token");
    }

    if unsafe { GetTokenInformation(user_handle, TokenOwner, Some(owner_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get owner token");
    }

    if unsafe { GetTokenInformation(user_handle, TokenDefaultDacl, Some(default_dacl_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get default DACL token");
    }

    let token_information_v2 = unsafe { LSA_TOKEN_INFORMATION_V1 {
        ExpirationTime: expiry_time,
        User: user_token.cast::<TOKEN_USER>().read(),
        Groups: groups_token.cast::<TOKEN_GROUPS>(),
        PrimaryGroup: primary_group_token.cast::<TOKEN_PRIMARY_GROUP>().read(),
        Privileges: privileges_token.cast::<TOKEN_PRIVILEGES>(),
        Owner: owner_token.cast::<TOKEN_OWNER>().read(),
        DefaultDacl: default_dacl_token.cast::<TOKEN_DEFAULT_DACL>().read(),
    }};

    // Allocate to LSA heap space
    let alloc_lsa_heap = match &secpkg_dispatch_table.AllocateLsaHeap {
        Some(func) => func,
        None => {
            event!(Level::ERROR, "AP: Failed to get LSA heap allocation function");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let substatus_lsa = match unsafe { allocate_mem_lsa(0i32, alloc_lsa_heap) } {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate substatus"),
    };
    let token_information_type_lsa = match unsafe { allocate_mem_lsa(LsaTokenInformationV2, alloc_lsa_heap)} {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate token information type"),
    };
    let token_information_lsa = match unsafe { allocate_mem_lsa(token_information_v2, alloc_lsa_heap) } {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate the token information"),
    };
    let authenticating_authority_lsa = match unsafe { allocate_mem_lsa(rust_to_unicode(kanidm_client.get_url().to_string()), alloc_lsa_heap)} {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate the authenticating authority"),
    };
    let account_name_lsa = match unsafe { allocate_mem_lsa(provided_credentials.username, alloc_lsa_heap)} {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate the authenticating authority"),
    };

    unsafe {
        let token_information = token_information.cast::<*mut LSA_TOKEN_INFORMATION_V1>();

        substatus = substatus_lsa;
        token_information_type = token_information_type_lsa;
        *token_information = token_information_lsa;
        *account_name = account_name_lsa;
        *authenticating_authority = authenticating_authority_lsa;
        logon_id = logon_id_new;
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

    let alloc_client_heap = match &dispatch_table.AllocateClientBuffer {
        Some(func) => func,
        None => {
            event!(Level::ERROR, "AP: Failed to get LSA heap allocation function");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let response_ptr = match unsafe {
        allocate_mem_client(response, alloc_client_heap, client_req)
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
        AP_LOGON_IDS.remove(&(*luid).into());
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

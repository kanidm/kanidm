use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::time::SystemTime;

use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UnixUserToken;
use kanidm_windows::{
    AuthPkgError, AuthPkgRequest, AuthPkgResponse, AuthenticateAccountResponse,
    AuthenticationInformation,
};
use once_cell::sync::Lazy;
use tracing::{event, span, Level};

use windows::core::PSTR;
use windows::Win32::Foundation::{
    BOOLEAN, FALSE, HANDLE, LUID, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, TRUE,
    UNICODE_STRING,
};
use windows::Win32::Security::Authentication::Identity::{
    LsaTokenInformationV2, SecNameFlat, LSA_DISPATCH_TABLE, LSA_SECPKG_FUNCTION_TABLE,
    LSA_TOKEN_INFORMATION_TYPE, LSA_TOKEN_INFORMATION_V1, SECPKG_PARAMETERS, SECURITY_LOGON_TYPE,
};
use windows::Win32::Security::Credentials::{STATUS_LOGON_FAILURE, STATUS_NO_SUCH_USER};
use windows::Win32::Security::{
    AllocateLocallyUniqueId, GetTokenInformation, TokenDefaultDacl, TokenGroups, TokenOwner,
    TokenPrimaryGroup, TokenPrivileges, TokenUser, TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_OWNER,
    TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_USER,
};
use windows::Win32::System::Kernel::STRING;

use crate::convert::{rust_to_unicode, unicode_to_rust};
use crate::mem::{allocate_mem_client, allocate_mem_lsa, MemoryAllocationError};
use crate::structs::LogonId;
use crate::PROGRAM_DIR;

pub(crate) static mut KANIDM_CLIENT: Lazy<KanidmClient> = Lazy::new(|| {
    let program_dir = match unsafe { &PROGRAM_DIR } {
        Some(dir) => dir,
        None => std::process::exit(1),
    };

    let config_path = format!("{}/authlib_client.toml", program_dir);

    KanidmClientBuilder::new()
        .read_options_from_optional_config(config_path)
        .unwrap_or_else(|_| std::process::exit(1))
        .build()
        .unwrap_or_else(|_| std::process::exit(1))
});
static mut AP_DISPATCH_TABLE: Option<LSA_DISPATCH_TABLE> = None;
static mut AP_PACKAGE_ID: u32 = 0;
pub(crate) static mut AP_LOGON_IDS: Lazy<HashMap<LogonId, UnixUserToken>> = Lazy::new(HashMap::new);
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
    event!(Level::DEBUG, "Getting reference to dispatch table from parameter");
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

    event!(Level::DEBUG, "Getting reference to the heap allocation function for the LSA");
    let alloc_lsa_heap = match &dt_ref.AllocateLsaHeap {
        Some(func) => func,
        None => {
            event!(
                Level::ERROR,
                "AP: Failed to get LSA heap allocation function"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    event!(Level::DEBUG, "Beginning creation of package name to return to LSA");
    let mut package_name = env!("CARGO_PKG_NAME").to_owned();
    let package_name_win = STRING {
        Buffer: PSTR(package_name.as_mut_ptr()),
        Length: package_name.len() as u16,
        MaximumLength: package_name.len() as u16,
    };
    let alloc_package_name = match unsafe { allocate_mem_lsa(package_name_win, alloc_lsa_heap) } {
        Ok(ptr) => ptr,
        Err(e) => match e {
            MemoryAllocationError::AllocFuncFailed => {
                event!(Level::ERROR, "Failed to allocate package name");
                return STATUS_UNSUCCESSFUL;
            }
        },
    };
    event!(Level::DEBUG, "Finished creation of package name");

    event!(Level::DEBUG, "Returning package name to LSA and setting the dispatch table and package id as global variables");
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
    event!(Level::DEBUG, "Getting reference to the security package function table");
    let secpkg_dispatch_table = match unsafe { SP_FUNC_TABLE } {
        Some(tbl) => tbl,
        None => {
            return error_then_return("AP: Failed to obtain reference to the LSA dispatch table")
        }
    };

    event!(Level::DEBUG, "Getting reference to the kanidm client");
    let kanidm_client = match Lazy::get(unsafe { &KANIDM_CLIENT }) {
        Some(client) => client,
        None => {
            return error_then_return("AP: Failed to obtain reference to the kanidm client");
        }
    };

    event!(Level::DEBUG, "Casting and checking for null in the provided authentication information");
    let authentication_information = authentication_information.cast::<AuthenticationInformation>();

    if authentication_information.is_null() {
        return error_then_return("AP: Authentication information provided is null");
    }

    event!(Level::DEBUG, "Reading authentication information for username and password");
    let provided_credentials = unsafe { authentication_information.read() };
    let username = match unicode_to_rust(provided_credentials.username) {
        Some(str) => str,
        None => return STATUS_UNSUCCESSFUL,
    };
    let password = match unicode_to_rust(provided_credentials.password) {
        Some(str) => str,
        None => return STATUS_UNSUCCESSFUL,
    };

    event!(Level::DEBUG, "Converting username into user principal name style");
    let upn_name = format!("{}@{}", username, kanidm_client.get_url());
    let upn_name_win = rust_to_unicode(upn_name);
    let upn_name_win_ptr = &upn_name_win as *const UNICODE_STRING;

    event!(Level::DEBUG, "Beginning verification of account credentials");
    match kanidm_client
        .idm_account_unix_cred_verify(&username, &password)
        .await
    {
        Ok(_) => event!(Level::INFO, "AP: Successfully logged on {}", username),
        Err(ClientError::AuthenticationFailed) => {
            event!(Level::INFO, "AP: {} failed credential check", username);
            return STATUS_LOGON_FAILURE;
        }
        Err(_) => {
            let msg = format!("AP: Failed to authenticate user {}", username);
            return error_then_return(&msg);
        }
    };
    event!(Level::DEBUG, "Successfully verified account credentials");

    // Logon ID
    event!(Level::DEBUG, "Beginning allocation of locally unique login identification");
    let logon_id_new: *mut LUID = null_mut();

    if let TRUE = unsafe { AllocateLocallyUniqueId(logon_id_new) } {
        return error_then_return("AP: Failed to allocate logon id");
    }
    event!(Level::DEBUG, "Successfully allocated login identification");

    // Expiry Time
    event!(Level::DEBUG, "Beginning creation of token information for the client");
    event!(Level::DEBUG, "Creating expiry time of the token information");
    let current_time = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(time) => time,
        Err(_) => return error_then_return("AP: Failed to get the current time"),
    };
    let expiry_time = current_time.as_secs() as i64 + (24 * 60 * 60);

    // User Handle
    event!(Level::DEBUG, "Getting reference to OpenSamUser from the LSA's dispatch table");
    let open_sam_user = match secpkg_dispatch_table.OpenSamUser {
        Some(func) => func,
        None => return error_then_return("AP: Failed to get reference to LSA OpenSamUser"),
    };

    event!(Level::DEBUG, "Getting user handle from provided authentication information");
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
    event!(Level::DEBUG, "Beginning to get information needed for the token information");
    let user_token: *mut c_void = null_mut();
    let groups_token: *mut c_void = null_mut();
    let primary_group_token: *mut c_void = null_mut();
    let privileges_token: *mut c_void = null_mut();
    let owner_token: *mut c_void = null_mut();
    let default_dacl_token: *mut c_void = null_mut();

    event!(Level::DEBUG, "Getting the user token for {}", username);
    if unsafe { GetTokenInformation(user_handle, TokenUser, Some(user_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get user token");
    }

    event!(Level::DEBUG, "Getting the groups token for {}", username);
    if unsafe { GetTokenInformation(user_handle, TokenGroups, Some(groups_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get groups token");
    }

    event!(Level::DEBUG, "Getting the primary group token for {}", username);
    if unsafe {
        GetTokenInformation(
            user_handle,
            TokenPrimaryGroup,
            Some(primary_group_token),
            0,
            null_mut(),
        )
    } == FALSE
    {
        return error_then_return("AP: Failed to get primary group token");
    }

    event!(Level::DEBUG, "Getting the privileges token for {}", username);
    if unsafe {
        GetTokenInformation(
            user_handle,
            TokenPrivileges,
            Some(privileges_token),
            0,
            null_mut(),
        )
    } == FALSE
    {
        return error_then_return("AP: Failed to get privileges token");
    }

    event!(Level::DEBUG, "Getting the owner token for {}", username);
    if unsafe { GetTokenInformation(user_handle, TokenOwner, Some(owner_token), 0, null_mut()) }
        == FALSE
    {
        return error_then_return("AP: Failed to get owner token");
    }

    event!(Level::DEBUG, "Getting the default discretionary access control list token for {}", username);
    if unsafe {
        GetTokenInformation(
            user_handle,
            TokenDefaultDacl,
            Some(default_dacl_token),
            0,
            null_mut(),
        )
    } == FALSE
    {
        return error_then_return("AP: Failed to get default DACL token");
    }
    event!(Level::DEBUG, "Finished getting information for the token information");

    event!(Level::DEBUG, "Creating token information for {}", username);
    let token_information_v2 = unsafe {
        LSA_TOKEN_INFORMATION_V1 {
            ExpirationTime: expiry_time,
            User: user_token.cast::<TOKEN_USER>().read(),
            Groups: groups_token.cast::<TOKEN_GROUPS>(),
            PrimaryGroup: primary_group_token.cast::<TOKEN_PRIMARY_GROUP>().read(),
            Privileges: privileges_token.cast::<TOKEN_PRIVILEGES>(),
            Owner: owner_token.cast::<TOKEN_OWNER>().read(),
            DefaultDacl: default_dacl_token.cast::<TOKEN_DEFAULT_DACL>().read(),
        }
    };

    // Allocate to LSA heap space
    event!(Level::DEBUG, "Getting reference to the heap allocation function for the LSA");
    let alloc_lsa_heap = match &secpkg_dispatch_table.AllocateLsaHeap {
        Some(func) => func,
        None => {
            event!(
                Level::ERROR,
                "AP: Failed to get LSA heap allocation function"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    event!(Level::DEBUG, "Allocating the substatus to the LSA");
    let substatus_lsa = match unsafe { allocate_mem_lsa(0i32, alloc_lsa_heap) } {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate substatus"),
    };

    event!(Level::DEBUG, "Allocating the token information type to the LSA");
    let token_information_type_lsa =
        match unsafe { allocate_mem_lsa(LsaTokenInformationV2, alloc_lsa_heap) } {
            Ok(ptr) => ptr,
            Err(_) => return error_then_return("AP: Failed to allocate token information type"),
        };

    event!(Level::DEBUG, "Allocating the token information to the LSA");
    let token_information_lsa =
        match unsafe { allocate_mem_lsa(token_information_v2, alloc_lsa_heap) } {
            Ok(ptr) => ptr,
            Err(_) => return error_then_return("AP: Failed to allocate the token information"),
        };

    event!(Level::DEBUG, "Allocating the authenticating authority to the LSA");
    let authenticating_authority_lsa = match unsafe {
        allocate_mem_lsa(
            rust_to_unicode(kanidm_client.get_url().to_string()),
            alloc_lsa_heap,
        )
    } {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate the authenticating authority"),
    };

    event!(Level::DEBUG, "Allocating the account name to the LSA");
    let account_name_lsa = match unsafe {
        allocate_mem_lsa(provided_credentials.username, alloc_lsa_heap)
    } {
        Ok(ptr) => ptr,
        Err(_) => return error_then_return("AP: Failed to allocate the authenticating authority"),
    };

    event!(Level::DEBUG, "Assigning return values for the LSA");
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
    event!(Level::DEBUG, "Getting reference to the LSA dispatch table");
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

    event!(Level::DEBUG, "Getting reference to the kanidm client");
    let client = match Lazy::get(unsafe { &KANIDM_CLIENT }) {
        Some(client) => client,
        None => {
            event!(Level::ERROR, "Failed to get a reference to kanidm client");
            return STATUS_UNSUCCESSFUL;
        }
    };

    event!(Level::DEBUG, "Getting reference to the client request");
    let request_ptr = submit_buf.cast::<AuthPkgRequest>();
    let request = match unsafe { request_ptr.as_ref() } {
        Some(req) => req,
        None => return STATUS_UNSUCCESSFUL,
    };

    event!(Level::DEBUG, "Beginning response to the client");
    let response = match request {
        AuthPkgRequest::AuthenticateAccount(auth_request) => {
            event!(Level::DEBUG, "Beginning authentication response for the client");
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

    event!(Level::DEBUG, "Getting reference to the client heap allocation function");
    let alloc_client_heap = match &dispatch_table.AllocateClientBuffer {
        Some(func) => func,
        None => {
            event!(
                Level::ERROR,
                "AP: Failed to get LSA heap allocation function"
            );
            return STATUS_UNSUCCESSFUL;
        }
    };

    event!(Level::DEBUG, "Allocating the response to the client");
    let response_ptr = match unsafe { allocate_mem_client(response, alloc_client_heap, client_req) }
    {
        Ok(ptr) => ptr,
        Err(_) => {
            span!(Level::ERROR, "Failed to allocate response");
            return STATUS_UNSUCCESSFUL;
        }
    };

    event!(Level::DEBUG, "Assigning the return information for the client");
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
    event!(Level::DEBUG, "Removing logon id from the stored ids");
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
    event!(Level::DEBUG, "Getting reference to the security package parameters");
    let params = match unsafe { params_ptr.as_ref() } {
        Some(params) => params.to_owned(),
        None => {
            event!(Level::ERROR, "Failed to convert params to reference");
            return STATUS_UNSUCCESSFUL;
        }
    };

    event!(Level::DEBUG, "Getting reference to the security package function table");
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

    event!(Level::DEBUG, "Assigning parameters to the global state");
    unsafe {
        SP_PACKAGE_ID = package_id;
        SP_SECPKG_PARAMS = Some(params);
        SP_FUNC_TABLE = Some(func_table);
    }

    STATUS_SUCCESS
}

use std::u32;

use authentication_pkg as authpkg;
use security_pkg as secpkg;
use windows::Win32::{Foundation::*, Security::Authentication::Identity::*};

mod authentication_pkg;
mod security_pkg;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn SpLsaModeInitialize(
    _: u32,
    pkg_ver: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    let pptable = SECPKG_FUNCTION_TABLE {
        InitializePackage: Some(authpkg::ap_initialise_pkg),
        LogonUserA: Some(authpkg::ap_logon_user),
        CallPackage: Some(authpkg::ap_call_package),
        LogonTerminated: Some(authpkg::ap_logon_terminated),
        CallPackageUntrusted: Some(authpkg::ap_call_package_untrusted),
        CallPackagePassthrough: Some(authpkg::ap_call_package_passthrough),
        LogonUserExA: Some(authpkg::ap_logon_user_ex),
        LogonUserEx2: Some(authpkg::ap_logon_user_ex2),
        PostLogonUser: Some(authpkg::ap_post_logon_user),
        LogonUserEx3: Some(authpkg::ap_logon_user_ex3),
        PreLogonUserSurrogate: Some(authpkg::ap_pre_logon_user_surrogate),
        PostLogonUserSurrogate: Some(authpkg::ap_post_logon_user_surrogate),

        // Security Package
        Initialize: Some(secpkg::sp_initialise),
        Shutdown: Some(secpkg::sp_shutdown),
        GetInfo: Some(secpkg::sp_get_info),
        AcceptCredentials: Some(secpkg::sp_accept_credentials),
        AcquireCredentialsHandleA: Some(secpkg::sp_acquire_credentials_handle),
        QueryCredentialsAttributesA: Some(secpkg::sp_query_credentials_attributes),
        FreeCredentialsHandle: Some(secpkg::sp_free_credentials_handle),
        SaveCredentials: Some(secpkg::sp_save_credentials),
        GetCredentials: Some(secpkg::sp_get_credentials),
        DeleteCredentials: Some(secpkg::sp_delete_credentials),
        InitLsaModeContext: Some(secpkg::sp_init_lsa_mode_context),
        AcceptLsaModeContext: Some(secpkg::sp_accept_lsa_mode_context),
        DeleteContext: Some(secpkg::sp_delete_ctx),
        ApplyControlToken: Some(secpkg::sp_apply_control_token),
        GetUserInfo: Some(secpkg::sp_get_user_info),
        GetExtendedInformation: Some(secpkg::sp_get_extended_info),
        QueryContextAttributesA: Some(secpkg::sp_query_ctx_attributes),
        AddCredentialsA: Some(secpkg::sp_add_creds),
        SetExtendedInformation: Some(secpkg::sp_set_extended_info),
        SetContextAttributesA: Some(secpkg::sp_set_ctx_attributes),
        ChangeAccountPasswordA: Some(secpkg::sp_change_account_password),
        QueryMetaData: Some(secpkg::sp_query_metadata),
        ExchangeMetaData: Some(secpkg::sp_exchange_metadata),
        GetCredUIContext: Some(secpkg::sp_get_cred_ui_ctx),
        UpdateCredentials: Some(secpkg::sp_update_creds),
        ValidateTargetInfo: Some(secpkg::sp_validate_target_info),
        GetRemoteCredGuardLogonBuffer: Some(secpkg::sp_get_remote_cred_guard_logon_buffer),
        GetRemoteCredGuardSupplementalCreds: Some(
            secpkg::sp_get_remote_cred_guard_supplemental_creds,
        ),
        GetTbalSupplementalCreds: Some(secpkg::sp_get_tbal_supplemental_creds),
        SetCredentialsAttributesA: Some(secpkg::sp_set_cred_attributes),
    };

    unsafe {
        *pkg_ver = 1u32;
        *pctables = 1u32;
        *(*pptables) = pptable;
    }

    STATUS_SUCCESS
}

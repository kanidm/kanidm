use std::u32;

use windows::Win32::{Foundation::*, Security::Authentication::Identity::*};
use authentication_pkg as authpkg;
use security_pkg as secpkg;

mod authentication_pkg;
mod security_pkg;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn SpLsaModeInitialize(
    lsaversion: u32,
    pkg_ver: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    unsafe {
        *pkg_ver = 1u32;
        *pctables = 39u32;

        let mut tbl_ref = *(*pptables);

        // Authentication Package
        tbl_ref.InitializePackage = Some(authpkg::ap_initialise_pkg);
        tbl_ref.LogonUserA = Some(authpkg::ap_logon_user);
        tbl_ref.CallPackage = Some(authpkg::ap_call_package);
        tbl_ref.LogonTerminated = Some(authpkg::ap_logon_terminated);
        tbl_ref.CallPackageUntrusted = Some(authpkg::ap_call_package_untrusted);
        tbl_ref.CallPackagePassthrough = Some(authpkg::ap_call_package_passthrough);
        tbl_ref.LogonUserExA = Some(authpkg::ap_logon_user_ex);
        tbl_ref.LogonUserEx2 = Some(authpkg::ap_logon_user_ex2);
        tbl_ref.PostLogonUser = Some(authpkg::ap_post_logon_user);
        tbl_ref.LogonUserEx3 = Some(authpkg::ap_logon_user_ex3);
        tbl_ref.PreLogonUserSurrogate = Some(authpkg::ap_pre_logon_user_surrogate);
        tbl_ref.PostLogonUserSurrogate = Some(authpkg::ap_post_logon_user_surrogate);

        // Security Package
        tbl_ref.Initialize = Some(secpkg::sp_initialise);
        tbl_ref.Shutdown = Some(secpkg::sp_shutdown);
        tbl_ref.GetInfo = Some(secpkg::sp_get_info);
        tbl_ref.AcceptCredentials = Some(secpkg::sp_accept_credentials);
        tbl_ref.AcquireCredentialsHandleA = Some(secpkg::sp_acquire_credentials_handle);
        tbl_ref.QueryCredentialsAttributesA = Some(secpkg::sp_query_credentials_attributes);
        tbl_ref.FreeCredentialsHandle = Some(secpkg::sp_free_credentials_handle);
        tbl_ref.SaveCredentials = Some(secpkg::sp_save_credentials);
        tbl_ref.GetCredentials = Some(secpkg::sp_get_credentials);
        tbl_ref.DeleteCredentials = Some(secpkg::sp_delete_credentials);
        tbl_ref.InitLsaModeContext = Some(secpkg::sp_init_lsa_mode_context);
        tbl_ref.AcceptLsaModeContext = Some(secpkg::sp_accept_lsa_mode_context);
        tbl_ref.DeleteContext = Some(secpkg::sp_delete_ctx);
        tbl_ref.ApplyControlToken = Some(secpkg::sp_apply_control_token);
        tbl_ref.GetUserInfo = Some(secpkg::sp_get_user_info);
        tbl_ref.GetExtendedInformation = Some(secpkg::sp_get_extended_info);
        tbl_ref.QueryContextAttributesA = Some(secpkg::sp_query_ctx_attributes);
        tbl_ref.AddCredentialsA = Some(secpkg::sp_add_creds);
        tbl_ref.SetExtendedInformation = Some(secpkg::sp_set_extended_info);
        tbl_ref.SetContextAttributesA = Some(secpkg::sp_set_ctx_attributes);
        tbl_ref.ChangeAccountPasswordA = Some(secpkg::sp_change_account_password);
        tbl_ref.QueryMetaData = Some(secpkg::sp_query_metadata);
        tbl_ref.ExchangeMetaData = Some(secpkg::sp_exchange_metadata);
        tbl_ref.GetCredUIContext = Some(secpkg::sp_get_cred_ui_ctx);
        tbl_ref.UpdateCredentials = Some(secpkg::sp_update_creds);
        tbl_ref.ValidateTargetInfo = Some(secpkg::sp_validate_target_info);
        tbl_ref.GetRemoteCredGuardLogonBuffer = Some(secpkg::sp_get_remote_cred_guard_logon_buffer);
        tbl_ref.GetRemoteCredGuardSupplementalCreds = Some(secpkg::sp_get_remote_cred_guard_supplemental_creds);
        tbl_ref.GetTbalSupplementalCreds = Some(secpkg::sp_get_tbal_supplemental_creds);
    }
    NTSTATUS(0x0)
}

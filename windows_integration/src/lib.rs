use tracing::{event, Level};
use windows::Win32::{
    Foundation::{NTSTATUS, STATUS_SUCCESS},
    Security::Authentication::Identity::SECPKG_FUNCTION_TABLE,
};

mod auth_pkg;
mod wrapper_funcs;
mod security_pkg;

/// # Safety
/// This should only ever be called by the windows api, and FFI with C++ is always unsafe
/// So beware of demons I guess :shrug:
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn SpLsaModeInitialize(
    lsa_version: u32,
    pkg_ver: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    event!(Level::INFO, "Initialising kanidm Windows client");
    event!(
        Level::INFO,
        "Local Security Authority Version {}",
        lsa_version
    );
    event!(Level::INFO, "Client Version v{}", env!("CARGO_PKG_VERSION"));

    let package_version_str = format!(
        "{}{}{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH")
    );

    let package_version = match package_version_str.parse::<u32>() {
        Ok(ver) => ver,
        Err(e) => {
            event!(Level::ERROR, "Failed to parse version string as int");
            event!(Level::DEBUG, "ParseIntError {}", e);
            1 // Just return 1 as the version number as we can't determine the correct version
        }
    };

    let function_table = SECPKG_FUNCTION_TABLE {
        InitializePackage: Some(wrapper_funcs::ap_initialise_pkg),
        LogonUserA: Some(wrapper_funcs::ap_logon_user),
        CallPackage: None,
        LogonTerminated: None,
        CallPackageUntrusted: None,
        CallPackagePassthrough: None,
        LogonUserExA: None,
        LogonUserEx2: None,
        Initialize: Some(wrapper_funcs::sp_initialise),
        Shutdown: Some(wrapper_funcs::sp_shutdown),
        GetInfo: None,
        AcceptCredentials: None,
        AcquireCredentialsHandleA: None,
        QueryCredentialsAttributesA: None,
        FreeCredentialsHandle: None,
        SaveCredentials: None,
        GetCredentials: None,
        DeleteCredentials: None,
        InitLsaModeContext: None,
        AcceptLsaModeContext: None,
        DeleteContext: None,
        ApplyControlToken: None,
        GetUserInfo: None,
        GetExtendedInformation: None,
        QueryContextAttributesA: None,
        AddCredentialsA: None,
        SetExtendedInformation: None,
        SetContextAttributesA: None,
        SetCredentialsAttributesA: None,
        ChangeAccountPasswordA: None,
        QueryMetaData: None,
        ExchangeMetaData: None,
        GetCredUIContext: None,
        UpdateCredentials: None,
        ValidateTargetInfo: None,
        PostLogonUser: None,
        GetRemoteCredGuardLogonBuffer: None,
        GetRemoteCredGuardSupplementalCreds: None,
        GetTbalSupplementalCreds: None,
        LogonUserEx3: None,
        PreLogonUserSurrogate: None,
        PostLogonUserSurrogate: None,
        ExtractTargetInfo: None,
    };

    unsafe {
        *pkg_ver = package_version;
        *pctables = 1u32;
        **pptables = function_table;
    }

    STATUS_SUCCESS
}

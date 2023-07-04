#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use once_cell::sync::Lazy;
use tracing::{event, Level};

use windows::Win32::System::Kernel::STRING;
use windows::core::PCSTR;
use windows::Win32::Foundation::{
    ERROR_MORE_DATA, ERROR_SUCCESS, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use windows::Win32::Security::Authentication::Identity::SECPKG_FUNCTION_TABLE;
use windows::Win32::System::Registry::{
    RegGetValueA, HKEY_LOCAL_MACHINE, REG_VALUE_TYPE, RRF_RT_REG_SZ,
};

use crate::convert::win_string_to_rust;
use crate::package::{AP_LOGON_IDS, KANIDM_CLIENT};

pub(crate) mod convert;
pub(crate) mod mem;
pub mod package;
pub(crate) mod structs;

pub(crate) static mut PROGRAM_DIR: Option<String> = None;

pub(crate) const REGISTRY_KEY: &str = "SOFTWARE\\kanidm";
pub(crate) const REGISTRY_KEY_INSTALL_LOCATION: &str = "InstallLocation";

// Naming Scheme for Tracing spans
// The current naming scheme for these consist of the initials of function names followed by an s
// For example: logon_user -> lus

/// If you're looking for the library which contains the protocol definitions then you've found the wrong library.
/// The library you're looking for is `kanidm_windows` not `kanidm_windows_client`
/// # Safety
/// This function should only ever be called by the windows api. This library heavily depends on the win32 api and uses a special allocator provided
/// by the windows local security authority. Depending on this library for anything is unsupported and undefined behaviour. So if you do attempt to use
/// anything from this library, be warned there may be dragons.
#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async unsafe extern "system" fn SpLsaModeInitialize(
    lsa_version: u32,
    pkg_ver: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    let registry_key = PCSTR::from_raw(REGISTRY_KEY.as_ptr());
    let registry_key_value = PCSTR::from_raw(REGISTRY_KEY_INSTALL_LOCATION.as_ptr());

    let program_dir_ptr = null_mut();
    let program_dir_ptr_len = null_mut();

    if ERROR_SUCCESS
        != unsafe {
            RegGetValueA(
                HKEY_LOCAL_MACHINE,
                registry_key,
                registry_key_value,
                RRF_RT_REG_SZ,
                None,
                Some(program_dir_ptr),
                Some(program_dir_ptr_len),
            )
        }
    {
        return STATUS_UNSUCCESSFUL;
    };

    let program_dir = {
        let ptr = program_dir_ptr.cast::<STRING>();

        if ptr.is_null() {
            return STATUS_UNSUCCESSFUL;
        }

        match win_string_to_rust(unsafe { ptr.read() }) {
            Some(str) => str,
            None => return STATUS_UNSUCCESSFUL,
        }
    };

    unsafe {
        PROGRAM_DIR = Some(program_dir.clone());
    }

    let file_appender = tracing_appender::rolling::daily(program_dir, "authlib.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt().with_writer(non_blocking).init();

    event!(Level::INFO, "Initialising Kanidm Windows client");
    event!(
        Level::INFO,
        "Local Security Authority Version {}",
        lsa_version
    );
    event!(Level::INFO, "Client Version v{}", env!("CARGO_PKG_VERSION"));

    event!(
        Level::DEBUG,
        "Beginning version determination for Local Security Authority"
    );
    let package_version_str = format!(
        "{}{:0>3}{:0>3}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH")
    );

    let package_version = match package_version_str.parse::<u32>() {
        Ok(ver) => ver,
        Err(_) => {
            event!(Level::ERROR, "Failed to parse version string as int");
            1 // Just return 1 as the version number as we can't determine the correct version
        }
    };
    event!(
        Level::DEBUG,
        "Finished version determination. Version is determined as {}",
        package_version
    );

    event!(
        Level::DEBUG,
        "Creating security package function table and assigning return variables"
    );
    let function_table = SECPKG_FUNCTION_TABLE {
        InitializePackage: Some(package::ApInitialisePackage),
        LogonUserA: Some(package::ApLogonUser),
        CallPackage: Some(package::ApCallPackage),
        LogonTerminated: Some(package::ApLogonTerminated),
        CallPackageUntrusted: Some(package::ApCallPackage),
        CallPackagePassthrough: Some(package::ApCallPackage),
        LogonUserExA: None,
        LogonUserEx2: None,
        Initialize: Some(package::SpInitialise),
        Shutdown: None,
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
    event!(
        Level::DEBUG,
        "Finished creating table and assigning variables"
    );

    // Because Lazy only inits on first access, this may cause issues in the package
    // therefore we access these global vars to ensure initialisation
    event!(
        Level::DEBUG,
        "Beginning initialisation of required global state"
    );
    event!(Level::INFO, "Initialising kanidm client");
    Lazy::get(unsafe { &KANIDM_CLIENT });

    event!(Level::INFO, "Initialising login session hashmap");
    Lazy::get(unsafe { &AP_LOGON_IDS });
    event!(
        Level::DEBUG,
        "Finished initialisation of required global state"
    );

    STATUS_SUCCESS
}

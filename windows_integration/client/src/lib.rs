#![deny(unsafe_op_in_unsafe_fn)]

use std::ptr::{null_mut};

use kanidm_client::KanidmClientBuilder;
use once_cell::sync::Lazy;
use tracing::{event, Level};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use uuid::{Uuid, uuid};
use win_etw_tracing::TracelogSubscriber;
use win_etw_provider::GUID;

use windows::Win32::System::Kernel::STRING;
use windows::core::PCSTR;
use windows::Win32::Foundation::{
    ERROR_SUCCESS, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use windows::Win32::Security::Authentication::Identity::SECPKG_FUNCTION_TABLE;
use windows::Win32::System::Registry::{
    RegGetValueA, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
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

pub(crate) const IDM_GROUP_FOR_LOCAL_ADMIN: &str = "windows_admin";

pub(crate) const KANIDM_EVENTLOG_NAME: &str = "KanidmSSPAP";
pub(crate) const KANIDM_EVENTLOG_GUID: Uuid = uuid!("23ea1e19-d478-412b-bfe1-4bbff1917f4b");

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

    let guid = GUID::from(KANIDM_EVENTLOG_GUID);
    let etw_subscriber = match TracelogSubscriber::new(guid, KANIDM_EVENTLOG_NAME) {
        Ok(etw) => etw,
        Err(_) => return STATUS_UNSUCCESSFUL,
    };

    tracing_subscriber::registry().with(etw_subscriber);

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
    let config_path = format!("{}/authlib_client.toml", program_dir);

    let mut client_builder = KanidmClientBuilder::new();

    client_builder = match client_builder.read_options_from_optional_config(config_path) {
        Ok(cb) => cb,
        Err(_) => {
            event!(Level::ERROR, "Failed to read options from configuration");
            return STATUS_UNSUCCESSFUL;
        }
    };

    let client = match client_builder.build() {
        Ok(client) => client,
        Err(_) => {
            event!(Level::ERROR, "Failed to build the kanidm client");
            return STATUS_UNSUCCESSFUL;
        }
    };

    unsafe {
        KANIDM_CLIENT = Some(client);
    }

    event!(Level::INFO, "Initialising login session hashmap");
    Lazy::get(unsafe { &AP_LOGON_IDS });
    event!(
        Level::DEBUG,
        "Finished initialisation of required global state"
    );

    STATUS_SUCCESS
}

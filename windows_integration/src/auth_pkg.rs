// TODO: Finish implementing the auth package
use std::{ffi::c_void, ptr, mem};
use tracing::{event, span, Level};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, LUID, UNICODE_STRING},
        Security::Authentication::Identity::{LSA_DISPATCH_TABLE, SECURITY_LOGON_TYPE, LSA_TOKEN_INFORMATION_TYPE},
        System::Kernel::STRING,
    },
};

pub static mut GLOBAL_AUTHENTICATION_PACKAGE: AuthenticationPackage = AuthenticationPackage {
    package_id: None,
    dispatch_table: None,
};

pub struct AuthenticationPackage {
    /// The identifier the LSA has assigned the client
    package_id: Option<u32>,
    /// The dispatch table which provides functions to be called by the client
    dispatch_table: Option<&'static LSA_DISPATCH_TABLE>,
}

pub struct AuthInfo {
    username: UNICODE_STRING,
    password: UNICODE_STRING,
}

pub struct ProfileBuffer {}

impl AuthenticationPackage {
    pub async fn initialise_package(
        &mut self,
        package_id: u32,
        dispatch_table: *const LSA_DISPATCH_TABLE,
        out_pkg_name: *mut *mut STRING,
    ) -> NTSTATUS {
        let init_pkg_span =
            span!(Level::INFO, "Initialising kanidm Authentication Package").entered();

        if self.dispatch_table.is_some() || self.package_id.is_some() {
            event!(Level::ERROR, "kanidm client has already been initialised");

            return STATUS_UNSUCCESSFUL;
        }

        let dispatch_table_ref = unsafe {
            match dispatch_table.as_ref() {
                Some(tbl) => tbl,
                None => {
                    event!(Level::ERROR, "Failed to get reference to dispatch table");

                    return STATUS_UNSUCCESSFUL;
                },
            }
        };

        self.dispatch_table = Some(dispatch_table_ref);
        self.package_id = Some(package_id);

        let mut package_name = env!("CARGO_PKG_NAME").to_owned();
        let package_name_length = match u16::try_from(package_name.len()) {
            Ok(len) => len,
            Err(e) => {
                event!(Level::ERROR, "Failed to convert package name length");
                event!(Level::DEBUG, "TryFromIntError {}", e);

                return STATUS_UNSUCCESSFUL;
            }
        };
        let ap_name = STRING {
            Length: package_name_length,
            MaximumLength: package_name_length,
            Buffer: PSTR(package_name.as_mut_ptr()),
        };

        unsafe {
            **out_pkg_name = ap_name;
        }

        init_pkg_span.exit();
        STATUS_SUCCESS
    }

    pub async fn logon_user(
        &self,
        client_request: *const *const c_void,
        logon_type: SECURITY_LOGON_TYPE,
        authentication_info: *const AuthInfo,
        client_authentication_base: *const *const AuthInfo,
        authentication_info_length: u32,
        out_profile_buffer: *mut *mut ProfileBuffer,
        out_profile_buffer_length: *mut u32,
        out_logon_id: *mut LUID,
        out_substatus: *mut i32,
        out_token_info_type: *mut LSA_TOKEN_INFORMATION_TYPE,
        out_token_info: *mut *mut c_void,
        out_account_name: *mut *mut UNICODE_STRING,
        out_authenticating_authority: *mut *mut UNICODE_STRING,
    ) -> NTSTATUS {
        let logon_user_span = span!(Level::INFO, "Logging on user").entered();

        let dispatch_table = match self.dispatch_table {
            Some(tbl) => tbl,
            None => {
                event!(Level::ERROR, "Missing Dispatch Table");

                return STATUS_UNSUCCESSFUL;
            }
        };

        logon_user_span.exit();
        STATUS_SUCCESS
    }
}

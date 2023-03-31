use std::sync::{Arc, Mutex};
use tracing::{event, span, Level};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
        Security::Authentication::Identity::LSA_DISPATCH_TABLE,
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
    dispatch_table: Option<Arc<Mutex<*const LSA_DISPATCH_TABLE>>>,
}

impl AuthenticationPackage {
    pub fn initialise_package(
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

        self.dispatch_table = Some(Arc::new(Mutex::new(dispatch_table)));
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
}

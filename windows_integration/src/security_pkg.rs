use tracing::{span, Level, event};
use windows::Win32::{
    Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL},
    Security::Authentication::Identity::{LSA_SECPKG_FUNCTION_TABLE, SECPKG_PARAMETERS},
};

pub static mut GLOBAL_SECURITY_PACKAGE: SecurityPackage = SecurityPackage {
	package_id: None,
	params: None,
	lsa_support_fns: None,
};

pub struct SecurityPackage {
    /// The id of the security package assigned by the LSA
    pub package_id: Option<usize>,
    /// The parameters which contain primary domain & machine state info
    pub params: Option<&'static SECPKG_PARAMETERS>,
    /// The LSA support functions
    pub lsa_support_fns: Option<&'static LSA_SECPKG_FUNCTION_TABLE>,
}

impl SecurityPackage {
    pub fn initialise_package(
        &mut self,
        package_id: usize,
        params: *const SECPKG_PARAMETERS,
        lsa_support_fns: *const LSA_SECPKG_FUNCTION_TABLE,
    ) -> NTSTATUS {
        let init_pkg_span = span!(Level::INFO, "Initialising kanidm security package").entered();

		if self.package_id.is_some() || self.params.is_some() || self.lsa_support_fns.is_some() {
			event!(Level::ERROR, "kanidm security package has already been initialised");
			
			return STATUS_UNSUCCESSFUL;
		}

		let func_table_ref = unsafe {
			match lsa_support_fns.as_ref() {
				Some(tbl) => tbl,
				None => {
					event!(Level::ERROR, "Failed to get reference to the LSA's support functions");

					return STATUS_UNSUCCESSFUL;
				}
			}
		};
		let params_ref = unsafe {
			match params.as_ref() {
				Some(prms) => prms,
				None => {
					event!(Level::ERROR, "Failed to get reference to secpkg parameters");

					return STATUS_UNSUCCESSFUL;
				}
			}
		};

		self.package_id = Some(package_id);
		self.params = Some(params_ref);
		self.lsa_support_fns = Some(func_table_ref);

		init_pkg_span.exit();
        STATUS_SUCCESS
    }

	pub fn shutdown_package(
		&mut self,
	) -> NTSTATUS {
		// TODO: Implement cleanup logic when there is resources to clean up

		STATUS_SUCCESS
	}
}

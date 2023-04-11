use crate::{client::KanidmWindowsClient, CONFIG_PATH};
use once_cell::sync::Lazy;
use tracing::{event, Level, span};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::*,
        Security::{Authentication::Identity::*, Credentials::STATUS_LOGON_FAILURE},
        System::Kernel::*,
    },
};

pub(crate) static mut KANIDM_WINDOWS_CLIENT: Lazy<Option<KanidmWindowsClient>> = Lazy::new(|| {
    let client = match KanidmWindowsClient::new(CONFIG_PATH) {
        Ok(client) => client,
        Err(e) => {
            event!(Level::ERROR, "Failed to create new KanidmWindowsClient");
            event!(Level::INFO, "KanidmWindowsClientError {:?}", e);

            return None;
        }
    };

    Some(client)
});
static mut AP_DISPATCH_TABLE: Option<LSA_DISPATCH_TABLE> = None;
static mut AP_PACKAGE_ID: u32 = 0;

#[tokio::main(flavor = "current_thread")]
#[no_mangle]
#[allow(non_snake_case)]
pub async extern "system" fn ApInitializePackage(
    package_id: u32,
    dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    out_package_name: *mut *mut STRING,
) -> NTSTATUS {
	let apips = span!(Level::INFO, "Initialising Kanidm Authentication Package").entered();
    let mut package_name = env!("CARGO_PKG_NAME").to_owned();
    let package_name_win = STRING {
        Buffer: PSTR(package_name.as_mut_ptr()),
        Length: package_name.len() as u16,
        MaximumLength: package_name.len() as u16,
    };
	let dt_ref = match unsafe { dispatch_table.as_ref() } {
		Some(dt) => dt,
		None => {
			event!(Level::ERROR, "Failed to get reference to the LSA Dispatch Table");
			return STATUS_UNSUCCESSFUL;
		},
	};
    unsafe { 
		*(*out_package_name) = package_name_win;
		AP_DISPATCH_TABLE = Some(dt_ref.to_owned());
		AP_PACKAGE_ID = package_id;
	}

	if unsafe { KANIDM_WINDOWS_CLIENT.is_none() } {
		event!(Level::ERROR, "Kanidm Windows Client did not initialise correctly");
		return STATUS_UNSUCCESSFUL;
	}

	apips.exit();
    STATUS_SUCCESS
}

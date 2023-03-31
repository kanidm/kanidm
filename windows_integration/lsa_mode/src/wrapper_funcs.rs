use windows::Win32::{Security::Authentication::Identity::LSA_DISPATCH_TABLE, Foundation::NTSTATUS, System::Kernel::STRING};

use crate::auth_pkg::GLOBAL_AUTHENTICATION_PACKAGE;

pub extern "system" fn ap_initialise_pkg(
    package_id: u32,
    dispatch_table: *const LSA_DISPATCH_TABLE,
    _: *const STRING,
    _: *const STRING,
    ap_pkg_name_return: *mut *mut STRING,
) -> NTSTATUS {
    unsafe {
        GLOBAL_AUTHENTICATION_PACKAGE.initialise_package(
            package_id,
            dispatch_table,
            ap_pkg_name_return,
        )
    }
}

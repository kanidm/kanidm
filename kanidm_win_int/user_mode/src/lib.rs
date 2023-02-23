use windows::Win32::{Foundation::NTSTATUS, Security::Authentication::Identity::*};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn SpUserModeInitialize(
    lsaversion: u32,
    packageversion: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    NTSTATUS(0x0)
}

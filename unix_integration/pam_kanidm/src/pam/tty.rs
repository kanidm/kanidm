use std::ffi::CStr;
use crate::pam::constants::*;
use crate::pam::module::{PamItem, PamResult};

use libc::c_char;

#[repr(C)]
pub struct PamTty {
    name: *const c_char,
}

impl PamItem for PamTty {
    fn item_type() -> PamItemType {
        PAM_TTY
    }
}

impl PamTty {
    pub fn as_str(&self) -> PamResult<String> {
        if !self.name.is_null() {
            let cstr = unsafe { CStr::from_ptr(self.name) };
            cstr.to_str()
                .map_err(|_| PamResultCode::PAM_CONV_ERR)
                .map(|s| s.to_string())
        } else {
            Err(PamResultCode::PAM_CONV_ERR)
        }
    }
}

#[repr(C)]
pub struct PamRhost {
    name: *const c_char,
}

impl PamItem for PamRhost {
    fn item_type() -> PamItemType {
        PAM_RHOST
    }
}

impl PamRhost {
    pub fn as_str(&self) -> PamResult<String> {
        if !self.name.is_null() {
            let cstr = unsafe { CStr::from_ptr(self.name) };
            cstr.to_str()
                .map_err(|_| PamResultCode::PAM_CONV_ERR)
                .map(|s| s.to_string())
        } else {
            Err(PamResultCode::PAM_CONV_ERR)
        }
    }
}

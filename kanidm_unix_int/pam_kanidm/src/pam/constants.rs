use libc::{c_int, c_uint};

// TODO: Import constants from C header file at compile time.

pub type PamFlag = c_uint;
pub type PamItemType = c_int;
pub type PamMessageStyle = c_int;
pub type AlwaysZero = c_int;

// The Linux-PAM flags
// see /usr/include/security/_pam_types.h
pub const PAM_SILENT: PamFlag = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK: PamFlag = 0x0001;
pub const PAM_ESTABLISH_CRED: PamFlag = 0x0002;
pub const PAM_DELETE_CRED: PamFlag = 0x0004;
pub const PAM_REINITIALIZE_CRED: PamFlag = 0x0008;
pub const PAM_REFRESH_CRED: PamFlag = 0x0010;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x0020;

// The Linux-PAM item types
// see /usr/include/security/_pam_types.h
/// The service name
pub const PAM_SERVICE: PamItemType = 1;
/// The user name
pub const PAM_USER: PamItemType = 2;
/// The tty name
pub const PAM_TTY: PamItemType = 3;
/// The remote host name
pub const PAM_RHOST: PamItemType = 4;
/// The pam_conv structure
pub const PAM_CONV: PamItemType = 5;
/// The authentication token (password)
pub const PAM_AUTHTOK: PamItemType = 6;
/// The old authentication token
pub const PAM_OLDAUTHTOK: PamItemType = 7;
/// The remote user name
pub const PAM_RUSER: PamItemType = 8;
/// the prompt for getting a username
pub const PAM_USER_PROMPT: PamItemType = 9;
/* Linux-PAM :extensionsPamItemType = */
/// app supplied function to override failure delays
pub const PAM_FAIL_DELAY: PamItemType = 10;
/// X :display name
pub const PAM_XDISPLAY: PamItemType = 11;
/// X :server authentication data
pub const PAM_XAUTHDATA: PamItemType = 12;
/// The type for pam_get_authtok
pub const PAM_AUTHTOK_TYPE: PamItemType = 13;

// Message styles
pub const PAM_PROMPT_ECHO_OFF: PamMessageStyle = 1;
pub const PAM_PROMPT_ECHO_ON: PamMessageStyle = 2;
pub const PAM_ERROR_MSG: PamMessageStyle = 3;
pub const PAM_TEXT_INFO: PamMessageStyle = 4;
/// yes/no/maybe conditionals
pub const PAM_RADIO_TYPE: PamMessageStyle = 5;
pub const PAM_BINARY_PROMPT: PamMessageStyle = 7;

// The Linux-PAM return values
// see /usr/include/security/_pam_types.h
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_OPEN_ERR = 1,
    PAM_SYMBOL_ERR = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR = 5,
    PAM_PERM_DENIED = 6,
    PAM_AUTH_ERR = 7,
    PAM_CRED_INSUFFICIENT = 8,
    PAM_AUTHINFO_UNAVAIL = 9,
    PAM_USER_UNKNOWN = 10,
    PAM_MAXTRIES = 11,
    PAM_NEW_AUTHTOK_REQD = 12,
    PAM_ACCT_EXPIRED = 13,
    PAM_SESSION_ERR = 14,
    PAM_CRED_UNAVAIL = 15,
    PAM_CRED_EXPIRED = 16,
    PAM_CRED_ERR = 17,
    PAM_NO_MODULE_DATA = 18,
    PAM_CONV_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_TRY_AGAIN = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_AUTHTOK_EXPIRED = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_BAD_ITEM = 29,
    PAM_CONV_AGAIN = 30,
    PAM_INCOMPLETE = 31,
}

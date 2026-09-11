use libc::{c_int, c_uint};

pub type PamFlag = c_uint;
pub type PamItemType = c_int;
pub type PamMessageStyle = c_int;
pub type AlwaysZero = c_int;

// See /usr/include/security/pam_constants.h

pub const _PAM_SILENT: PamFlag = 0x8000_0000;
pub const _PAM_DISALLOW_NULL_AUTHTOK: PamFlag = 0x0001;
pub const _PAM_ESTABLISH_CRED: PamFlag = 0x0001;
pub const _PAM_DELETE_CRED: PamFlag = 0x0002;
pub const _PAM_REINITIALIZE_CRED: PamFlag = 0x0004;
pub const _PAM_REFRESH_CRED: PamFlag = 0x0008;
pub const _PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x0004;

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
// OpenPAM extensions
pub const _PAM_REPOSITORY: PamItemType = 10;
pub const _PAM_AUTHTOK_PROMPT: PamItemType = 11;
pub const _PAM_OLDAUTHTOK_PROMPT: PamItemType = 12;
pub const _PAM_HOST: PamItemType = 13;

// Message styles
pub const PAM_PROMPT_ECHO_OFF: PamMessageStyle = 1;
pub const PAM_PROMPT_ECHO_ON: PamMessageStyle = 2;
pub const PAM_ERROR_MSG: PamMessageStyle = 3;
pub const PAM_TEXT_INFO: PamMessageStyle = 4;

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
    PAM_CONV_ERR = 6,
    PAM_PERM_DENIED = 7,
    PAM_MAXTRIES = 8,
    PAM_AUTH_ERR = 9,
    PAM_NEW_AUTHTOK_REQD = 10,
    PAM_CRED_INSUFFICIENT = 11,
    PAM_AUTHINFO_UNAVAIL = 12,
    PAM_USER_UNKNOWN = 13,
    PAM_CRED_UNAVAIL = 14,
    PAM_CRED_EXPIRED = 15,
    PAM_CRED_ERR = 16,
    PAM_ACCT_EXPIRED = 17,
    PAM_AUTHTOK_EXPIRED = 18,
    PAM_SESSION_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_NO_MODULE_DATA = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_TRY_AGAIN = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_DOMAIN_UNKNOWN = 29,
    PAM_BAD_HANDLE = 30,  /* OpenPAM extension */
    PAM_BAD_ITEM = 31,    /* OpenPAM extension */
    PAM_BAD_FEATURE = 32, /* OpenPAM extension */
    PAM_BAD_CONSTANT = 33,
}

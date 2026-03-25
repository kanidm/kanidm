//! FFI boundary - this is the translation layer between RLM C structures
//! and internal native rust types.

use crate::error::ModuleError;
use crate::freeradius::rlm_rcodes;
use crate::{RequestAttributes, Response, ResponseControlAttributes, ResponseReplyAttributes};
use libc::c_char;
use std::ffi::{CStr, CString};
use std::ptr;

// TODO: These should be private!
pub const ATTR_USER_NAME: &CStr = c"User-Name";
pub const ATTR_TLS_CN: &CStr = c"TLS-Client-Cert-Common-Name";
pub const ATTR_TLS_SAN_DN_CN: &CStr =
    c"TLS-Client-Cert-Subject-Alt-Name-Directory-Name-Common-Name";
pub const REPLY_USER_NAME: &CStr = c"User-Name";
pub const REPLY_MESSAGE: &CStr = c"Reply-Message";
pub const REPLY_TUNNEL_TYPE: &CStr = c"Tunnel-Type";
pub const REPLY_TUNNEL_MEDIUM_TYPE: &CStr = c"Tunnel-Medium-Type";
pub const REPLY_TUNNEL_PRIVATE_GROUP_ID: &CStr = c"Tunnel-Private-Group-ID";
pub const CONTROL_CLEARTEXT_PASSWORD: &CStr = c"Cleartext-Password";

pub(crate) fn cstr_to_string(ptr_in: *const c_char) -> Result<String, ModuleError> {
    if ptr_in.is_null() {
        return Err(ModuleError::Other("null pointer".to_string()));
    }
    let cstr = unsafe { CStr::from_ptr(ptr_in) };
    cstr.to_str()
        .map(String::from)
        .map_err(|err| ModuleError::Other(format!("invalid utf-8 string: {err}")))
}

/// Helper to free an array of KVPair allocated in Rust and returned to C. This should be called for the `reply` and `control` fields of `AuthResultC` after the caller is done using them, to avoid memory leaks.
pub fn free_kv_pairs(ptr_pairs: *mut KVPair, len: usize) {
    if ptr_pairs.is_null() {
        return;
    }

    // This works because of the use of shrink_to_fit in ownedpairs.into().
    let pairs = unsafe { Vec::from_raw_parts(ptr_pairs, len, len) };

    // This drains and frees Pairs at the end.
    for pair in pairs {
        if !pair.key.is_null() {
            unsafe {
                drop(CString::from_raw(pair.key.cast_mut()));
            }
        }
        if !pair.value.is_null() {
            unsafe {
                drop(CString::from_raw(pair.value.cast_mut()));
            }
        }
    }
}

pub fn kvpairs_to_attributes(
    request_attrs: *const KVPair,
    request_attrs_len: usize,
) -> Result<RequestAttributes, ModuleError> {
    if request_attrs.is_null() && request_attrs_len != 0 {
        return Err(ModuleError::Other(
            "request_attrs pointer is null with non-zero length".to_string(),
        ));
    }
    let attrs_slice: &[KVPair] = if request_attrs_len != 0 {
        unsafe { std::slice::from_raw_parts(request_attrs, request_attrs_len) }
    } else {
        &[]
    };

    let mut request_attrs = RequestAttributes::default();

    for pair in attrs_slice {
        let value = cstr_to_string(pair.value)?;

        let key = unsafe { CStr::from_ptr(pair.key) };

        if key == ATTR_TLS_SAN_DN_CN {
            request_attrs.tls_san_dn_cn = Some(value);
        } else if key == ATTR_TLS_CN {
            request_attrs.tls_cn = Some(value);
        } else if key == ATTR_USER_NAME {
            request_attrs.user_name = Some(value);
        } else {
            let key = cstr_to_string(pair.key)?;
            request_attrs.attrs.insert(key, value);
        };
    }

    Ok(request_attrs)
}

#[repr(C)]
pub struct KVPair {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct AuthResultC {
    pub code: u32,
    pub reply: *mut KVPair,
    pub reply_len: usize,
    pub control: *mut KVPair,
    pub control_len: usize,
    pub error: *mut c_char,
}

impl From<ModuleError> for AuthResultC {
    fn from(input: ModuleError) -> Self {
        let c_message =
            CString::new(input.to_string()).unwrap_or_else(|_| CString::from(c"module error"));

        AuthResultC {
            code: rlm_rcodes::RLM_MODULE_FAIL,
            reply: ptr::null_mut(),
            reply_len: 0,
            control: ptr::null_mut(),
            control_len: 0,
            error: c_message.into_raw(),
        }
    }
}

impl Response {
    fn code(&self) -> u32 {
        // TODO: Make these use the header values
        match self {
            Response::Reject => rlm_rcodes::RLM_MODULE_REJECT,
            Response::Fail => rlm_rcodes::RLM_MODULE_FAIL,
            Response::Ok { .. } => rlm_rcodes::RLM_MODULE_OK,
            Response::Handled => rlm_rcodes::RLM_MODULE_HANDLED,
            Response::Invalid => rlm_rcodes::RLM_MODULE_INVALID,
            Response::UserLock => rlm_rcodes::RLM_MODULE_USERLOCK,
            Response::NotFound => rlm_rcodes::RLM_MODULE_NOTFOUND,
            Response::NoOp => rlm_rcodes::RLM_MODULE_NOOP,
            Response::Updated => rlm_rcodes::RLM_MODULE_UPDATED,
        }
    }
}

pub struct OwnedPair {
    pub key: CString,
    pub value: CString,
}

impl<S> TryFrom<(&CStr, S)> for OwnedPair
where
    S: AsRef<str>,
{
    type Error = ModuleError;

    fn try_from((key, value): (&CStr, S)) -> Result<Self, Self::Error> {
        Ok(OwnedPair {
            key: CString::from(key),
            value: CString::new(value.as_ref())
                .map_err(|err| ModuleError::Other(format!("invalid c string: {key:?} {err}")))?,
        })
    }
}

pub struct OwnedPairs {
    pairs: Vec<OwnedPair>,
}

impl Into<Vec<KVPair>> for OwnedPairs {
    fn into(self: OwnedPairs) -> Vec<KVPair> {
        let mut raw_vec = self
            .pairs
            .into_iter()
            .map(|OwnedPair { key, value }| KVPair {
                key: key.into_raw(),
                value: value.into_raw(),
            })
            .collect::<Vec<_>>();

        // IMPORTANT: This is required so that when we reconstruct
        // this vector, we can use length as capacity.
        raw_vec.shrink_to_fit();

        raw_vec
    }
}

impl TryFrom<ResponseControlAttributes> for OwnedPairs {
    type Error = ModuleError;

    fn try_from(response: ResponseControlAttributes) -> Result<Self, Self::Error> {
        let ResponseControlAttributes { cleartext_password } = response;

        let pairs = if let Some(cleartext_password) = cleartext_password {
            vec![OwnedPair::try_from((
                CONTROL_CLEARTEXT_PASSWORD,
                cleartext_password,
            ))?]
        } else {
            Vec::default()
        };

        Ok(OwnedPairs { pairs })
    }
}

impl TryFrom<ResponseReplyAttributes> for OwnedPairs {
    type Error = ModuleError;

    fn try_from(response: ResponseReplyAttributes) -> Result<Self, Self::Error> {
        let ResponseReplyAttributes {
            user_name,
            message,
            tunnel_type,
            tunnel_medium_type,
            tunnel_private_group_id,
        } = response;

        let pairs = vec![
            OwnedPair::try_from((REPLY_USER_NAME, user_name))?,
            OwnedPair::try_from((REPLY_MESSAGE, message))?,
            OwnedPair::try_from((REPLY_TUNNEL_TYPE, tunnel_type))?,
            OwnedPair::try_from((REPLY_TUNNEL_MEDIUM_TYPE, tunnel_medium_type))?,
            OwnedPair::try_from((REPLY_TUNNEL_PRIVATE_GROUP_ID, tunnel_private_group_id))?,
        ];

        Ok(OwnedPairs { pairs })
    }
}

impl TryFrom<Response> for AuthResultC {
    type Error = ModuleError;

    fn try_from(response: Response) -> Result<Self, Self::Error> {
        match response {
            Response::Ok { reply, control } => {
                let reply_pairs = OwnedPairs::try_from(reply)?;
                let control_pairs = OwnedPairs::try_from(control)?;

                // ========================================================
                // After this point we MUST NOT FAIL else we leak memory!!!
                let reply_vec: Vec<KVPair> = reply_pairs.into();
                let control_vec: Vec<KVPair> = control_pairs.into();

                let (reply_ptr, reply_len, _) = reply_vec.into_raw_parts();
                let (control_ptr, control_len, _) = control_vec.into_raw_parts();

                Ok(AuthResultC {
                    code: rlm_rcodes::RLM_MODULE_OK,
                    reply: reply_ptr,
                    reply_len,
                    control: control_ptr,
                    control_len,
                    error: ptr::null_mut(),
                })
            }
            _ => Ok(AuthResultC {
                code: response.code(),
                reply: ptr::null_mut(),
                reply_len: 0,
                control: ptr::null_mut(),
                control_len: 0,
                error: ptr::null_mut(),
            }),
        }
    }
}

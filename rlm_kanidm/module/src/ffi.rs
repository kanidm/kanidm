//! FFI boundary - this is the translation layer between RLM C structures
//! and internal native rust types.

use libc::c_char;
use std::ffi::{CStr};
use crate::error::ModuleError;

const ATTR_USER_NAME: &str = "User-Name";
const ATTR_TLS_CN: &str = "TLS-Client-Cert-Common-Name";
const ATTR_TLS_SAN_DN_CN: &str = "TLS-Client-Cert-Subject-Alt-Name-Directory-Name-Common-Name";
const REPLY_USER_NAME: &str = "User-Name";
const REPLY_MESSAGE: &str = "Reply-Message";
const REPLY_TUNNEL_TYPE: &str = "Tunnel-Type";
const REPLY_TUNNEL_MEDIUM_TYPE: &str = "Tunnel-Medium-Type";
const REPLY_TUNNEL_PRIVATE_GROUP_ID: &str = "Tunnel-Private-Group-ID";
const CONTROL_CLEARTEXT_PASSWORD: &str = "Cleartext-Password";


struct OwnedPair {
    key: CString,
    value: CString,
}

pub(crate) fn cstr_to_string(ptr_in: *const c_char) -> Result<String, ModuleError> {
    if ptr_in.is_null() {
        return Err(ModuleError::Other("null string pointer".to_string()));
    }
    let cstr = unsafe { CStr::from_ptr(ptr_in) };
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|e| ModuleError::Other(format!("invalid utf-8 string: {e}")))
}


/// Helper to free an array of KVPair allocated in Rust and returned to C. This should be called for the `reply` and `control` fields of `AuthResultC` after the caller is done using them, to avoid memory leaks.
fn free_kv_pairs(ptr_pairs: *mut KVPair, len: usize) {
    if ptr_pairs.is_null() {
        return;
    }
    let slice_ptr = ptr::slice_from_raw_parts_mut(ptr_pairs, len);
    let boxed = unsafe { Box::from_raw(slice_ptr) };
    for pair in boxed.iter() {
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

fn kvpairs_to_attributes(
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
    let mut attrs = BTreeMap::<String, String>::new();
    for pair in attrs_slice {
        let key = cstr_to_string(pair.key)?;
        let value = cstr_to_string(pair.value)?;
        attrs.insert(key, value);
    }
    Ok(RequestAttributes { attrs })
}

#[repr(C)]
pub struct KVPair {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct AuthResultC {
    pub code: i32,
    pub reply: *mut KVPair,
    pub reply_len: usize,
    pub control: *mut KVPair,
    pub control_len: usize,
    pub error: *mut c_char,
}

fn auth_result_from_pairs(response: &Response) -> AuthResultC {
    let reply_vec = into_kvpairs(response.reply());
    let control_vec = into_kvpairs(response.control());
    let reply_len = reply_vec.len();
    let control_len = control_vec.len();
    let mut reply_boxed = reply_vec.into_boxed_slice();
    let mut control_boxed = control_vec.into_boxed_slice();
    let reply_ptr = reply_boxed.as_mut_ptr();
    let control_ptr = control_boxed.as_mut_ptr();
    std::mem::forget(reply_boxed);
    std::mem::forget(control_boxed);
    AuthResultC {
        code: response.code(),
        reply: reply_ptr,
        reply_len,
        control: control_ptr,
        control_len,
        error: ptr::null_mut(),
    }
}

fn into_kvpairs(pairs: Vec<(&'static str, String)>) -> Vec<KVPair> {
    #[allow(clippy::expect_used)]
    pairs
        .into_iter()
        .map(|(k, v)| {
            let k_c = CString::new(k).expect("literal CString");
            let v_c = CString::new(v).expect("literal CString");
            KVPair {
                key: k_c.into_raw(),
                value: v_c.into_raw(),
            }
        })
        .collect()
}

/// Create an AuthError result with the given message. Might panic if `message` can't be turned into a C string, but since we only call this with static strings or error messages from Rust code, that should be fine.
fn auth_error(response: &Response, message: String) -> AuthResultC {
    // At some point we just have to convert to a C string, and if that fails we can't do much about it, so it's fine to panic with a literal here
    #[allow(clippy::expect_used)]
    let c_message = CString::new(message)
        .unwrap_or_else(|_| CString::new("module error").expect("literal CString"));
    AuthResultC {
        code: response.code(),
        reply: ptr::null_mut(),
        reply_len: 0,
        control: ptr::null_mut(),
        control_len: 0,
        error: c_message.into_raw(),
    }
}



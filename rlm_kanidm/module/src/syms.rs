//! Externally Facing Symbols - This is what we export to FreeRADIUS to call into us
//! to drive the operation of the rlm_kanidm module.

use crate::error::ModuleError;
use crate::ffi::{
    cstr_to_string, free_kv_pairs, kvpairs_to_attributes, AuthResultC, KVPair, OwnedPair,
};
use crate::{Module, ModuleHandle, ModuleOptions};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::mem::offset_of;
use std::ptr;

use crate::freeradius::{
    self as fr, conf_part as conf_part_t,
    fr_token_t::T_OP_EQ,
    module_t, packetmethod as packetmethod_t,
    rlm_components::{MOD_AUTHORIZE, MOD_COUNT},
    rlm_kanidm_module, rlm_rcode_t,
    rlm_rcodes::RLM_MODULE_FAIL,
    CONF_PARSER as conf_parser_t,
    PW_TYPE::PW_TYPE_STRING,
    REQUEST, RLM_TYPE_THREAD_SAFE,
};

#[repr(C)]
struct RlmKanidmInstance {
    config_path: *const c_char,
    rust_handle: *mut ModuleHandle,
}

const CONFIG_PATH_KEY: &CStr = c"config_path";
const DEFAULT_CONFIG_PATH: &CStr = c"/data/radius.toml";
const MODULE_NAME: &CStr = c"kanidm";

static mut MODULE_CONFIG: [conf_parser_t; 2] = [
    conf_parser_t {
        name: CONFIG_PATH_KEY.as_ptr(),
        type_: PW_TYPE_STRING as c_int,
        // TODO: Not sure this is safe?
        offset: offset_of!(RlmKanidmInstance, config_path),
        data: ptr::null_mut(),
        dflt: DEFAULT_CONFIG_PATH.as_ptr().cast(),
    },
    conf_parser_t {
        name: ptr::null(),
        type_: -1,
        offset: 0,
        data: ptr::null_mut(),
        dflt: ptr::null(),
    },
];

const MODULE_METHODS: [packetmethod_t; MOD_COUNT as usize] = {
    let mut methods: [packetmethod_t; MOD_COUNT as usize] = [None; MOD_COUNT as usize];

    methods[MOD_AUTHORIZE as usize] =
        Some(mod_authorize as unsafe extern "C" fn(*mut c_void, *mut REQUEST) -> _);
    methods
};

/// This is the entry point that allows FreeRADIUS to start the module. It must be named the same
/// as the module, and must be the only publicly exported symbol.
#[unsafe(no_mangle)]
#[used]
pub static mut rlm_kanidm: module_t = module_t {
    magic: rlm_kanidm_module::INIT as u64,
    name: MODULE_NAME.as_ptr(),
    type_: RLM_TYPE_THREAD_SAFE as c_int,
    inst_size: size_of::<RlmKanidmInstance>(),
    config: ptr::addr_of!(MODULE_CONFIG).cast(),
    bootstrap: None,
    instantiate: Some(mod_instantiate),
    detach: Some(mod_detach),
    methods: MODULE_METHODS,
};

/// the instantiate method is called when the module is loaded, and should return 0 on success. The instance pointer is a pointer to a block of memory of size `inst_size`, which can be used to store module state. The config pointer is a pointer to the module configuration, which is parsed according to the `config` field of the module struct.
unsafe extern "C" fn mod_instantiate(_conf: *mut conf_part_t, instance: *mut c_void) -> c_int {
    if instance.is_null() {
        return -1;
    }

    let inst = unsafe { &mut *(instance.cast::<RlmKanidmInstance>()) };
    if inst.config_path.is_null() {
        // tracing::error!("rlm_kanidm: config_path missing");
        return -1;
    }

    let handle = rlm_kanidm_instantiate(inst.config_path);
    if handle.is_null() {
        // tracing::error!("rlm_kanidm: rust instantiate failed");
        return -1;
    }

    inst.rust_handle = handle;
    0
}

unsafe extern "C" fn mod_detach(instance: *mut c_void) -> c_int {
    if instance.is_null() {
        return 0;
    }

    let inst = unsafe { &mut *(instance.cast::<RlmKanidmInstance>()) };
    if !inst.rust_handle.is_null() {
        unsafe { rlm_kanidm_detach(inst.rust_handle) };
        inst.rust_handle = ptr::null_mut();
    }

    0
}

unsafe extern "C" fn mod_authorize(
    instance: *mut c_void,
    request: *mut fr::REQUEST,
) -> rlm_rcode_t {
    if instance.is_null() || request.is_null() {
        return fail_code();
    }

    let inst = unsafe { &mut *(instance.cast::<RlmKanidmInstance>()) };
    if inst.rust_handle.is_null() {
        // tracing::error!("rlm_kanidm not initialised");
        return fail_code();
    }

    let owned_pairs = unsafe { collect_request_attrs(request) };
    let raw_pairs = build_raw_pairs(&owned_pairs);

    let auth_result =
        unsafe { rlm_kanidm_authorize(inst.rust_handle, raw_pairs.as_ptr(), raw_pairs.len()) };

    /*
    if !auth_result.error.is_null() {
        let message = unsafe { CStr::from_ptr(auth_result.error) }.to_string_lossy();
        // tracing::error!("rlm_kanidm authorize error: {message}");
    }
    */

    let reply_ok =
        unsafe { add_pairs_to_request(request, auth_result.reply, auth_result.reply_len, false) };
    if !reply_ok {
        rlm_kanidm_free_auth_result(auth_result);
        return fail_code();
    }

    let control_ok = unsafe {
        add_pairs_to_request(request, auth_result.control, auth_result.control_len, true)
    };
    if !control_ok {
        rlm_kanidm_free_auth_result(auth_result);
        return fail_code();
    }

    let code = auth_result.code as fr::rlm_rcode_t;
    rlm_kanidm_free_auth_result(auth_result);
    code
}

/// Instantiate module state from a config path.
#[unsafe(no_mangle)]
extern "C" fn rlm_kanidm_instantiate(config_path: *const c_char) -> *mut ModuleHandle {
    let Ok(path) = cstr_to_string(config_path) else {
        return ptr::null_mut();
    };
    match Module::from_config_path(&path, &ModuleOptions::default()) {
        Ok(module) => {
            let handle = ModuleHandle { module };
            Box::into_raw(Box::new(handle))
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Free module state.
///
/// # Safety
/// - if you're calling this from C, ensure you only call it once per handle returned from `rlm_kanidm_instantiate` and do not use the handle after calling this.
#[unsafe(no_mangle)]
unsafe extern "C" fn rlm_kanidm_detach(handle: *mut ModuleHandle) {
    if handle.is_null() {
        return;
    }

    unsafe {
        let _ = Box::from_raw(handle);
    }
}

/// Authorize a request represented as key/value pairs.
///
/// # Safety
/// - `handle` must be a pointer returned from `rlm_kanidm_instantiate` and not yet freed by `rlm_kanidm_detach`.
/// - `request_attrs` must point to an array of `KVPair` of length `request_attrs_len`.
/// - The strings pointed to by `KVPair` must be valid null-terminated C strings.
#[unsafe(no_mangle)]
unsafe extern "C" fn rlm_kanidm_authorize(
    handle: *mut ModuleHandle,
    request_attrs: *const KVPair,
    request_attrs_len: usize,
) -> AuthResultC {
    if handle.is_null() {
        return ModuleError::Other("null module handle".to_string()).into();
    }

    let attrs = match kvpairs_to_attributes(request_attrs, request_attrs_len) {
        Ok(v) => v,
        Err(e) => return e.into(),
    };

    let module = unsafe { &(*handle).module };

    let module_result = module.authorize(&attrs);

    let auth_result = AuthResultC::try_from(module_result).unwrap_or_else(AuthResultC::from);

    auth_result
}

/// Free memory allocated in `AuthResultC`.
#[unsafe(no_mangle)]
extern "C" fn rlm_kanidm_free_auth_result(result: AuthResultC) {
    free_kv_pairs(result.reply, result.reply_len);
    free_kv_pairs(result.control, result.control_len);
    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
    }
}

const fn fail_code() -> rlm_rcode_t {
    RLM_MODULE_FAIL as rlm_rcode_t
}

unsafe fn collect_request_attrs(request: *mut fr::REQUEST) -> Vec<OwnedPair> {
    let mut cursor = unsafe { std::mem::zeroed::<fr::vp_cursor_t>() };
    let mut out = Vec::new();
    let request_ref = unsafe { &*request };
    let packet_ptr = request_ref.packet;
    if packet_ptr.is_null() {
        return out;
    }

    let packet_ref = unsafe { &*packet_ptr };
    let mut pair = unsafe { fr::fr_cursor_init(&mut cursor, ptr::addr_of!(packet_ref.vps)) };

    while !pair.is_null() {
        let key_ptr = unsafe {
            let dict_attr = (*pair).da;
            if dict_attr.is_null() {
                ptr::null()
            } else {
                ptr::addr_of!((*dict_attr).name).cast::<c_char>()
            }
        };

        if !key_ptr.is_null() {
            // TODO: FIX THIS
            let mut value_buf = [0 as c_char; 4096];
            unsafe {
                fr::vp_prints_value(
                    value_buf.as_mut_ptr(),
                    value_buf.len(),
                    pair,
                    // TODO: Fix this to be a null type.
                    '\0' as c_char,
                )
            };

            let key = unsafe { CStr::from_ptr(key_ptr) }.to_owned();
            let value = unsafe { CStr::from_ptr(value_buf.as_ptr()) }.to_owned();

            out.push(OwnedPair { key, value });
        }

        pair = unsafe { fr::fr_cursor_next(&mut cursor) };
    }

    out
}

fn build_raw_pairs(pairs: &[OwnedPair]) -> Vec<KVPair> {
    pairs
        .iter()
        .map(|pair| KVPair {
            key: pair.key.as_ptr(),
            value: pair.value.as_ptr(),
        })
        .collect()
}

unsafe fn add_pairs_to_request(
    request: *mut fr::REQUEST,
    pairs: *mut KVPair,
    len: usize,
    control: bool,
) -> bool {
    if pairs.is_null() {
        return len == 0;
    }

    let items = unsafe { std::slice::from_raw_parts(pairs.cast_const(), len) };

    for pair in items {
        if pair.key.is_null() || pair.value.is_null() {
            return false;
        }

        let added = if control {
            let req_ptr = request.cast::<c_void>();
            let request_ref = unsafe { &mut *request };
            unsafe {
                fr::fr_pair_make(
                    req_ptr,
                    ptr::addr_of_mut!(request_ref.config),
                    pair.key,
                    pair.value,
                    T_OP_EQ,
                )
            }
        } else {
            let request_ref = unsafe { &mut *request };
            if request_ref.reply.is_null() {
                return false;
            }

            let reply_ref = unsafe { &mut *request_ref.reply };
            unsafe {
                fr::fr_pair_make(
                    request_ref.reply.cast::<c_void>(),
                    ptr::addr_of_mut!(reply_ref.vps),
                    pair.key,
                    pair.value,
                    T_OP_EQ,
                )
            }
        };

        if added.is_null() {
            return false;
        }
    }

    true
}

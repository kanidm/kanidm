//! This is based on the example module in the FreeRADIUS source, but rewritten in Rust. The module implements the Authorize method, which is called during the authorization phase of the RADIUS request processing. The module reads configuration from the FreeRADIUS configuration file, and uses a Rust library to perform the actual authorization logic. The module also demonstrates how to read attributes from the RADIUS request, and how to add attributes to the reply and control sections of the request.
//!
//! - [FreeRADIUS module page](https://wiki.freeradius.org/contributing/Modules)
//! - [Example module source](https://github.com/jacques/freeradius/blob/master/src/modules/rlm_example/rlm_example.c)

use crate::{KVPair, ModuleHandle};
use libc::c_char;
use std::ffi::{CStr, CString};
use std::mem::{offset_of, size_of};
use std::os::raw::{c_int, c_void};
use std::ptr;

#[allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]
mod fr {
    include!(concat!(env!("OUT_DIR"), "/freeradius_bindings.rs"));
}

#[repr(C)]
struct RlmKanidmInstance {
    config_path: *const c_char,
    rust_handle: *mut ModuleHandle,
}

struct OwnedPair {
    key: CString,
    value: CString,
}

const CONFIG_PATH_KEY: &[u8] = b"config_path\0";
const DEFAULT_CONFIG_PATH: &[u8] = b"/data/kanidm\0";
//
const MODULE_NAME: &[u8] = b"kanidm\0";

const MODULE_METHODS: [fr::rlm_kanidm_packetmethod_t; fr::RLM_KANIDM_MOD_COUNT as usize] = {
    let mut methods: [fr::rlm_kanidm_packetmethod_t; fr::RLM_KANIDM_MOD_COUNT as usize] =
        [None; fr::RLM_KANIDM_MOD_COUNT as usize];
    methods[fr::RLM_KANIDM_MOD_AUTHORIZE as usize] =
        Some(mod_authorize as unsafe extern "C" fn(*mut c_void, *mut fr::REQUEST) -> _);
    methods
};

static mut MODULE_CONFIG: [fr::rlm_kanidm_conf_parser_t; 2] = [
    fr::rlm_kanidm_conf_parser_t {
        name: CONFIG_PATH_KEY.as_ptr().cast(),
        type_: fr::RLM_KANIDM_PW_TYPE_STRING as c_int,
        offset: offset_of!(RlmKanidmInstance, config_path),
        data: ptr::null_mut(),
        dflt: DEFAULT_CONFIG_PATH.as_ptr().cast(),
    },
    fr::rlm_kanidm_conf_parser_t {
        name: ptr::null(),
        type_: -1,
        offset: 0,
        data: ptr::null_mut(),
        dflt: ptr::null(),
    },
];

#[unsafe(no_mangle)]
#[used]
pub static mut rlm_kanidm: fr::rlm_kanidm_module_t = fr::rlm_kanidm_module_t {
    magic: fr::RLM_KANIDM_RLM_MODULE_INIT as u64,
    name: MODULE_NAME.as_ptr().cast(),
    type_: fr::RLM_KANIDM_RLM_TYPE_THREAD_SAFE as c_int,
    inst_size: size_of::<RlmKanidmInstance>(),
    config: ptr::addr_of!(MODULE_CONFIG).cast(),
    bootstrap: None,
    instantiate: Some(mod_instantiate),
    detach: Some(mod_detach),
    methods: MODULE_METHODS,
};

const fn fail_code() -> fr::rlm_rcode_t {
    fr::RLM_KANIDM_MODULE_FAIL as fr::rlm_rcode_t
}

/// the instantiate method is called when the module is loaded, and should return 0 on success. The instance pointer is a pointer to a block of memory of size `inst_size`, which can be used to store module state. The config pointer is a pointer to the module configuration, which is parsed according to the `config` field of the module struct.
unsafe extern "C" fn mod_instantiate(_conf: *mut c_void, instance: *mut c_void) -> c_int {
    if instance.is_null() {
        return -1;
    }

    let inst = unsafe { &mut *(instance.cast::<RlmKanidmInstance>()) };
    if inst.config_path.is_null() {
        tracing::error!("rlm_kanidm: config_path missing");
        return -1;
    }

    let handle = crate::rlm_kanidm_instantiate(inst.config_path);
    if handle.is_null() {
        tracing::error!("rlm_kanidm: rust instantiate failed");
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
        unsafe { crate::rlm_kanidm_detach(inst.rust_handle) };
        inst.rust_handle = ptr::null_mut();
    }

    0
}

unsafe extern "C" fn mod_authorize(
    instance: *mut c_void,
    request: *mut fr::REQUEST,
) -> fr::rlm_rcode_t {
    if instance.is_null() || request.is_null() {
        return fail_code();
    }

    let inst = unsafe { &mut *(instance.cast::<RlmKanidmInstance>()) };
    if inst.rust_handle.is_null() {
        tracing::error!("rlm_kanidm not initialised");
        return fail_code();
    }

    let owned_pairs = unsafe { collect_request_attrs(request) };
    let raw_pairs = build_raw_pairs(&owned_pairs);

    let auth_result = unsafe {
        crate::rlm_kanidm_authorize(inst.rust_handle, raw_pairs.as_ptr(), raw_pairs.len())
    };

    if !auth_result.error.is_null() {
        let message = unsafe { CStr::from_ptr(auth_result.error) }.to_string_lossy();
        tracing::error!("rlm_kanidm authorize error: {message}");
    }

    let reply_ok =
        unsafe { add_pairs_to_request(request, auth_result.reply, auth_result.reply_len, false) };
    if !reply_ok {
        crate::rlm_kanidm_free_auth_result(auth_result);
        return fail_code();
    }

    let control_ok = unsafe {
        add_pairs_to_request(request, auth_result.control, auth_result.control_len, true)
    };
    if !control_ok {
        crate::rlm_kanidm_free_auth_result(auth_result);
        return fail_code();
    }

    let code = auth_result.code as fr::rlm_rcode_t;
    crate::rlm_kanidm_free_auth_result(auth_result);
    code
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
            let mut value_buf = [0 as c_char; 4096];
            unsafe {
                fr::vp_prints_value(
                    value_buf.as_mut_ptr(),
                    value_buf.len(),
                    pair,
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
                    fr::RLM_KANIDM_T_OP_EQ as fr::FR_TOKEN,
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
                    fr::RLM_KANIDM_T_OP_EQ as fr::FR_TOKEN,
                )
            }
        };

        if added.is_null() {
            return false;
        }
    }

    true
}

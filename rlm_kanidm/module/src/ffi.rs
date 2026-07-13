//! Externally Facing Symbols - This is what we export to FreeRADIUS to call into us
//! to drive the operation of the rlm_kanidm module.

use crate::glue::{rlm_kanidm_authorise, rlm_kanidm_instantiate, ModuleHandle};
use crate::logic::{
    AuthError, AuthRequest, AuthResponse, ResponseControlAttributes, ResponseReplyAttributes,
};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::marker::PhantomData;
use std::mem::offset_of;
use std::ptr;

use crate::freeradius::{
    conf_part, dict_attr, fr_cursor_init, fr_cursor_next, fr_pair_make,
    fr_token_t::T_OP_EQ,
    module_t, packetmethod as packetmethod_t,
    rlm_components::{MOD_AUTHORIZE, MOD_COUNT},
    rlm_kanidm_module, rlm_rcode_t,
    rlm_rcodes::{self, RLM_MODULE_FAIL, RLM_MODULE_OK},
    value_pair, vp_cursor_t, vp_prints_value, CONF_PARSER,
    PW_TYPE::PW_TYPE_STRING,
    REQUEST, RLM_TYPE_THREAD_SAFE,
};

// From rlm_kanidm.c
unsafe extern "C" {
    pub unsafe fn rlm_kanidm_rdebug(message: *const c_char, request: &mut REQUEST) -> ();

    pub unsafe fn rlm_kanidm_rinfo(message: *const c_char, request: &mut REQUEST) -> ();

    pub unsafe fn rlm_kanidm_rerror(message: *const c_char, request: &mut REQUEST) -> ();
}

const ATTR_USER_NAME: &str = "User-Name";
const ATTR_TLS_CN: &str = "TLS-Client-Cert-Common-Name";
const ATTR_TLS_SAN_DN_CN: &str = "TLS-Client-Cert-Subject-Alt-Name-Directory-Name-Common-Name";

const REPLY_USER_NAME: &CStr = c"User-Name";
const REPLY_MESSAGE: &CStr = c"Reply-Message";
const REPLY_TUNNEL_TYPE: &CStr = c"Tunnel-Type";
const REPLY_TUNNEL_MEDIUM_TYPE: &CStr = c"Tunnel-Medium-Type";
const REPLY_TUNNEL_PRIVATE_GROUP_ID: &CStr = c"Tunnel-Private-Group-ID";

const CONTROL_CLEARTEXT_PASSWORD: &CStr = c"Cleartext-Password";

const CONFIG_PATH_KEY: &CStr = c"config_path";
const DEFAULT_CONFIG_PATH: &CStr = c"/data/radius.toml";
const MODULE_NAME: &CStr = c"kanidm";

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

#[repr(C)]
struct RlmKanidmInstance {
    config_path: *const c_char,
    handle: *mut ModuleHandle,
}

static mut MODULE_CONFIG: [CONF_PARSER; 2] = [
    CONF_PARSER {
        name: CONFIG_PATH_KEY.as_ptr(),
        type_: PW_TYPE_STRING as c_int,
        offset: offset_of!(RlmKanidmInstance, config_path),
        data: ptr::null_mut(),
        dflt: DEFAULT_CONFIG_PATH.as_ptr().cast(),
    },
    CONF_PARSER {
        name: ptr::null(),
        type_: -1,
        offset: 0,
        data: ptr::null_mut(),
        dflt: ptr::null(),
    },
];

const MODULE_METHODS: [packetmethod_t; MOD_COUNT as usize] = {
    let mut methods: [packetmethod_t; MOD_COUNT as usize] = [None; MOD_COUNT as usize];

    // Add our registered methods to the table.
    methods[MOD_AUTHORIZE as usize] = Some(mod_authorise);

    methods
};

unsafe extern "C" fn mod_instantiate(_conf: *mut conf_part, instance_ptr: *mut c_void) -> c_int {
    let instance_ptr: *mut RlmKanidmInstance = instance_ptr as _;

    // The purpose of these functions is to be the thinest possibly layer that converts
    // from unsafe C types into safe (albeit lowlevel) rust types. These then are sent
    // to the ffi layer which handles most of the interaction and is somewhat radius aware.
    let Some(instance) = instance_ptr.as_mut() else {
        return -1;
    };

    let config_path = if !instance.config_path.is_null() {
        unsafe { CStr::from_ptr(instance.config_path) }
    } else {
        DEFAULT_CONFIG_PATH
    };

    let Ok(path) = config_path.to_str() else {
        return -1;
    };

    match rlm_kanidm_instantiate(path) {
        Ok(module_handle) => {
            let handle = Box::new(module_handle);
            instance.handle = Box::into_raw(handle);
            0
        }
        Err(_) => -1,
    }
}

unsafe extern "C" fn mod_detach(instance_ptr: *mut c_void) -> c_int {
    let instance_ptr: *mut RlmKanidmInstance = instance_ptr as _;

    let Some(instance) = instance_ptr.as_mut() else {
        return 0;
    };

    if !instance.handle.is_null() {
        unsafe {
            let _ = Box::from_raw(instance.handle);
            instance.handle = ptr::null_mut();
        }
    }

    0
}

unsafe extern "C" fn mod_authorise(
    instance_ptr: *mut c_void,
    request: *mut REQUEST,
) -> rlm_rcode_t {
    let instance_ptr: *mut RlmKanidmInstance = instance_ptr as _;

    let talloc_ctx = request as *mut c_void;

    let Some(request) = request.as_mut() else {
        return RLM_MODULE_FAIL;
    };

    rdebug("mod_authorise: begin", request);

    let Some(instance) = instance_ptr.as_ref() else {
        rerror("mod_authorise: invalid instance_ptr", request);
        return RLM_MODULE_FAIL;
    };

    let Some(module_handle) = instance.handle.as_ref() else {
        rerror("mod_authorise: invalid module handle", request);
        return RLM_MODULE_FAIL;
    };

    let auth_request = match AuthRequest::new(request) {
        Ok(auth_request) => auth_request,
        Err(auth_error) => {
            rerror(
                "mod_authorise: auth_request was unable to be constructed",
                request,
            );
            return auth_error.into();
        }
    };

    let auth_response = match rlm_kanidm_authorise(auth_request, module_handle) {
        Ok(auth_response) => auth_response,
        Err(auth_error) => {
            rerror("mod_authorise: rlm_kanidm_authorise failed", request);
            return auth_error.into();
        }
    };

    match auth_response.populate_request(request, talloc_ctx) {
        Ok(()) => RLM_MODULE_OK,
        Err(auth_error) => {
            rerror(
                "mod_authorise: unable to populate return values to radius",
                request,
            );
            auth_error.into()
        }
    }
}

#[derive(Debug, Clone, Default)]
struct AuthRequestBuilder {
    pub tls_san_dn_cn: Option<String>,
    pub tls_cn: Option<String>,
    pub user_name: Option<String>,
    #[allow(dead_code)]
    pub attrs: BTreeMap<String, String>,
}

impl<'a> AuthRequest<'a> {
    fn new(request: &'a mut REQUEST) -> Result<Self, AuthError> {
        if request.packet.is_null() {
            return Err(AuthError::Fail);
        }

        let mut request_builder = AuthRequestBuilder::default();
        let mut cursor = unsafe { std::mem::zeroed::<vp_cursor_t>() };

        let request_vp: *const *mut value_pair = unsafe { &(*request.packet).vps as *const _ };

        let mut pair = unsafe { fr_cursor_init(&mut cursor, request_vp) };

        while !pair.is_null() {
            let key_ptr = unsafe {
                let dict_attr: *const dict_attr = (*pair).da;
                if dict_attr.is_null() {
                    ptr::null()
                } else {
                    // NOTE: This is incorrectly a [u8; 1], maybe it's a VLA. That's
                    // why this weird looking cast exists.
                    ptr::addr_of!((*dict_attr).name).cast::<c_char>()
                }
            };

            if !key_ptr.is_null() {
                let mut value_buf = [0 as u8; 4096];
                unsafe {
                    vp_prints_value(
                        value_buf.as_mut_ptr() as *mut c_char,
                        value_buf.len(),
                        pair,
                        // Quote character to be added before and after the value. default/0 for no quoting
                        c_char::default(),
                    )
                };

                let key = unsafe {
                    CStr::from_ptr(key_ptr)
                        .to_str()
                        .map(String::from)
                        .map_err(|_| AuthError::Fail)?
                };

                let value: String = CStr::from_bytes_until_nul(&value_buf)
                    .map_err(|_| AuthError::Fail)
                    .and_then(|cstr| {
                        cstr.to_str().map(String::from).map_err(|_| AuthError::Fail)
                    })?;

                // Choose how to handle the key.
                match key.as_str() {
                    ATTR_TLS_SAN_DN_CN => request_builder.tls_san_dn_cn = Some(value),
                    ATTR_TLS_CN => request_builder.tls_cn = Some(value),
                    ATTR_USER_NAME => request_builder.user_name = Some(value),
                    _ => {
                        request_builder.attrs.insert(key, value);
                    }
                };
            }

            pair = unsafe { fr_cursor_next(&mut cursor) };
        }

        let AuthRequestBuilder {
            tls_san_dn_cn,
            tls_cn,
            user_name,
            attrs,
        } = request_builder;

        Ok(AuthRequest {
            tls_san_dn_cn,
            tls_cn,
            user_name,
            attrs,
            phantom: PhantomData,
            request,
        })
    }

    pub fn error(&mut self, message: &str) {
        rerror(message, self.request)
    }

    pub fn info(&mut self, message: &str) {
        rinfo(message, self.request)
    }

    pub fn debug(&mut self, message: &str) {
        rdebug(message, self.request)
    }
}

impl AuthResponse {
    fn populate_request(
        self,
        request: &mut REQUEST,
        talloc_ctx: *mut c_void,
    ) -> Result<(), AuthError> {
        if request.reply.is_null() {
            return Err(AuthError::Fail);
        }

        let AuthResponse { control, reply } = self;

        let control_vp: *mut *mut value_pair = &mut request.config as *mut _;
        let reply_vp: *mut *mut value_pair = unsafe { &mut (*request.reply).vps as *mut _ };

        // Control Attributes
        let ResponseControlAttributes { cleartext_password } = control;

        if let Some(cleartext_password) = cleartext_password {
            vp_add_pair(
                talloc_ctx,
                control_vp,
                CONTROL_CLEARTEXT_PASSWORD,
                cleartext_password.as_str(),
            )?;
        }

        // Reply Attributes
        let ResponseReplyAttributes {
            user_name,
            message,
            tunnel_type,
            tunnel_medium_type,
            tunnel_private_group_id,
        } = reply;

        vp_add_pair(talloc_ctx, reply_vp, REPLY_USER_NAME, user_name.as_str())?;
        vp_add_pair(talloc_ctx, reply_vp, REPLY_MESSAGE, message.as_str())?;
        vp_add_pair(talloc_ctx, reply_vp, REPLY_TUNNEL_TYPE, tunnel_type)?;
        vp_add_pair(
            talloc_ctx,
            reply_vp,
            REPLY_TUNNEL_MEDIUM_TYPE,
            tunnel_medium_type,
        )?;
        vp_add_pair(
            talloc_ctx,
            reply_vp,
            REPLY_TUNNEL_PRIVATE_GROUP_ID,
            tunnel_private_group_id.as_str(),
        )?;

        Ok(())
    }
}

fn vp_add_pair(
    talloc_ctx: *mut c_void,
    vp: *mut *mut value_pair,
    key: &CStr,
    value: &str,
) -> Result<(), AuthError> {
    let value = CString::new(value).map_err(|_| AuthError::Fail)?;

    let key_c = key.as_ptr();
    let value_c = value.as_ptr();

    // NOTE: This strcpy's the value, so we don't need to do any memory management dances.
    let return_code = unsafe { fr_pair_make(talloc_ctx, vp, key_c, value_c, T_OP_EQ) };

    if return_code.is_null() {
        Err(AuthError::Fail)
    } else {
        Ok(())
    }
}

impl Into<rlm_rcode_t> for AuthError {
    fn into(self) -> rlm_rcode_t {
        match self {
            AuthError::Reject => rlm_rcodes::RLM_MODULE_REJECT,
            AuthError::Fail => rlm_rcodes::RLM_MODULE_FAIL,
            AuthError::Handled => rlm_rcodes::RLM_MODULE_HANDLED,
            AuthError::Invalid => rlm_rcodes::RLM_MODULE_INVALID,
            AuthError::UserLock => rlm_rcodes::RLM_MODULE_USERLOCK,
            AuthError::NotFound => rlm_rcodes::RLM_MODULE_NOTFOUND,
            AuthError::NoOp => rlm_rcodes::RLM_MODULE_NOOP,
            AuthError::Updated => rlm_rcodes::RLM_MODULE_UPDATED,
        }
    }
}

fn rerror(message: &str, request: &mut REQUEST) -> () {
    if let Ok(message) = CString::new(message) {
        unsafe { rlm_kanidm_rerror(message.as_ptr(), request) };
    } else {
        unsafe { rlm_kanidm_rerror(c"BUG: INVALID MESSAGE".as_ptr(), request) };
    }
}

fn rinfo(message: &str, request: &mut REQUEST) -> () {
    if let Ok(message) = CString::new(message) {
        unsafe { rlm_kanidm_rinfo(message.as_ptr(), request) };
    } else {
        unsafe { rlm_kanidm_rerror(c"BUG: INVALID MESSAGE".as_ptr(), request) };
    }
}

fn rdebug(message: &str, request: &mut REQUEST) -> () {
    if let Ok(message) = CString::new(message) {
        unsafe { rlm_kanidm_rdebug(message.as_ptr(), request) };
    } else {
        unsafe { rlm_kanidm_rerror(c"BUG: INVALID MESSAGE".as_ptr(), request) };
    }
}

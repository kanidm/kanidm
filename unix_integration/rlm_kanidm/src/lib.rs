//! A FreeRADIUS module for Kanidm authentication and authorization.
//!
//! Here be unsafe dragons.

#![deny(warnings)]
#![deny(deprecated)]
#![recursion_limit = "512"]
#![warn(unused_extern_crates)]
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![deny(clippy::indexing_slicing)]
#![allow(clippy::unreachable)]

use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder, StatusCode};
use kanidm_proto::internal::{Group, RadiusAuthToken};
use libc::c_char;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

#[cfg(feature = "freeradius-module")]
mod freeradius;

const ATTR_USER_NAME: &str = "User-Name";
const ATTR_TLS_CN: &str = "TLS-Client-Cert-Common-Name";
const ATTR_TLS_SAN_DN_CN: &str = "TLS-Client-Cert-Subject-Alt-Name-Directory-Name-Common-Name";

const REPLY_USER_NAME: &str = "User-Name";
const REPLY_MESSAGE: &str = "Reply-Message";
const REPLY_TUNNEL_TYPE: &str = "Tunnel-Type";
const REPLY_TUNNEL_MEDIUM_TYPE: &str = "Tunnel-Medium-Type";
const REPLY_TUNNEL_PRIVATE_GROUP_ID: &str = "Tunnel-Private-Group-ID";
const CONTROL_CLEARTEXT_PASSWORD: &str = "Cleartext-Password";

/// RADIUS response codes as expected by FreeRADIUS.
/// ```rust
/// use rlm_kanidm::Response;
/// assert_eq!(Response::Reject as i32, 0);
/// assert_eq!(Response::Fail as i32, 1);
/// assert_eq!(Response::Ok as i32, 2);
/// assert_eq!(Response::Handled as i32, 3);
///
///
/// ```
#[repr(i32)]
pub enum Response {
    Reject = 0,
    Fail = 1,
    Ok = 2,
    Handled = 3,
    Invalid = 4,
    UserLock = 5,
    NotFound = 6,
    NoOp = 7,
    Updated = 8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RadiusGroupConfig {
    pub spn: String,
    pub vlan: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RadiusClientConfig {
    pub name: String,
    pub ipaddr: String,
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct KanidmRadiusConfig {
    pub uri: String,
    pub auth_token: String,
    #[serde(default = "default_bool_true")]
    pub verify_hostnames: bool,
    #[serde(default = "default_bool_true")]
    pub verify_certificate: bool,

    #[serde(default)]
    pub ca_path: Option<String>,

    #[serde(default)]
    pub radius_required_groups: Vec<String>,
    #[serde(default = "default_vlan")]
    /// Defaults to 1, which is the default VLAN for "no VLAN" in many RADIUS setups, but can be set to 0 if the setup expects that for "no VLAN". Any user in a group that doesn't have a specific VLAN mapping will get this VLAN.
    pub radius_default_vlan: u32,
    #[serde(default)]
    pub radius_groups: Vec<RadiusGroupConfig>,
    #[serde(default)]
    pub radius_clients: Vec<RadiusClientConfig>,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

fn default_bool_true() -> bool {
    true
}

fn default_vlan() -> u32 {
    1
}

fn default_connect_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Clone)]
pub struct ModuleOptions {
    pub http_timeout: Duration,
    pub cache_ttl: Duration,
    pub cache_stale_if_error: Duration,
    pub cache_max_entries: usize,
}

impl Default for ModuleOptions {
    fn default() -> Self {
        Self {
            http_timeout: Duration::from_secs(5),
            cache_ttl: Duration::from_secs(30),
            cache_stale_if_error: Duration::from_secs(120),
            cache_max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestAttributes {
    attrs: BTreeMap<String, String>,
}

impl RequestAttributes {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let attrs = pairs.into_iter().collect();
        Self { attrs }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }

    pub fn user_id(&self) -> Option<&str> {
        self.get(ATTR_TLS_SAN_DN_CN)
            .or_else(|| self.get(ATTR_TLS_CN))
            .or_else(|| self.get(ATTR_USER_NAME))
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    pub code: i32,
    pub reply: Vec<(String, String)>,
    pub control: Vec<(String, String)>,
}

impl AuthorizeResult {
    fn new(code: Response) -> Self {
        Self {
            code: code as i32,
            reply: Vec::new(),
            control: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct CacheEntry {
    token: RadiusAuthToken,
    fetched_at: Instant,
}

impl CacheEntry {
    /// Duration since this entry was pulled from Kanidm
    fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.fetched_at)
    }

    /// If it's less than the TTL
    fn fresh(&self, now: Instant, ttl: Duration) -> bool {
        self.age(now) <= ttl
    }

    /// If it's past the TTL but within the stale window
    fn stale_allowed(&self, now: Instant, ttl: Duration, stale_window: Duration) -> bool {
        let age = self.age(now);
        age > ttl && age <= ttl.saturating_add(stale_window)
    }
}

#[derive(Debug)]
pub enum ModuleError {
    Io(String),
    Config(String),
    Http(String),
    Other(String),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "IO Error: {s}"),
            Self::Config(s) => write!(f, "Config Error: {s}"),
            Self::Http(s) => write!(f, "HTTP Error: {s}"),
            Self::Other(s) => write!(f, "Internal Error: {s}"),
        }
    }
}

impl From<ModuleError> for AuthResultC {
    fn from(input: ModuleError) -> AuthResultC {
        auth_error(Response::Fail, input.to_string())
    }
}

impl std::error::Error for ModuleError {}

pub struct Module {
    cfg: KanidmRadiusConfig,
    required_groups: BTreeSet<String>,
    vlan_by_spn: BTreeMap<String, u32>,
    cache: Mutex<BTreeMap<String, CacheEntry>>,
    client: KanidmClient,
    runtime: Runtime,
    options: ModuleOptions,
}

impl Module {
    pub fn from_config_path(path: &str, options: ModuleOptions) -> Result<Arc<Self>, ModuleError> {
        let config_text = fs::read_to_string(path)
            .map_err(|e| ModuleError::Io(format!("failed reading config {path}: {e}")))?;
        let cfg: KanidmRadiusConfig = toml::from_str(&config_text)
            .map_err(|e| ModuleError::Config(format!("failed parsing TOML {path}: {e}")))?;
        Self::from_config(cfg, options)
    }

    pub fn from_config(
        cfg: KanidmRadiusConfig,
        options: ModuleOptions,
    ) -> Result<Arc<Self>, ModuleError> {
        if cfg.uri.trim().is_empty() {
            return Err(ModuleError::Config("uri must not be empty".to_string()));
        }
        if cfg.auth_token.trim().is_empty() {
            return Err(ModuleError::Config(
                "auth_token must not be empty".to_string(),
            ));
        }

        let runtime = Runtime::new()
            .map_err(|e| ModuleError::Config(format!("Failed creating tokio runtime: {e}")))?;

        let timeout_secs = options.http_timeout.as_secs().max(cfg.connect_timeout_secs);
        let mut client_builder = KanidmClientBuilder::new()
            .address(cfg.uri.clone())
            .danger_accept_invalid_hostnames(!cfg.verify_hostnames)
            .danger_accept_invalid_certs(!cfg.verify_certificate)
            .connect_timeout(timeout_secs)
            .request_timeout(timeout_secs);
        if let Some(ca_path) = cfg.ca_path.as_deref() {
            client_builder = client_builder
                .add_root_certificate_filepath(ca_path)
                .map_err(|e| {
                    ModuleError::Config(format!(
                        "Failed loading ca_path {ca_path} into KanidmClientBuilder: {e:?}"
                    ))
                })?;
        }

        let client = client_builder
            .build()
            .map_err(|e| ModuleError::Http(format!("Failed creating KanidmClient: {e:?}")))?;

        runtime.block_on(client.set_token(cfg.auth_token.clone()));

        let required_groups: BTreeSet<String> =
            cfg.radius_required_groups.iter().cloned().collect();
        let vlan_by_spn = cfg
            .radius_groups
            .iter()
            .map(|g| (g.spn.clone(), g.vlan))
            .collect::<BTreeMap<_, _>>();

        Ok(Arc::new(Self {
            cfg,
            required_groups,
            vlan_by_spn,
            cache: Mutex::new(BTreeMap::new()),
            client,
            runtime,
            options,
        }))
    }

    pub fn authorize(&self, attrs: &RequestAttributes) -> AuthorizeResult {
        let Some(user_id) = attrs.user_id() else {
            return AuthorizeResult::new(Response::Invalid);
        };

        let token_result = self.fetch_token_with_cache(user_id);
        let token = match token_result {
            Ok(Some(tok)) => tok,
            Ok(None) => return AuthorizeResult::new(Response::NotFound),
            Err(_) => return AuthorizeResult::new(Response::Fail),
        };

        if !self.user_in_required_groups(&token.groups) {
            return AuthorizeResult::new(Response::Reject);
        }

        let selected_vlan = self.resolve_vlan(&token.groups);
        let mut result = AuthorizeResult::new(Response::Ok);
        result
            .reply
            .push((REPLY_USER_NAME.to_string(), token.name.clone()));
        result.reply.push((
            REPLY_MESSAGE.to_string(),
            format!("Kanidm-Uuid: {}", token.uuid),
        ));
        result
            .reply
            .push((REPLY_TUNNEL_TYPE.to_string(), "13".to_string()));
        result
            .reply
            .push((REPLY_TUNNEL_MEDIUM_TYPE.to_string(), "6".to_string()));
        result.reply.push((
            REPLY_TUNNEL_PRIVATE_GROUP_ID.to_string(),
            selected_vlan.to_string(),
        ));
        result
            .control
            .push((CONTROL_CLEARTEXT_PASSWORD.to_string(), token.secret.clone()));
        result
    }

    fn user_in_required_groups(&self, user_groups: &[Group]) -> bool {
        user_groups.iter().any(|group| {
            self.required_groups.contains(&group.uuid) || self.required_groups.contains(&group.spn)
        })
    }

    fn resolve_vlan(&self, user_groups: &[Group]) -> u32 {
        let mut vlan = self.cfg.radius_default_vlan;
        for group in user_groups {
            if let Some(mapped_vlan) = self.vlan_by_spn.get(&group.spn) {
                vlan = *mapped_vlan;
            }
        }
        vlan
    }

    fn fetch_token_with_cache(
        &self,
        user_id: &str,
    ) -> Result<Option<RadiusAuthToken>, ModuleError> {
        let now = Instant::now();

        if let Some(cached) = self.lookup_cache(user_id, now) {
            return Ok(Some(cached));
        }

        match self.runtime.block_on(self.fetch_token_http(user_id))? {
            Some(token) => {
                self.insert_cache(user_id.to_string(), token.clone(), now);
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    fn lookup_cache(&self, user_id: &str, now: Instant) -> Option<RadiusAuthToken> {
        let Ok(cache_guard) = self.cache.lock() else {
            return None;
        };
        let entry = cache_guard.get(user_id)?;
        if entry.fresh(now, self.options.cache_ttl) {
            return Some(entry.token.clone());
        }
        None
    }

    fn lookup_stale_cache(&self, user_id: &str, now: Instant) -> Option<RadiusAuthToken> {
        let Ok(cache_guard) = self.cache.lock() else {
            return None;
        };
        let entry = cache_guard.get(user_id)?;
        if entry.stale_allowed(
            now,
            self.options.cache_ttl,
            self.options.cache_stale_if_error,
        ) {
            return Some(entry.token.clone());
        }
        None
    }

    fn insert_cache(&self, user_id: String, token: RadiusAuthToken, now: Instant) {
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= self.options.cache_max_entries && !guard.contains_key(&user_id) {
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, entry)| entry.fetched_at)
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&oldest_key);
                }
            }
            guard.insert(
                user_id,
                CacheEntry {
                    token,
                    fetched_at: now,
                },
            );
        }
    }

    async fn fetch_token_http(
        &self,
        user_id: &str,
    ) -> Result<Option<RadiusAuthToken>, ModuleError> {
        match self.client.idm_account_radius_token_get(user_id).await {
            Ok(token) => Ok(Some(token)),
            Err(ClientError::Http(status, _, _)) if status == StatusCode::NOT_FOUND => Ok(None),
            Err(error) => {
                let now = Instant::now();
                if let Some(stale) = self.lookup_stale_cache(user_id, now) {
                    tracing::warn!("using stale cache token after upstream error");
                    return Ok(Some(stale));
                }
                Err(ModuleError::Http(format!(
                    "kanidm_client request failed: {error:?}"
                )))
            }
        }
    }
}

pub struct ModuleHandle {
    module: Arc<Module>,
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

pub(crate) fn cstr_to_string(ptr_in: *const c_char) -> Result<String, ModuleError> {
    if ptr_in.is_null() {
        return Err(ModuleError::Other("null string pointer".to_string()));
    }
    let cstr = unsafe { CStr::from_ptr(ptr_in) };
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|e| ModuleError::Other(format!("invalid utf-8 string: {e}")))
}

fn auth_result_from_pairs(
    code: i32,
    reply: Vec<(String, String)>,
    control: Vec<(String, String)>,
) -> AuthResultC {
    let reply_vec = into_kvpairs(reply);
    let control_vec = into_kvpairs(control);
    let reply_len = reply_vec.len();
    let control_len = control_vec.len();
    let mut reply_boxed = reply_vec.into_boxed_slice();
    let mut control_boxed = control_vec.into_boxed_slice();
    let reply_ptr = reply_boxed.as_mut_ptr();
    let control_ptr = control_boxed.as_mut_ptr();
    std::mem::forget(reply_boxed);
    std::mem::forget(control_boxed);
    AuthResultC {
        code,
        reply: reply_ptr,
        reply_len,
        control: control_ptr,
        control_len,
        error: ptr::null_mut(),
    }
}

fn into_kvpairs(pairs: Vec<(String, String)>) -> Vec<KVPair> {
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
fn auth_error(code: Response, message: String) -> AuthResultC {
    // At some point we just have to convert to a C string, and if that fails we can't do much about it, so it's fine to panic with a literal here
    #[allow(clippy::expect_used)]
    let c_message = CString::new(message)
        .unwrap_or_else(|_| CString::new("module error").expect("literal CString"));
    AuthResultC {
        code: code as i32,
        reply: ptr::null_mut(),
        reply_len: 0,
        control: ptr::null_mut(),
        control_len: 0,
        error: c_message.into_raw(),
    }
}

/// Instantiate module state from a config path.
#[unsafe(no_mangle)]
pub extern "C" fn rlm_kanidm_instantiate(config_path: *const c_char) -> *mut ModuleHandle {
    let Ok(path) = cstr_to_string(config_path) else {
        return ptr::null_mut();
    };
    match Module::from_config_path(&path, ModuleOptions::default()) {
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
pub unsafe extern "C" fn rlm_kanidm_detach(handle: *mut ModuleHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Authorize a request represented as key/value pairs.
///
/// # Safety
/// - `handle` must be a pointer returned from `rlm_kanidm_instantiate` and not yet freed by `rlm_kanidm_detach`.
/// - `request_attrs` must point to an array of `KVPair` of length `request_attrs_len`.
/// - The strings pointed to by `KVPair` must be valid null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rlm_kanidm_authorize(
    handle: *mut ModuleHandle,
    request_attrs: *const KVPair,
    request_attrs_len: usize,
) -> AuthResultC {
    if handle.is_null() {
        return auth_error(Response::Fail, "null module handle".to_string());
    }

    let attrs = match kvpairs_to_attributes(request_attrs, request_attrs_len) {
        Ok(v) => v,
        Err(e) => return e.into(),
    };

    let module = unsafe { &(*handle).module };
    let result = module.authorize(&attrs);
    auth_result_from_pairs(result.code, result.reply, result.control)
}

/// Free memory allocated in `AuthResultC`.
#[unsafe(no_mangle)]
pub extern "C" fn rlm_kanidm_free_auth_result(result: AuthResultC) {
    free_kv_pairs(result.reply, result.reply_len);
    free_kv_pairs(result.control, result.control_len);
    if !result.error.is_null() {
        unsafe {
            drop(CString::from_raw(result.error));
        }
    }
}

/// Helper to free an array of KVPair allocated in Rust and returned to C. This should be called for the `reply` and `control` fields of `AuthResultC` after the caller is done using them, to avoid memory leaks.
fn free_kv_pairs(ptr_pairs: *mut KVPair, len: usize) {
    if ptr_pairs.is_null() || len == 0 {
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
    let attrs_slice = if request_attrs_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_attrs, request_attrs_len) }
    };
    let mut attrs = BTreeMap::<String, String>::new();
    for pair in attrs_slice {
        let key = cstr_to_string(pair.key)?;
        let value = cstr_to_string(pair.value)?;
        attrs.insert(key, value);
    }
    Ok(RequestAttributes { attrs })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn sample_token(groups: Vec<Group>) -> RadiusAuthToken {
        RadiusAuthToken {
            name: "alice".to_string(),
            displayname: "Alice".to_string(),
            uuid: "u-1".to_string(),
            secret: "radius-secret".to_string(),
            groups,
        }
    }

    #[test]
    fn user_id_precedence() {
        let attrs = RequestAttributes::from_pairs(vec![
            (ATTR_USER_NAME.to_string(), "username".to_string()),
            (ATTR_TLS_CN.to_string(), "cn".to_string()),
            (ATTR_TLS_SAN_DN_CN.to_string(), "san".to_string()),
        ]);
        assert_eq!(attrs.user_id(), Some("san"));
    }

    #[test]
    fn vlan_last_match_wins() {
        let cfg = KanidmRadiusConfig {
            uri: "https://localhost:8443".to_string(),
            auth_token: "token".to_string(),
            ca_path: None,
            radius_required_groups: vec!["allow".to_string()],
            radius_default_vlan: 1,
            radius_groups: vec![
                RadiusGroupConfig {
                    spn: "g1".to_string(),
                    vlan: 10,
                },
                RadiusGroupConfig {
                    spn: "g2".to_string(),
                    vlan: 20,
                },
            ],
            radius_clients: Vec::new(),
            ..KanidmRadiusConfig::default()
        };

        let module = Module::from_config(cfg, ModuleOptions::default()).expect("module");
        let groups = vec![
            Group {
                spn: "g1".to_string(),
                uuid: "uuid-1".to_string(),
            },
            Group {
                spn: "g2".to_string(),
                uuid: "uuid-2".to_string(),
            },
        ];
        assert_eq!(module.resolve_vlan(&groups), 20);
    }

    #[test]
    fn required_group_by_spn_or_uuid() {
        let cfg = KanidmRadiusConfig {
            uri: "https://localhost:8443".to_string(),
            auth_token: "token".to_string(),
            ca_path: None,
            radius_required_groups: vec!["required-spn".to_string(), "required-uuid".to_string()],
            ..KanidmRadiusConfig::default()
        };
        let module = Module::from_config(cfg, ModuleOptions::default()).expect("module");

        let token_spn = sample_token(vec![Group {
            spn: "required-spn".to_string(),
            uuid: "x".to_string(),
        }]);
        assert!(module.user_in_required_groups(&token_spn.groups));

        let token_uuid = sample_token(vec![Group {
            spn: "other".to_string(),
            uuid: "required-uuid".to_string(),
        }]);
        assert!(module.user_in_required_groups(&token_uuid.groups));
    }

    #[test]
    fn cache_entry_timing_helpers() {
        let entry = CacheEntry {
            token: sample_token(Vec::new()),
            fetched_at: Instant::now() - Duration::from_secs(10),
        };
        let now = Instant::now();
        assert!(entry.fresh(now, Duration::from_secs(30)));
        assert!(!entry.fresh(now, Duration::from_secs(5)));
        assert!(entry.stale_allowed(now, Duration::from_secs(5), Duration::from_secs(10)));
    }

    #[test]
    fn test_parse_examples() {
        // let's make sure our provided examples actually parse!
        let config_files = vec!["radius.toml", "radius_full.toml"];
        for config_file in config_files {
            let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/")
                .join(config_file);
            if !config_path.exists() {
                panic!("example config file not found: {}", config_path.display());
            }
            let config_text =
                fs::read_to_string(&config_path).expect("failed to read example config file");
            let _cfg: KanidmRadiusConfig =
                toml::from_str(&config_text).expect("failed to parse config!");
        }
    }
}

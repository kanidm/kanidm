use crate::error::ModuleError;
use crate::logic::{AuthError, AuthRequest, AuthResponse, Module};
use concread::arcache::{ARCache, ARCacheBuilder};
use rlm_kanidm_shared::config::KanidmRadiusConfig;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

// The cache doesn't have to be huge, or have a long duration - it just
// needs to help debounce freeradius which calls out to the module a few
// times during every authorisation attempt.
const CACHE_EXPIRY: Duration = Duration::from_secs(60);
const CACHE_ITEMS: usize = 1024;

#[derive(Clone, Debug)]
struct CacheItem {
    expiry_time: Instant,
    response: Result<AuthResponse, AuthError>,
}

pub struct ModuleHandle {
    runtime: Runtime,
    module: Module,
    cache: ARCache<Option<String>, CacheItem>,
}

pub fn rlm_kanidm_instantiate<P: AsRef<Path>>(
    config_path: P, // config: KanidmRadiusConfig,
) -> Result<ModuleHandle, ModuleError> {
    let config = KanidmRadiusConfig::try_from(config_path.as_ref()).map_err(ModuleError::Io)?;

    let runtime = Runtime::new()
        .map_err(|err| ModuleError::Config(format!("Failed creating tokio runtime: {err:?}")))?;

    let module = runtime
        .block_on(Module::from_config(config))
        .map_err(|err| ModuleError::Config(format!("Failed creating radius module: {err:?}")))?;

    let cache = ARCacheBuilder::new()
        .set_size(CACHE_ITEMS, 0)
        .build()
        .ok_or_else(|| {
            ModuleError::Config(format!(
                "Failed creating radius module: cache build failure"
            ))
        })?;

    Ok(ModuleHandle {
        runtime,
        module,
        cache,
    })
}

pub fn rlm_kanidm_authorise(
    mut request: AuthRequest,
    module_handle: &ModuleHandle,
) -> Result<AuthResponse, AuthError> {
    // We cache the response of the module here which avoids the need to dip into
    // tokio which would introduce latency.
    //
    // The reason we cache here is because radius often requests the same information
    // repeatedly in quick succession. We can't rely on the freeradius cache module as
    // it seems to be broken every time I've tried it.

    let req_user_id = request.user_id().map(String::from);
    let now = Instant::now();

    let mut read_txn = module_handle.cache.read();

    if let Some(cache_item) = read_txn.get(&req_user_id) {
        if cache_item.expiry_time >= now {
            request.debug("cache hit");
            return cache_item.response.clone();
        }
    }

    let response = module_handle
        .runtime
        .block_on(module_handle.module.authorise(request));

    let expiry_time = now + CACHE_EXPIRY;

    let item = CacheItem {
        expiry_time,
        response: response.clone(),
    };

    read_txn.insert(req_user_id, item);

    response
}

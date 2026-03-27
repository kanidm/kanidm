use crate::error::ModuleError;
use crate::logic::{AuthError, AuthRequest, AuthResponse, Module};
use rlm_kanidm_shared::config::KanidmRadiusConfig;
use std::path::Path;
use tokio::runtime::Runtime;

pub struct ModuleHandle {
    runtime: Runtime,
    module: Module,
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

    Ok(ModuleHandle { runtime, module })
}

pub fn rlm_kanidm_authorise(
    request: AuthRequest,
    module_handle: &ModuleHandle,
) -> Result<AuthResponse, AuthError> {
    module_handle
        .runtime
        .block_on(module_handle.module.authorise(request))
}

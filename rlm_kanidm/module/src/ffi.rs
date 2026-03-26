//! FFI boundary - this is the translation layer between RLM C structures
//! and internal native rust types.

use crate::error::ModuleError;
use crate::{AuthError, AuthRequest, AuthResponse, Module, ModuleHandle};
use rlm_kanidm_shared::config::KanidmRadiusConfig;
use std::path::Path;

pub(crate) fn rlm_kanidm_instantiate<P: AsRef<Path>>(
    config_path: P, // config: KanidmRadiusConfig,
) -> Result<ModuleHandle, ModuleError> {
    let config = KanidmRadiusConfig::try_from(config_path.as_ref()).map_err(ModuleError::Io)?;

    Module::from_config(config).map(|module| ModuleHandle { module })
}

pub(crate) fn rlm_kanidm_authorise(
    request: AuthRequest,
    module_handle: &ModuleHandle,
) -> Result<AuthResponse, AuthError> {
    module_handle.module.authorise(&request)
}

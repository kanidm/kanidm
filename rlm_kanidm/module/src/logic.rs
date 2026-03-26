use crate::error::ModuleError;
use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder, StatusCode};
use kanidm_proto::internal::{Group, RadiusAuthToken};
use rlm_kanidm_shared::config::KanidmRadiusConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Runtime;

pub(crate) enum AuthError {
    Reject,
    Fail,
    Handled,
    Invalid,
    UserLock,
    NotFound,
    NoOp,
    Updated,
}

pub struct AuthResponse {
    pub reply: ResponseReplyAttributes,
    pub control: ResponseControlAttributes,
}

pub struct ResponseReplyAttributes {
    pub user_name: String,
    pub message: String,
    pub tunnel_type: &'static str,
    pub tunnel_medium_type: &'static str,
    pub tunnel_private_group_id: String,
}

pub struct ResponseControlAttributes {
    pub cleartext_password: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthRequest {
    pub tls_san_dn_cn: Option<String>,
    pub tls_cn: Option<String>,
    pub user_name: Option<String>,
    pub attrs: BTreeMap<String, String>,
}

impl AuthRequest {
    pub fn user_id(&self) -> Option<&str> {
        self.tls_san_dn_cn
            .as_deref()
            .or(self.tls_cn.as_deref())
            .or(self.user_name.as_deref())
    }
}

struct ModuleHandle {
    module: Arc<Module>,
}

struct Module {
    cfg: KanidmRadiusConfig,
    required_groups: BTreeSet<String>,
    vlan_by_spn: BTreeMap<String, u32>,
    client: KanidmClient,
    runtime: Runtime,
}

impl Module {
    fn from_config(cfg: KanidmRadiusConfig) -> Result<Arc<Self>, ModuleError> {
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

        // Should be in the config!
        // let timeout_secs = options.http_timeout.as_secs().max(cfg.connect_timeout_secs);

        let mut client_builder = KanidmClientBuilder::new()
            .address(cfg.uri.clone())
            .danger_accept_invalid_hostnames(!cfg.verify_hostnames)
            .danger_accept_invalid_certs(!cfg.verify_certificate);
        // .connect_timeout(timeout_secs)
        // .request_timeout(timeout_secs);
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
            client,
            runtime,
        }))
    }

    fn authorise(&self, request: &AuthRequest) -> Result<AuthResponse, AuthError> {
        let Some(user_id) = request.user_id() else {
            return Err(AuthError::Invalid);
        };

        let token_result = self.fetch_token(user_id);
        let token = match token_result {
            Ok(Some(tok)) => tok,
            Ok(None) => return Err(AuthError::NotFound),
            Err(_) => return Err(AuthError::Fail),
        };

        // TODO: Audit this.
        if !self.user_in_required_groups(&token.groups) {
            return Err(AuthError::Reject);
        }

        // TODO: Audit this too.
        let selected_vlan = self.resolve_vlan(&token.groups);

        let reply = ResponseReplyAttributes {
            user_name: token.name.clone(),
            message: format!("Kanidm-Uuid: {}", token.uuid),
            // TODO: Make these constants.
            tunnel_type: "13",
            tunnel_medium_type: "6",
            tunnel_private_group_id: selected_vlan.to_string(),
        };

        let control = ResponseControlAttributes {
            cleartext_password: Some(token.secret.clone()),
        };

        Ok(AuthResponse { reply, control })
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

    fn fetch_token(&self, user_id: &str) -> Result<Option<RadiusAuthToken>, ModuleError> {
        let lookup_result = self
            .runtime
            .block_on(self.client.idm_account_radius_token_get(user_id));

        match lookup_result {
            Ok(token) => Ok(Some(token)),
            Err(ClientError::Http(status, _, _)) if status == StatusCode::NOT_FOUND => Ok(None),
            Err(error) => Err(ModuleError::Http(format!(
                "kanidm_client request failed: {error:?}"
            ))),
        }
    }
}

pub fn rlm_kanidm_instantiate<P: AsRef<Path>>(
    config_path: P, // config: KanidmRadiusConfig,
) -> Result<ModuleHandle, ModuleError> {
    let config = KanidmRadiusConfig::try_from(config_path.as_ref()).map_err(ModuleError::Io)?;

    Module::from_config(config).map(|module| ModuleHandle { module })
}

pub fn rlm_kanidm_authorise(
    request: AuthRequest,
    module_handle: &ModuleHandle,
) -> Result<AuthResponse, AuthError> {
    module_handle.module.authorise(&request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlm_kanidm_shared::config::RadiusGroupConfig;
    use std::path::PathBuf;

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

        let module = Module::from_config(cfg).expect("module");
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
        let module = Module::from_config(cfg).expect("module");

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

            KanidmRadiusConfig::try_from(config_path.as_ref()).expect("failed to parse config!");
        }
    }

    #[kanidmd_testkit::test]
    async fn test_authorise_flow(_rsclient: &KanidmClient) {
        // todo!();
    }
}

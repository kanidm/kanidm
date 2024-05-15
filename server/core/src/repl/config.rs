use kanidm_lib_crypto::prelude::X509;
use kanidm_lib_crypto::serialise::x509b64::{self, cert_from_string};
use kanidm_proto::constants::{DEFAULT_REPLICATION_ADDRESS, DEFAULT_REPLICATION_ORIGIN};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use url::Url;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum RepNodeConfig {
    #[serde(rename = "allow-pull")]
    AllowPull {
        #[serde(with = "x509b64")]
        consumer_cert: X509,
    },
    #[serde(rename = "pull")]
    Pull {
        #[serde(with = "x509b64")]
        supplier_cert: X509,
        #[serde(default)]
        automatic_refresh: bool,
    },
    #[serde(rename = "mutual-pull")]
    MutualPull {
        #[serde(with = "x509b64")]
        partner_cert: X509,
        #[serde(default)]
        automatic_refresh: bool,
    },
    /*
    AllowPush {
    },
    Push {
    },
    */
}

impl RepNodeConfig {
    /// hacky workaround to check types from the CLI
    pub fn is_valid_type(input: &str) -> bool {
        match input {
            "allow-pull" | "pull" | "mutual-pull" => true,
            _ => false,
        }
    }
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct ReplicationConfiguration {
    /// Defaults to [kanidm_proto::constants::DEFAULT_REPLICATION_ORIGIN]
    pub origin: Url,
    /// Defaults to [kanidm_proto::constants::DEFAULT_REPLICATION_ADDRESS]
    pub bindaddress: SocketAddr,
    /// Number of seconds between running a replication event
    pub task_poll_interval: Option<u64>,

    #[serde(flatten)]
    pub manual: BTreeMap<Url, RepNodeConfig>,
}

impl Default for ReplicationConfiguration {
    fn default() -> Self {
        // we're using expect here because if we stuff it up, we did it at compile time
        #[allow(clippy::expect_used)]
        let origin: Url = Url::from_str(DEFAULT_REPLICATION_ORIGIN)
            .expect("Failed to parse default replication origin URL");
        #[allow(clippy::expect_used)]
        let bindaddress: SocketAddr = DEFAULT_REPLICATION_ADDRESS
            .parse()
            .expect("Failed to parse default replication bind address");
        Self {
            origin,
            bindaddress,
            task_poll_interval: None,
            manual: BTreeMap::new(),
        }
    }
}

const DEFAULT_REPL_TASK_POLL_INTERVAL: u64 = 15;

impl ReplicationConfiguration {
    /// Get the task poll interval, or the default if not set.
    pub(crate) fn get_task_poll_interval(&self) -> core::time::Duration {
        core::time::Duration::from_secs(
            self.task_poll_interval
                .unwrap_or(DEFAULT_REPL_TASK_POLL_INTERVAL),
        )
    }

    pub fn add_peer(&mut self, url: Url, config: RepNodeConfig) {
        self.manual.insert(url, config);
    }

    pub fn try_update_peer_from_cli(
        &mut self,
        _url: Url,
        _peer_type: Option<&str>,
        _peer_certificate: Option<&str>,
        _automatic_refresh: &Option<bool>,
    ) -> Result<(), String> {
        todo!("iterate through the options and update the config etc etc")
    }

    pub fn try_add_peer_from_cli(
        &mut self,
        url: Url,
        peer_type: &str,
        peer_certificate: &str,
        automatic_refresh: &bool,
    ) -> Result<(), String> {
        if !RepNodeConfig::is_valid_type(peer_type) {
            return Err(format!("Invalid peer type: {}", peer_type));
        }
        match peer_type {
            "allow-pull" => {
                let consumer_cert = match cert_from_string(&peer_certificate) {
                    Ok(c) => c,
                    Err(err) => return Err(format!("{:?}", err)),
                };

                let rep_node_config = RepNodeConfig::AllowPull { consumer_cert };
                self.add_peer(url, rep_node_config);
            }
            "pull" => {
                let supplier_cert = match cert_from_string(&peer_certificate) {
                    Ok(c) => c,
                    Err(err) => return Err(format!("{:?}", err)),
                };
                let rep_node_config = RepNodeConfig::Pull {
                    automatic_refresh: *automatic_refresh,
                    supplier_cert,
                };
                self.add_peer(url, rep_node_config);
            }
            "mutual-pull" => {
                let partner_cert = match cert_from_string(&peer_certificate) {
                    Ok(c) => c,
                    Err(err) => return Err(format!("{:?}", err)),
                };
                let rep_node_config = RepNodeConfig::MutualPull {
                    automatic_refresh: *automatic_refresh,
                    partner_cert,
                };
                self.add_peer(url, rep_node_config);
            }
            _ => return Err(format!("Invalid peer type: {}", peer_type)),
        }
        Ok(())
    }

    pub fn delete_peer(&mut self, url: &Url) -> bool {
        self.manual.remove(url).is_some()
    }

    pub fn validate_peer_uri(value: &str) -> Result<Url, String> {
        let peer_uri: Url = match value.parse() {
            Ok(u) => u,
            Err(e) => {
                error!("Invalid URI: {}", e);
                return Err(format!("Invalid URI: {:?}", e));
            }
        };

        if peer_uri.scheme().to_lowercase() != "repl" {
            error!("Only repl is supported as a URI scheme!");
            return Err("Only repl is supported as a URI scheme!".to_string());
        }

        Ok(peer_uri)
    }
}

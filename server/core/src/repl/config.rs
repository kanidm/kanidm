use kanidm_lib_crypto::prelude::X509;
use kanidm_lib_crypto::serialise::x509b64;
use kanidm_proto::constants::{DEFAULT_REPLICATION_ADDRESS, DEFAULT_REPLICATION_ORIGIN};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use url::Url;

#[derive(Deserialize, Debug, Clone)]
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

#[derive(Deserialize, Debug, Clone)]
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
}

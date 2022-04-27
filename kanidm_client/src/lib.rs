#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate tracing;

use serde::Deserialize;
use serde_json::error::Error as SerdeJsonError;
use std::fs::{metadata, File, Metadata};
use std::io::ErrorKind;
use std::io::Read;

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

use std::path::Path;
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

pub use reqwest::StatusCode;

use kanidm_proto::v1::*;

pub mod asynchronous;

pub use crate::asynchronous::KanidmAsyncClient;

pub const APPLICATION_JSON: &str = "application/json";
pub const KOPID: &str = "X-KANIDM-OPID";
pub const KSESSIONID: &str = "X-KANIDM-AUTH-SESSION-ID";

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    Http(reqwest::StatusCode, Option<OperationError>, String),
    Transport(reqwest::Error),
    AuthenticationFailed,
    EmptyResponse,
    TotpVerifyFailed(Uuid, TotpSecret),
    TotpInvalidSha1(Uuid),
    JsonDecode(reqwest::Error, String),
    JsonEncode(SerdeJsonError),
    SystemError,
}

#[derive(Debug, Deserialize)]
struct KanidmClientConfig {
    uri: Option<String>,
    verify_ca: Option<bool>,
    verify_hostnames: Option<bool>,
    ca_path: Option<String>,
    // Should we add username/pw later? They could be part of the builder
    // process ...
}

#[derive(Debug, Clone, Default)]
pub struct KanidmClientBuilder {
    address: Option<String>,
    verify_ca: bool,
    verify_hostnames: bool,
    ca: Option<reqwest::Certificate>,
    connect_timeout: Option<u64>,
    use_system_proxies: bool,
}

fn read_file_metadata<P: AsRef<Path>>(path: &P) -> Result<Metadata, ()> {
    metadata(path).map_err(|e| {
        error!(
            "Unable to read metadata for {} - {:?}",
            path.as_ref().to_str().unwrap_or("Alert: invalid path"),
            e
        );
    })
}

impl KanidmClientBuilder {
    pub fn new() -> Self {
        KanidmClientBuilder {
            address: None,
            verify_ca: true,
            verify_hostnames: true,
            ca: None,
            connect_timeout: None,
            use_system_proxies: true,
        }
    }

    fn parse_certificate(ca_path: &str) -> Result<reqwest::Certificate, ()> {
        let mut buf = Vec::new();
        // Is the CA secure?
        #[cfg(target_family = "windows")]
        warn!("File metadata checks on Windows aren't supported right now, this could be a security risk.");

        #[cfg(target_family = "unix")]
        {
            let path = Path::new(ca_path);
            let ca_meta = read_file_metadata(&path)?;

            if !ca_meta.permissions().readonly() {
                warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", ca_path);
            }

            #[cfg(target_family = "unix")]
            if ca_meta.uid() != 0 || ca_meta.gid() != 0 {
                warn!(
                    "{} should be owned be root:root to prevent tampering",
                    ca_path
                );
            }
        }

        // TODO #253: Handle these errors better, or at least provide diagnostics?
        let mut f = File::open(ca_path).map_err(|e| {
            error!(?e);
        })?;
        f.read_to_end(&mut buf).map_err(|e| {
            error!(?e);
        })?;
        reqwest::Certificate::from_pem(&buf).map_err(|e| {
            error!(?e);
        })
    }

    fn apply_config_options(self, kcc: KanidmClientConfig) -> Result<Self, ()> {
        let KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
            use_system_proxies,
        } = self;
        // Process and apply all our options if they exist.
        let address = match kcc.uri {
            Some(uri) => Some(uri),
            None => {
                debug!("No URI in config supplied to apply_config_options");
                address
            }
        };
        let verify_ca = kcc.verify_ca.unwrap_or(verify_ca);
        let verify_hostnames = kcc.verify_hostnames.unwrap_or(verify_hostnames);
        let ca = match kcc.ca_path {
            Some(ca_path) => Some(Self::parse_certificate(ca_path.as_str())?),
            None => ca,
        };

        Ok(KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
            use_system_proxies,
        })
    }

    #[allow(clippy::result_unit_err)]
    pub fn read_options_from_optional_config<P: AsRef<Path> + std::fmt::Debug>(
        self,
        config_path: P,
    ) -> Result<Self, ()> {
        debug!("Attempting to load configuration from {:#?}", &config_path);
        // If the file does not exist, we skip this function.
        let mut f = match File::open(&config_path) {
            Ok(f) => {
                debug!("Successfully opened configuration file {:#?}", &config_path);
                f
            }
            Err(e) => {
                match e.kind() {
                    ErrorKind::NotFound => {
                        debug!(
                            "Configuration file {:#?} not found, skipping.",
                            &config_path
                        );
                    }
                    ErrorKind::PermissionDenied => {
                        warn!(
                            "Permission denied loading configuration file {:#?}, skipping.",
                            &config_path
                        );
                    }
                    _ => {
                        debug!(
                            "Unable to open config file {:#?} [{:?}], skipping ...",
                            &config_path, e
                        );
                    }
                };
                return Ok(self);
            }
        };

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .map_err(|e| error!("{:?}", e))?;

        let config: KanidmClientConfig =
            toml::from_str(contents.as_str()).map_err(|e| error!("{:?}", e))?;

        self.apply_config_options(config)
    }

    pub fn address(self, address: String) -> Self {
        KanidmClientBuilder {
            address: Some(address),
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn danger_accept_invalid_hostnames(self, accept_invalid_hostnames: bool) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            // We have to flip the bool state here due to english language.
            verify_hostnames: !accept_invalid_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn danger_accept_invalid_certs(self, accept_invalid_certs: bool) -> Self {
        KanidmClientBuilder {
            address: self.address,
            // We have to flip the bool state here due to english language.
            verify_ca: !accept_invalid_certs,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn connect_timeout(self, secs: u64) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: Some(secs),
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn no_proxy(self) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: false,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn add_root_certificate_filepath(self, ca_path: &str) -> Result<Self, ()> {
        //Okay we have a ca to add. Let's read it in and setup.
        let ca = Self::parse_certificate(ca_path)?;

        Ok(KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: Some(ca),
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        })
    }

    fn display_warnings(&self, address: &str) {
        // Check for problems now
        if !self.verify_ca {
            warn!("verify_ca set to false in client configuration - this may allow network interception of passwords!");
        }

        if !self.verify_hostnames {
            warn!(
                "verify_hostnames set to false in client configuration - this may allow network interception of passwords!"
            );
        }

        if !address.starts_with("https://") {
            warn!("Address does not start with 'https://' - this may allow network interception of passwords!");
        }
    }

    /// Generates a useragent header based on the package name and version
    pub fn user_agent() -> &'static str {
        static APP_USER_AGENT: &str =
            concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
        APP_USER_AGENT
    }

    /*
    /// Consume self and return an async client.
    pub fn build(self) -> Result<KanidmClient, reqwest::Error> {
        self.build_async().map(|asclient| KanidmClient { asclient })
    }
    */

    /// Async client
    pub fn build_async(self) -> Result<KanidmAsyncClient, reqwest::Error> {
        // Errghh, how to handle this cleaner.
        let address = match &self.address {
            Some(a) => a.clone(),
            None => {
                error!("Configuration option 'uri' missing from client configuration, cannot continue client startup without specifying a server to connect to. 🤔");
                std::process::exit(1);
            }
        };

        self.display_warnings(address.as_str());

        let client_builder = reqwest::Client::builder()
            .user_agent(KanidmClientBuilder::user_agent())
            .danger_accept_invalid_hostnames(!self.verify_hostnames)
            .danger_accept_invalid_certs(!self.verify_ca);

        let client_builder = match self.use_system_proxies {
            true => client_builder,
            false => client_builder.no_proxy(),
        };

        let client_builder = match &self.ca {
            Some(cert) => client_builder.add_root_certificate(cert.clone()),
            None => client_builder,
        };

        let client_builder = match &self.connect_timeout {
            Some(secs) => client_builder
                .connect_timeout(Duration::from_secs(*secs))
                .timeout(Duration::from_secs(*secs)),
            None => client_builder,
        };

        let client = client_builder.build()?;

        // Now get the origin.
        #[allow(clippy::expect_used)]
        let uri = Url::parse(&address).expect("can not fail");

        #[allow(clippy::expect_used)]
        let origin = uri.origin().unicode_serialization();

        Ok(KanidmAsyncClient {
            client,
            addr: address,
            builder: self,
            bearer_token: RwLock::new(None),
            origin,
            auth_session_id: RwLock::new(None),
        })
    }
}


#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate log;

use serde_derive::Deserialize;
use serde_json::error::Error as SerdeJsonError;
use std::collections::BTreeSet as Set;
use std::fs::{metadata, File, Metadata};
use std::io::ErrorKind;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

pub use reqwest::StatusCode;

use webauthn_rs::proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
// use users::{get_current_uid, get_effective_uid};

use kanidm_proto::v1::*;

pub mod asynchronous;

use crate::asynchronous::KanidmAsyncClient;

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
        }
    }

    fn parse_certificate(ca_path: &str) -> Result<reqwest::Certificate, ()> {
        let mut buf = Vec::new();
        // Is the CA secure?
        let path = Path::new(ca_path);
        let ca_meta = read_file_metadata(&path)?;

        if !ca_meta.permissions().readonly() {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", ca_path);
        }

        if ca_meta.uid() != 0 || ca_meta.gid() != 0 {
            warn!(
                "{} should be owned be root:root to prevent tampering",
                ca_path
            );
        }

        // TODO #253: Handle these errors better, or at least provide diagnostics?
        let mut f = File::open(ca_path).map_err(|_| ())?;
        f.read_to_end(&mut buf).map_err(|_| ())?;
        reqwest::Certificate::from_pem(&buf).map_err(|_| ())
    }

    fn apply_config_options(self, kcc: KanidmClientConfig) -> Result<Self, ()> {
        let KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
        } = self;
        // Process and apply all our options if they exist.
        let address = match kcc.uri {
            Some(uri) => Some(uri),
            None => address,
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
        })
    }

    pub fn read_options_from_optional_config<P: AsRef<Path> + std::fmt::Debug>(
        self,
        config_path: P,
    ) -> Result<Self, ()> {
        debug!("Attempting to load configuration from {:#?}", &config_path);
        // If the file does not exist, we skip this function.
        let mut f = match File::open(&config_path) {
            Ok(f) => f,
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
            .map_err(|e| eprintln!("{:?}", e))?;

        let config: KanidmClientConfig =
            toml::from_str(contents.as_str()).map_err(|e| eprintln!("{:?}", e))?;

        self.apply_config_options(config)
    }

    pub fn address(self, address: String) -> Self {
        KanidmClientBuilder {
            address: Some(address),
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
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
        }
    }

    pub fn connect_timeout(self, secs: u64) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: Some(secs),
        }
    }

    pub fn add_root_certificate_filepath(self, ca_path: &str) -> Result<Self, ()> {
        //Okay we have a ca to add. Let's read it in and setup.
        let ca = Self::parse_certificate(ca_path)?;

        Ok(KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: Some(ca),
            connect_timeout: self.connect_timeout,
        })
    }

    fn display_warnings(&self, address: &str) {
        // Check for problems now
        if !self.verify_ca {
            warn!("verify_ca set to false - this may allow network interception of passwords!");
        }

        if !self.verify_hostnames {
            warn!(
                "verify_hostnames set to false - this may allow network interception of passwords!"
            );
        }

        if !address.starts_with("https://") {
            warn!("address does not start with 'https://' - this may allow network interception of passwords!");
        }
    }

    // Consume self and return a client.
    pub fn build(self) -> Result<KanidmClient, reqwest::Error> {
        self.build_async().map(|asclient| KanidmClient { asclient })
    }

    pub fn build_async(self) -> Result<KanidmAsyncClient, reqwest::Error> {
        // Errghh, how to handle this cleaner.
        let address = match &self.address {
            Some(a) => a.clone(),
            None => {
                eprintln!("uri (-H) missing, can not proceed");
                unimplemented!();
            }
        };

        self.display_warnings(address.as_str());

        let client_builder = reqwest::Client::builder()
            .danger_accept_invalid_hostnames(!self.verify_hostnames)
            .danger_accept_invalid_certs(!self.verify_ca);

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

#[derive(Debug)]
pub struct KanidmClient {
    asclient: KanidmAsyncClient,
}

#[allow(clippy::expect_used)]
fn tokio_block_on<R, F>(f: F) -> R
where
    F: std::future::Future + std::future::Future<Output = R>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start tokio");
    rt.block_on(f)
}

impl KanidmClient {
    pub fn get_origin(&self) -> &str {
        self.asclient.get_origin()
    }

    pub fn new_session(&self) -> Result<Self, reqwest::Error> {
        // Copy our builder, and then just process it.
        self.asclient
            .new_session()
            .map(|asclient| KanidmClient { asclient })
    }

    pub fn set_token(&self, new_token: String) {
        tokio_block_on(self.asclient.set_token(new_token));
    }

    pub fn get_token(&self) -> Option<String> {
        tokio_block_on(self.asclient.get_token())
    }

    pub fn logout(&self) {
        tokio_block_on(self.asclient.logout())
    }

    // whoami
    // Can't use generic get due to possible un-auth case.
    pub fn whoami(&self) -> Result<Option<(Entry, UserAuthToken)>, ClientError> {
        tokio_block_on(self.asclient.whoami())
    }

    // auth
    pub fn auth_step_init(&self, ident: &str) -> Result<Set<AuthMech>, ClientError> {
        tokio_block_on(self.asclient.auth_step_init(ident))
    }

    pub fn auth_step_begin(&self, mech: AuthMech) -> Result<Vec<AuthAllowed>, ClientError> {
        tokio_block_on(self.asclient.auth_step_begin(mech))
    }

    pub fn auth_step_anonymous(&self) -> Result<AuthResponse, ClientError> {
        tokio_block_on(self.asclient.auth_step_anonymous())
    }

    pub fn auth_step_password(&self, password: &str) -> Result<AuthResponse, ClientError> {
        tokio_block_on(self.asclient.auth_step_password(password))
    }

    pub fn auth_step_totp(&self, totp: u32) -> Result<AuthResponse, ClientError> {
        tokio_block_on(self.asclient.auth_step_totp(totp))
    }

    pub fn auth_step_webauthn_complete(
        &self,
        pkc: PublicKeyCredential,
    ) -> Result<AuthResponse, ClientError> {
        tokio_block_on(self.asclient.auth_step_webauthn_complete(pkc))
    }

    pub fn auth_anonymous(&self) -> Result<(), ClientError> {
        tokio_block_on(self.asclient.auth_anonymous())
    }

    pub fn auth_simple_password(&self, ident: &str, password: &str) -> Result<(), ClientError> {
        tokio_block_on(self.asclient.auth_simple_password(ident, password))
    }

    pub fn auth_password_totp(
        &self,
        ident: &str,
        password: &str,
        totp: u32,
    ) -> Result<(), ClientError> {
        tokio_block_on(self.asclient.auth_password_totp(ident, password, totp))
    }

    pub fn auth_webauthn_begin(
        &self,
        ident: &str,
    ) -> Result<RequestChallengeResponse, ClientError> {
        tokio_block_on(self.asclient.auth_webauthn_begin(ident))
    }

    pub fn auth_webauthn_complete(&self, pkc: PublicKeyCredential) -> Result<(), ClientError> {
        tokio_block_on(self.asclient.auth_webauthn_complete(pkc))
    }

    // search
    pub fn search(&self, filter: Filter) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.search(filter))
    }

    // create
    pub fn create(&self, entries: Vec<Entry>) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.create(entries))
    }

    // modify
    pub fn modify(&self, filter: Filter, modlist: ModifyList) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.modify(filter, modlist))
    }

    // delete
    pub fn delete(&self, filter: Filter) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.delete(filter))
    }

    // === idm actions here ==

    // ===== GROUPS
    pub fn idm_group_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_group_list())
    }

    pub fn idm_group_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_group_get(id))
    }

    pub fn idm_group_get_members(&self, id: &str) -> Result<Option<Vec<String>>, ClientError> {
        tokio_block_on(self.asclient.idm_group_get_members(id))
    }

    pub fn idm_group_set_members(&self, id: &str, members: &[&str]) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_set_members(id, members))
    }

    pub fn idm_group_add_members(&self, id: &str, members: &[&str]) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_add_members(id, members))
    }

    pub fn idm_group_remove_members(
        &self,
        group: &str,
        members: &[&str],
    ) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_remove_members(group, members))
    }

    pub fn idm_group_purge_members(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_purge_members(id))
    }

    pub fn idm_group_unix_token_get(&self, id: &str) -> Result<UnixGroupToken, ClientError> {
        tokio_block_on(self.asclient.idm_group_unix_token_get(id))
    }

    pub fn idm_group_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
    ) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_unix_extend(id, gidnumber))
    }

    pub fn idm_group_delete(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_delete(id))
    }

    pub fn idm_group_create(&self, name: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_group_create(name))
    }

    // ==== accounts
    pub fn idm_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_account_list())
    }

    pub fn idm_account_create(&self, name: &str, dn: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_create(name, dn))
    }

    pub fn idm_account_set_password(&self, cleartext: String) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_set_password(cleartext))
    }

    pub fn idm_account_set_displayname(&self, id: &str, dn: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_set_displayname(id, dn))
    }

    pub fn idm_account_delete(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_delete(id))
    }

    pub fn idm_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_account_get(id))
    }

    pub fn idm_account_get_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<Option<Vec<String>>, ClientError> {
        tokio_block_on(self.asclient.idm_account_get_attr(id, attr))
    }

    // different ways to set the primary credential?
    // not sure how to best expose this.
    pub fn idm_account_primary_credential_set_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<SetCredentialResponse, ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_set_password(id, pw),
        )
    }

    pub fn idm_account_purge_attr(&self, id: &str, attr: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_purge_attr(id, attr))
    }

    pub fn idm_account_set_attr(
        &self,
        id: &str,
        attr: &str,
        values: &[&str],
    ) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_set_attr(id, attr, values))
    }

    pub fn idm_account_primary_credential_import_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<bool, ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_import_password(id, pw),
        )
    }

    pub fn idm_account_primary_credential_set_generated(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_set_generated(id),
        )
    }

    // Reg intent for totp
    pub fn idm_account_primary_credential_generate_totp(
        &self,
        id: &str,
        label: &str,
    ) -> Result<(Uuid, TotpSecret), ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_generate_totp(id, label),
        )
    }

    // Verify the totp
    pub fn idm_account_primary_credential_verify_totp(
        &self,
        id: &str,
        otp: u32,
        session: Uuid,
    ) -> Result<bool, ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_verify_totp(id, otp, session),
        )
    }

    pub fn idm_account_primary_credential_remove_totp(
        &self,
        id: &str,
    ) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_primary_credential_remove_totp(id))
    }

    pub fn idm_account_primary_credential_register_webauthn(
        &self,
        id: &str,
        label: &str,
    ) -> Result<(Uuid, CreationChallengeResponse), ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_register_webauthn(id, label),
        )
    }

    pub fn idm_account_primary_credential_complete_webuthn_registration(
        &self,
        id: &str,
        rego: RegisterPublicKeyCredential,
        session: Uuid,
    ) -> Result<(), ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_complete_webuthn_registration(id, rego, session),
        )
    }

    pub fn idm_account_primary_credential_remove_webauthn(
        &self,
        id: &str,
        label: &str,
    ) -> Result<bool, ClientError> {
        tokio_block_on(
            self.asclient
                .idm_account_primary_credential_remove_webauthn(id, label),
        )
    }

    pub fn idm_account_get_credential_status(
        &self,
        id: &str,
    ) -> Result<CredentialStatus, ClientError> {
        tokio_block_on(self.asclient.idm_account_get_credential_status(id))
    }

    pub fn idm_account_radius_credential_get(
        &self,
        id: &str,
    ) -> Result<Option<String>, ClientError> {
        tokio_block_on(self.asclient.idm_account_radius_credential_get(id))
    }

    pub fn idm_account_radius_credential_regenerate(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        tokio_block_on(self.asclient.idm_account_radius_credential_regenerate(id))
    }

    pub fn idm_account_radius_credential_delete(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_radius_credential_delete(id))
    }

    pub fn idm_account_radius_token_get(&self, id: &str) -> Result<RadiusAuthToken, ClientError> {
        tokio_block_on(self.asclient.idm_account_radius_token_get(id))
    }

    pub fn idm_account_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
        shell: Option<&str>,
    ) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_unix_extend(id, gidnumber, shell))
    }

    pub fn idm_account_unix_token_get(&self, id: &str) -> Result<UnixUserToken, ClientError> {
        tokio_block_on(self.asclient.idm_account_unix_token_get(id))
    }

    pub fn idm_account_unix_cred_put(&self, id: &str, cred: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_unix_cred_put(id, cred))
    }

    pub fn idm_account_unix_cred_delete(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_unix_cred_delete(id))
    }

    pub fn idm_account_unix_cred_verify(
        &self,
        id: &str,
        cred: &str,
    ) -> Result<Option<UnixUserToken>, ClientError> {
        tokio_block_on(self.asclient.idm_account_unix_cred_verify(id, cred))
    }

    pub fn idm_account_get_ssh_pubkeys(&self, id: &str) -> Result<Vec<String>, ClientError> {
        tokio_block_on(self.asclient.idm_account_get_ssh_pubkeys(id))
    }

    pub fn idm_account_post_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
        pubkey: &str,
    ) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_post_ssh_pubkey(id, tag, pubkey))
    }

    pub fn idm_account_person_extend(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_person_extend(id))
    }

    /*
    pub fn idm_account_rename_ssh_pubkey(&self, id: &str, oldtag: &str, newtag: &str) -> Result<(), ClientError> {
        self.perform_put_request(format!("/v1/account/{}/_ssh_pubkeys/{}", id, oldtag).as_str(), newtag.to_string())
    }
    */

    pub fn idm_account_get_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<Option<String>, ClientError> {
        tokio_block_on(self.asclient.idm_account_get_ssh_pubkey(id, tag))
    }

    pub fn idm_account_delete_ssh_pubkey(&self, id: &str, tag: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_account_delete_ssh_pubkey(id, tag))
    }

    // ==== domain_info (aka domain)
    pub fn idm_domain_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_domain_list())
    }

    pub fn idm_domain_get(&self, id: &str) -> Result<Entry, ClientError> {
        tokio_block_on(self.asclient.idm_domain_get(id))
    }

    // pub fn idm_domain_get_attr
    pub fn idm_domain_get_ssid(&self, id: &str) -> Result<String, ClientError> {
        tokio_block_on(self.asclient.idm_domain_get_ssid(id))
    }

    // pub fn idm_domain_put_attr
    pub fn idm_domain_set_ssid(&self, id: &str, ssid: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.idm_domain_set_ssid(id, ssid))
    }

    // ==== schema
    pub fn idm_schema_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_schema_list())
    }

    pub fn idm_schema_attributetype_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_schema_attributetype_list())
    }

    pub fn idm_schema_attributetype_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_schema_attributetype_get(id))
    }

    pub fn idm_schema_classtype_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_schema_classtype_list())
    }

    pub fn idm_schema_classtype_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        tokio_block_on(self.asclient.idm_schema_classtype_get(id))
    }

    // ==== recycle bin
    pub fn recycle_bin_list(&self) -> Result<Vec<Entry>, ClientError> {
        tokio_block_on(self.asclient.recycle_bin_list())
    }

    pub fn recycle_bin_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        tokio_block_on(self.asclient.recycle_bin_get(id))
    }

    pub fn recycle_bin_revive(&self, id: &str) -> Result<bool, ClientError> {
        tokio_block_on(self.asclient.recycle_bin_revive(id))
    }
}

use kanidm_client::{KanidmClient, KanidmClientBuilder};

use crate::error::Error;
use crate::profile::Profile;

// This client contains our admin and idm_admin connections that are
// pre-authenticated for use against the kanidm server. In addition,
// new clients can be requested for our test actors.
pub struct KanidmOrcaClient {
    admin_client: KanidmClient,
    idm_admin_client: KanidmClient,
    // In future we probably need a way to connect to all the nodes?
    // Or we just need all their uris.
}

impl KanidmOrcaClient {
    pub async fn new(profile: &Profile) -> Result<Self, Error> {
        let admin_client = KanidmClientBuilder::new()
            .address(profile.control_uri().to_string())
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|err| {
                error!(?err, "Unable to create kanidm client");
                Error::KanidmClient
            })?;

        admin_client
            .auth_simple_password("admin", profile.admin_password())
            .await
            .map_err(|err| {
                error!(?err, "Unable to authenticate as admin");
                Error::KanidmClient
            })?;

        let idm_admin_client = admin_client.new_session().map_err(|err| {
            error!(?err, "Unable to create new session");
            Error::KanidmClient
        })?;

        idm_admin_client
            .auth_simple_password("idm_admin", profile.idm_admin_password())
            .await
            .map_err(|err| {
                error!(?err, "Unable to authenticate as idm_admin");
                Error::KanidmClient
            })?;

        Ok(KanidmOrcaClient {
            admin_client,
            idm_admin_client,
        })
    }

    pub async fn disable_mfa_requirement(&self) -> Result<(), Error> {
        self.idm_admin_client
            .group_account_policy_credential_type_minimum_set("idm_all_persons", "any")
            .await
            .map_err(|err| {
                error!(?err, "Unable to modify idm_all_persons policy");
                Error::KanidmClient
            })
    }

    pub async fn person_exists(&self, username: &str) -> Result<bool, Error> {
        self.idm_admin_client
            .idm_person_account_get(username)
            .await
            .map(|e| e.is_some())
            .map_err(|err| {
                error!(?err, ?username, "Unable to check person");
                Error::KanidmClient
            })
    }

    pub async fn person_create(&self, username: &str, display_name: &str) -> Result<(), Error> {
        self.idm_admin_client
            .idm_person_account_create(username, display_name)
            .await
            .map_err(|err| {
                error!(?err, ?username, "Unable to create person");
                Error::KanidmClient
            })
    }

    pub async fn person_set_pirmary_password_only(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), Error> {
        self.idm_admin_client
            .idm_person_account_primary_credential_set_password(username, password)
            .await
            .map_err(|err| {
                error!(?err, ?username, "Unable to set person password");
                Error::KanidmClient
            })
    }
}

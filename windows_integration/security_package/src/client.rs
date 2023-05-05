use kanidm_client::{KanidmClient, KanidmClientBuilder, ClientError};
use kanidm_proto::v1::{UnixUserToken, Entry};
use kanidm_windows::secpkg::ap_proto::v1::AccountType;
use tracing::{event, span, Level};

#[derive(Debug)]
pub enum KanidmWindowsClientError {
    ReadOptionsFail,
    BuildClientFail,
    AuthenticationFail,
    GetTokenFail,
}

pub struct KanidmWindowsClient {
    client: KanidmClient,
}

impl KanidmWindowsClient {
    pub fn new(config_path: &str) -> Result<Self, KanidmWindowsClientError> {
        let ns = span!(Level::INFO, "Creating new KanidmWindowsClient").entered();
        let mut cb = KanidmClientBuilder::new();
        cb = match cb.read_options_from_optional_config(config_path) {
            Ok(cb) => cb,
            Err(_) => {
                event!(Level::DEBUG, "Failed to read config path");
                return Err(KanidmWindowsClientError::ReadOptionsFail);
            }
        };

        let client = match cb.build() {
            Ok(client) => client,
            Err(_) => {
                event!(Level::DEBUG, "Failed to build kanidm client");
                return Err(KanidmWindowsClientError::BuildClientFail);
            }
        };

        ns.exit();
        Ok(KanidmWindowsClient { client: client })
    }

    // TODO: Implement token caching
    pub async fn logon_user(
        &self,
        username: &String,
        password: &String,
    ) -> Result<UnixUserToken, KanidmWindowsClientError> {
        let lus = span!(Level::INFO, "Starting logon process for {}", username).entered();
        let token = match self
            .client
            .idm_account_unix_cred_verify(username.as_str(), password.as_str())
            .await
        {
            Ok(Some(token)) => token,
            Ok(None) | Err(_) => {
                event!(
                    Level::ERROR,
                    "Failed to authenticate user credentials for {}",
                    username
                );
                return Err(KanidmWindowsClientError::AuthenticationFail);
            }
        };

        lus.exit();
        Ok(token)
    }

    pub async fn get_token(
        &self,
        username: &String,
    ) -> Result<UnixUserToken, KanidmWindowsClientError> {
        let gts = span!(Level::INFO, "Retrieving user token for {}", username).entered();
        let token = match self
            .client
            .idm_account_unix_token_get(username.as_str())
            .await
        {
            Ok(token) => token,
            Err(_) => {
                event!(Level::ERROR, "Failed to get token from kanidm client");
                return Err(KanidmWindowsClientError::GetTokenFail);
            }
        };

        gts.exit();
        Ok(token)
    }

    pub async fn get_accounts(&self, account_type: &AccountType) -> Result<Vec<Entry>, ClientError> {
        let gas = span!(Level::INFO, "Retrieving all account");
        let accounts = match account_type {
            AccountType::Person => self.client.idm_person_account_list().await,
            AccountType::Service => self.client.idm_service_account_list().await,
        };

        return accounts;
    }
}

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UnixUserToken;
use tracing::{event, span, Level};

#[derive(Debug)]
pub enum KanidmWindowsClientError {
    ReadOptions,
    BuildClient,
    Authentication,
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
                return Err(KanidmWindowsClientError::ReadOptions);
            }
        };

        let client = match cb.build() {
            Ok(client) => client,
            Err(_) => {
                event!(Level::DEBUG, "Failed to build kanidm client");
                return Err(KanidmWindowsClientError::BuildClient);
            }
        };

        ns.exit();
        Ok(KanidmWindowsClient { client })
    }

    // TODO: Implement token caching
    pub async fn logon_user_unix(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UnixUserToken, KanidmWindowsClientError> {
        let lus = span!(Level::INFO, "Starting logon process for {}", username).entered();
        let token = match self
            .client
            .idm_account_unix_cred_verify(username, password)
            .await
        {
            Ok(Some(token)) => token,
            Ok(None) | Err(_) => {
                event!(
                    Level::ERROR,
                    "Failed to authenticate user credentials for {}",
                    username
                );
                return Err(KanidmWindowsClientError::Authentication);
            }
        };

        lus.exit();
        Ok(token)
    }
}

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UnixUserToken;
use tracing::{event, Level, span};

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

		Ok(KanidmWindowsClient {
			client: client,
		})
	}

	// TODO: Implement token caching
	pub async fn logon_user(&self, username: &String, password: &String) -> Result<UnixUserToken, KanidmWindowsClientError> {
		let lus = span!(Level::INFO, "Starting logon process for {}", username).entered();
		let token = match self.client.idm_account_unix_cred_verify(username.as_str(), password.as_str()).await {
			Ok(Some(token)) => token,
			Ok(None) | Err(_) => return Err(KanidmWindowsClientError::AuthenticationFail),
		};

		lus.exit();
		Ok(token)
	}

	pub async fn get_token(&self, username: &String) -> Result<UnixUserToken, KanidmWindowsClientError> {
		let gts = span!(Level::INFO, "Retrieving user token for {}", username).entered();
		let token = match self.client.idm_account_unix_token_get(username.as_str()).await {
			Ok(token) => token,
			Err(_) => return Err(KanidmWindowsClientError::GetTokenFail),
		};

		gts.exit();
		Ok(token)
	}
}
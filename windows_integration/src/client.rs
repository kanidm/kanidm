use kanidm_client::{KanidmClient, KanidmClientBuilder};
use tracing::{event, Level};

#[derive(Debug)]
pub enum KanidmWindowsClientError {
	ReadOptionsFail,
	BuildClientFail,
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
}
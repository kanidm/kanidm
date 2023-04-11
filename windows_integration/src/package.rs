use once_cell::sync::Lazy;
use tracing::{event, Level};
use crate::{client::KanidmWindowsClient, CONFIG_PATH};

pub(crate) static mut KANIDM_WINDOWS_CLIENT: Lazy<Option<KanidmWindowsClient>> = Lazy::new(|| {
	let client = match KanidmWindowsClient::new(CONFIG_PATH) {
		Ok(client) => client,
		Err(e) => {
			event!(Level::ERROR, "Failed to create new KanidmWindowsClient");
			event!(Level::INFO, "KanidmWindowsClientError {:?}", e);

			return None;
		}
	};

	Some(client)
});
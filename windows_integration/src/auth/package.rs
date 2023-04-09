use kanidm_client::{KanidmClient, KanidmClientBuilder};
use tracing::{event, Level, span};
use windows::Win32::{Foundation::*, Security::Authentication::Identity::*, System::Kernel::*};

pub enum AuthError {
	ClientBuildFail,
}
pub struct AuthInfo {}
pub struct ProfileBuffer {}

pub struct AuthPackage {
	pub package_id: Option<u32>,
	pub dispatch_table: Option<LSA_DISPATCH_TABLE>,
	pub client: Option<KanidmClient>,
}

impl AuthPackage {
	pub async fn init(
		&mut self,
		package_id: u32,
		dispatch_table: LSA_DISPATCH_TABLE,
	) -> Result<String, AuthError> {
		let init_span = span!(Level::INFO, "Initialising authentication package").entered();
		self.package_id = Some(package_id);
		self.dispatch_table = Some(dispatch_table);

		let package_name = env!("CARGO_PKG_NAME");
		let client_builder = KanidmClientBuilder::new()
			.connect_timeout(60);
		
		if let Ok(client) = client_builder.build() {
			self.client = Some(client);
		} else {
			event!(Level::ERROR, "Failed to build kanidm client");
			return Err(AuthError::ClientBuildFail);
		}

		init_span.exit();
		Ok(package_name.to_string())
	}
}
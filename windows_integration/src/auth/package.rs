use windows::Win32::{Foundation::*, Security::Authentication::Identity::*, System::Kernel::*};

pub enum AuthError {}
pub struct AuthInfo {}
pub struct ProfileBuffer {}

pub struct AuthPackage {
	pub package_id: Option<u32>,
	pub dispatch_table: Option<LSA_DISPATCH_TABLE>,
}

impl AuthPackage {
	pub async fn init(
		&mut self,
		package_id: u32,
		dispatch_table: LSA_DISPATCH_TABLE,
	) -> String {
		self.package_id = Some(package_id);
		self.dispatch_table = Some(dispatch_table);

		let package_name = env!("CARGO_PKG_NAME");

		package_name.to_string()
	}
}
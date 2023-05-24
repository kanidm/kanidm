use kanidm_proto::v1::UnixUserToken;

pub enum AccountType {
	Person,
	Service,
}

// Authentication Package Protocol
pub enum AuthPkgRequest {
	AuthenticateAccount(AuthenticateAccountRequest),
}

pub enum AuthPkgResponse {
	AuthenticateAccount(AuthenticateAccountResponse),
	Error(AuthPkgError),
}

pub enum AuthPkgError {
	AuthenticationFailed,
}

pub struct AuthenticateAccountRequest {
	pub account_type: AccountType,
	pub id: String,
	pub password: String,
}

pub struct AuthenticateAccountResponse {
	pub status: Result<(), AuthPkgError>,
	pub token: Option<UnixUserToken>,
}

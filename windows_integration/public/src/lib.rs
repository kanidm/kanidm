use kanidm_client::ClientError;
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

pub enum AuthPkgError {}

pub struct AuthenticateAccountRequest {
	account_type: AccountType,
	id: String,
	password: String,
}

pub struct AuthenticateAccountResponse {
	status: Result<(), AuthPkgError>,
	token: Option<UnixUserToken>,
}

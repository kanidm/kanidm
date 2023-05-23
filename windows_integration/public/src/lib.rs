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

pub struct AuthenticateAccountRequest {}

pub struct AuthenticateAccountResponse {}

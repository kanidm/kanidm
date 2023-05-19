use kanidm_client::ClientError;

pub enum AccountType {
    Person,
    Service,
}

pub enum AuthPkgRequest {
    AuthenticateAccount(AuthenticateAccountRequest),
}

pub enum AuthPkgResponse {
    Error(AuthPkgError),
    AuthenticateAccount(AuthenticateAccountResponse),
}

pub enum AuthPkgError {
    ClientError(ClientError),
    UnsupportedAuthMethod,
}

pub struct AuthenticateAccountRequest {
    pub r#type: AccountType,
    pub id: String,
    pub password: String,
    pub totp: Option<u32>,
    pub backup_code: Option<String>,
}
pub struct AuthenticateAccountResponse {}

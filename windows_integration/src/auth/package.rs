use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UnixUserToken;
use std::collections::HashMap;
use tracing::{event, span, Level};
use windows::Win32::{Foundation::UNICODE_STRING, Security::Authentication::Identity::*};

use super::constants::CONFIG_PATH;

pub enum AuthError {
    ClientBuildFail,
    MissingInternalProp,
    AuthenticationFailed,
    GenericError,
}

pub struct AuthInfo {
    pub username: UNICODE_STRING,
    pub password: UNICODE_STRING,
}

pub struct AuthProfileBuffer {
    pub token: UnixUserToken,
}

pub struct AuthPackage {
    package_id: Option<u32>,
    dispatch_table: Option<LSA_DISPATCH_TABLE>,
    client: Option<KanidmClient>,
    tokens: HashMap<String, UnixUserToken>,
}

impl AuthPackage {
    pub fn new() -> Self {
        AuthPackage {
            package_id: None,
            dispatch_table: None,
            client: None,
            tokens: HashMap::new(),
        }
    }

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

    pub async fn logon_user(
        &mut self,
        username: String,
        password: String,
    ) -> Result<AuthProfileBuffer, AuthError> {
        let logon_user_span = span!(Level::INFO, "Logging on user {}", username).entered();
        let client = match &self.client {
            Some(c) => c,
            None => return Err(AuthError::MissingInternalProp),
        };

        if let Some(token) = self.tokens.get(&username) {
            let profile_buffer = AuthProfileBuffer {
                token: token.clone(),
            };
            return Ok(profile_buffer);
        }

        let token = match client
            .idm_account_unix_cred_verify(username.as_str(), password.as_str())
            .await
        {
            Ok(Some(token)) => token,
            Ok(None) => return Err(AuthError::AuthenticationFailed),
            Err(error) => {
                event!(Level::ERROR, "Failed to authenticate client");
                return match error {
                    ClientError::AuthenticationFailed => Err(AuthError::AuthenticationFailed),
                    _ => Err(AuthError::GenericError),
                };
            }
        };

        self.tokens.insert(username, token.clone());

        let profile_buffer = AuthProfileBuffer { token: token };

        logon_user_span.exit();
        Ok(profile_buffer)
    }
}

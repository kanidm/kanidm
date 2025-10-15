use super::CredState;
use crate::idm::authentication::AuthCredential;
use crate::prelude::*;
use std::fmt;

pub struct CredHandlerOAuth2Trust {
    // For logging
    provider_id: Uuid,
    provider_name: String,
    // The users ID as the remote trust provider knows them.
    user_id: String,
    client_id: String,
    client_secret: String,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    // Post auth we need to verify the token in some manner?
    pkce_challenge: String,
}

impl fmt::Debug for CredHandlerOAuth2Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredHandlerOauth2Trust")
            .field("provider_id", &self.provider_id)
            .field("provider_name", &self.provider_name)
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("authorisation_endpoint", &self.authorisation_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .finish()
    }
}

impl CredHandlerOAuth2Trust {
    pub fn validate(&self, cred: &AuthCredential) -> CredState {
        todo!();
    }
}

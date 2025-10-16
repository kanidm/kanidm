use super::CredState;
use crate::idm::authentication::AuthCredential;
use crate::idm::oauth2::PkceS256Secret;
use crate::idm::oauth2_trust::OAuth2TrustProvider;
use crate::prelude::*;
use crate::utils;
use kanidm_proto::oauth2::{AuthorisationRequest, ResponseType};
use std::collections::BTreeSet;
use std::fmt;

pub struct CredHandlerOAuth2Trust {
    // For logging
    provider_id: Uuid,
    provider_name: String,
    // The users ID as the remote trust provider knows them.
    request_scopes: BTreeSet<String>,
    user_id: String,
    client_id: String,
    client_secret: String,
    client_redirect_url: Url,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    pkce_secret: PkceS256Secret,
    // Post auth we need to verify the token in some manner?
    // token_verification_method: None | JWT | userinfo | id_token
    csrf_state: String,
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
    pub fn new(trust_provider: &OAuth2TrustProvider, trust_user_id: &str) -> Self {
        let pkce_secret = PkceS256Secret::default();
        let csrf_state = utils::password_from_random();

        CredHandlerOAuth2Trust {
            provider_id: trust_provider.uuid,
            provider_name: trust_provider.name.clone(),
            request_scopes: trust_provider.request_scopes.clone(),
            user_id: trust_user_id.to_string(),
            client_id: trust_provider.client_id.clone(),
            client_secret: trust_provider.basic_secret.clone(),
            client_redirect_url: trust_provider.client_redirect_uri.clone(),
            authorisation_endpoint: trust_provider.authorisation_endpoint.clone(),
            token_endpoint: trust_provider.token_endpoint.clone(),
            pkce_secret,
            csrf_state,
        }
    }

    pub fn start_auth_request(&self) -> (Url, AuthorisationRequest) {
        let pkce_request = self.pkce_secret.to_request();

        (
            self.authorisation_endpoint.clone(),
            AuthorisationRequest {
                redirect_uri: self.client_redirect_url.clone(),
                response_type: ResponseType::Code,
                response_mode: None,
                client_id: self.client_id.clone(),
                state: Some(self.csrf_state.clone()),
                pkce_request: Some(pkce_request),
                scope: self.request_scopes.clone(),
                nonce: None,
                oidc_ext: Default::default(),
                max_age: None,
                unknown_keys: Default::default(),
            },
        )
    }

    pub fn validate(&self, cred: &AuthCredential) -> CredState {
        todo!();
    }
}

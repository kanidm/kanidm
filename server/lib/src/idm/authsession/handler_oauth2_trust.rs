use super::{CredState, BAD_AUTH_TYPE_MSG, BAD_OAUTH2_CSRF_STATE_MSG};
use crate::idm::account::OAuth2TrustProviderCred;
use crate::idm::authentication::{AuthCredential, AuthExternal};
use crate::idm::oauth2::PkceS256Secret;
use crate::idm::oauth2_trust::OAuth2TrustProvider;
use crate::prelude::*;
use crate::utils;
use crate::value::{AuthType, SessionExtMetadata};
use kanidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, GrantTypeReq, ResponseType,
};
use std::collections::BTreeSet;
use std::fmt;

pub struct CredHandlerOAuth2Trust {
    // For logging - this is the trust provider we are using.
    provider_id: Uuid,
    provider_name: String,

    user_id: String,
    user_cred_id: Uuid,

    // The users ID as the remote trust provider knows them.
    request_scopes: BTreeSet<String>,
    client_id: String,
    client_basic_secret: String,
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
    pub fn new(
        trust_provider: &OAuth2TrustProvider,
        trust_user_cred: &OAuth2TrustProviderCred,
    ) -> Self {
        let pkce_secret = PkceS256Secret::default();
        let csrf_state = utils::password_from_random();

        CredHandlerOAuth2Trust {
            provider_id: trust_provider.uuid,
            provider_name: trust_provider.name.clone(),
            request_scopes: trust_provider.request_scopes.clone(),
            user_id: trust_user_cred.user_id.to_string(),
            user_cred_id: trust_user_cred.cred_id,
            client_id: trust_provider.client_id.clone(),
            client_basic_secret: trust_provider.client_basic_secret.clone(),
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

    pub fn validate(&self, cred: &AuthCredential, current_time: Duration) -> CredState {
        match cred {
            AuthCredential::OAuth2AuthorisationResponse { code, state } => {
                self.validate_authorisation_response(code, state.as_deref())
            }
            AuthCredential::OAuth2AccessTokenResponse { response } => {
                self.validate_access_token_response(response, current_time)
            }
            _ => CredState::Denied(BAD_AUTH_TYPE_MSG),
        }
    }

    fn validate_authorisation_response(&self, code: &str, state: Option<&str>) -> CredState {
        // Validate our csrf state

        let csrf_valid = state.map(|s| s == self.csrf_state).unwrap_or_default();

        if !csrf_valid {
            return CredState::Denied(BAD_OAUTH2_CSRF_STATE_MSG);
        }

        // How to handle this cleanly?
        let code_verifier = Some(self.pkce_secret.verifier().to_string());

        let grant_type_req = GrantTypeReq::AuthorizationCode {
            code: code.into(),
            redirect_uri: self.client_redirect_url.clone(),
            code_verifier,
        };

        let request = AccessTokenRequest::from(grant_type_req);

        CredState::External(AuthExternal::OAuth2AccessTokenRequest {
            token_url: self.token_endpoint.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_basic_secret.clone(),
            request,
        })
    }

    fn validate_access_token_response(
        &self,
        response: &AccessTokenResponse,
        current_time: Duration,
    ) -> CredState {
        // What is the credential id here? The provider id?
        // How do we make sure that session plugin doesn't kill us?
        let cred_id = self.user_cred_id;
        let access_expires_at = current_time + Duration::from_secs(response.expires_in as u64);

        // We need a way to bubble up extra session metadata now.
        // Need to pass up the expiry, token, refresh token.
        let ext_session_metadata = SessionExtMetadata::OAuth2 {
            access_token: response.access_token.clone(),
            refresh_token: response.refresh_token.clone(),
            access_expires_at,
        };

        CredState::Success {
            auth_type: AuthType::OAuth2Trust,
            cred_id,
            ext_session_metadata,
        }
    }
}

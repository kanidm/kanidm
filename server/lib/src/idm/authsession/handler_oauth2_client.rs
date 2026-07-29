use super::{
    CredState, BAD_AUTH_TYPE_MSG, BAD_OAUTH2_CSRF_STATE_MSG, BAD_OAUTH2_SESSION_MSG,
    BAD_OAUTH2_SUBJECT_MSG,
};
use crate::idm::account::OAuth2AccountCredential;
use crate::idm::authentication::{AuthCredential, AuthExternal};
use crate::idm::oauth2::PkceS256Secret;
use crate::idm::oauth2_client::{OAuth2ClientProvider, OAuth2SubjectVerifier};
use crate::prelude::*;
use crate::utils;
use crate::value::{AuthType, SessionExtMetadata};
use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationRequest, AuthorisationRequestOidc, GrantTypeReq,
    ResponseType,
};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone)]
enum SessionState {
    Init,
    AccessTokenRequested,
    AccessTokenUnverified {
        access_expires_at: Duration,
        access_token: String,
        refresh_token: Option<String>,
    },
    Finished,
}

#[derive(Clone)]
pub struct CredHandlerOAuth2Client {
    // For logging - this is the trust provider we are using.
    provider_id: Uuid,
    provider_name: String,

    // The users ID as the remote trust provider knows them.
    user_id: String,
    user_sub: String,
    user_cred_id: Uuid,

    user_sub_verifier: OAuth2SubjectVerifier,

    request_scopes: BTreeSet<String>,
    client_id: String,
    client_basic_secret: String,
    client_redirect_url: Url,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    pkce_secret: PkceS256Secret,
    csrf_state: String,

    session_state: SessionState,
}

impl fmt::Debug for CredHandlerOAuth2Client {
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

impl CredHandlerOAuth2Client {
    pub fn new(
        client_provider: &OAuth2ClientProvider,
        client_user_cred: &OAuth2AccountCredential,
    ) -> Self {
        let pkce_secret = PkceS256Secret::default();
        let csrf_state = utils::password_from_random();

        CredHandlerOAuth2Client {
            provider_id: client_provider.uuid,
            provider_name: client_provider.name.clone(),
            request_scopes: client_provider.request_scopes.clone(),
            user_id: client_user_cred.user_id.to_string(),
            user_sub: client_user_cred.user_sub.to_string(),
            user_cred_id: client_user_cred.cred_id,
            client_id: client_provider.client_id.clone(),
            client_basic_secret: client_provider.client_basic_secret.clone(),
            client_redirect_url: client_provider.client_redirect_uri.clone(),
            authorisation_endpoint: client_provider.authorisation_endpoint.clone(),
            token_endpoint: client_provider.token_endpoint.clone(),
            pkce_secret,
            csrf_state,
            user_sub_verifier: client_provider.user_sub_verifier.clone(),
            session_state: SessionState::Init,
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
                oidc_ext: AuthorisationRequestOidc {
                    login_hint: Some(self.user_id.clone()),
                    ..Default::default()
                },
                max_age: None,
                prompt: Vec::new(),
                ui_locales: Vec::new(),
                unknown_keys: Default::default(),
            },
        )
    }

    pub fn validate(&mut self, cred: &AuthCredential, current_time: Duration) -> CredState {
        let (next_state, response) = match (self.session_state.clone(), cred) {
            (SessionState::Init, AuthCredential::OAuth2AuthorisationResponse { code, state }) => {
                self.validate_authorisation_response(code, state.as_deref())
            }

            (
                SessionState::AccessTokenRequested,
                AuthCredential::OAuth2AccessTokenResponse { response },
            ) => self.validate_access_token_response(response, current_time),

            (
                SessionState::AccessTokenUnverified {
                    access_token,
                    refresh_token,
                    access_expires_at,
                },
                AuthCredential::OAuth2AccessTokenIntrospectResponse { response },
            ) => self.validate_access_token_introspection_response(
                response,
                access_token,
                refresh_token,
                access_expires_at,
            ),
            _ => (SessionState::Finished, CredState::Denied(BAD_AUTH_TYPE_MSG)),
        };

        self.session_state = next_state;
        response
    }

    fn validate_authorisation_response(
        &self,
        code: &str,
        state: Option<&str>,
    ) -> (SessionState, CredState) {
        // Validate our csrf state

        let csrf_valid = state.map(|s| s == self.csrf_state).unwrap_or_default();

        if !csrf_valid {
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_CSRF_STATE_MSG),
            );
        }

        let code_verifier = Some(self.pkce_secret.verifier().to_string());

        let grant_type_req = GrantTypeReq::AuthorizationCode {
            code: code.into(),
            redirect_uri: self.client_redirect_url.clone(),
            code_verifier,
        };

        let request = AccessTokenRequest::from(grant_type_req);

        (
            SessionState::AccessTokenRequested,
            CredState::External(AuthExternal::OAuth2AccessTokenRequest {
                token_url: self.token_endpoint.clone(),
                client_id: self.client_id.clone(),
                client_secret: self.client_basic_secret.clone(),
                request,
            }),
        )
    }

    fn validate_access_token_response(
        &self,
        response: &AccessTokenResponse,
        current_time: Duration,
    ) -> (SessionState, CredState) {
        // We have a positive response and now have the access and refresh tokens. However
        // now we need to assert the token belongs to our subject.

        match &self.user_sub_verifier {
            OAuth2SubjectVerifier::None => {
                (SessionState::Finished, CredState::Denied(BAD_AUTH_TYPE_MSG))
            }
            OAuth2SubjectVerifier::Rfc7662TokenIntrospection { endpoint } => {
                let request = AccessTokenIntrospectRequest::from(response.access_token.clone());

                let access_expires_at =
                    current_time + Duration::from_secs(response.expires_in as u64);

                (
                    SessionState::AccessTokenUnverified {
                        access_token: response.access_token.clone(),
                        refresh_token: response.refresh_token.clone(),
                        access_expires_at,
                    },
                    CredState::External(AuthExternal::OAuth2AccessTokenIntrospectionRequest {
                        introspection_url: endpoint.clone(),
                        client_id: self.client_id.clone(),
                        client_secret: self.client_basic_secret.clone(),
                        request,
                    }),
                )
            }
        }
    }

    fn validate_access_token_introspection_response(
        &self,
        response: &AccessTokenIntrospectResponse,
        access_token: String,
        refresh_token: Option<String>,
        access_expires_at: Duration,
    ) -> (SessionState, CredState) {
        // Process the response!!!

        // The session must be active.

        if !response.active {
            error!(
                "access token introspection indicates the token is not active, refusing to proceed"
            );
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_SESSION_MSG),
            );
        }

        if let Some(response_sub) = response.sub.as_deref() {
            if response_sub == self.user_sub {
                // It's all good!
            } else {
                error!("access token introspection returned a different subject than expected, refusing to proceed with authentication.");
                return (
                    SessionState::Finished,
                    CredState::Denied(BAD_OAUTH2_SUBJECT_MSG),
                );
            }
        } else {
            warn!("access token introspection has no subject field, unable to proceed with authentication.");
            return (
                SessionState::Finished,
                CredState::Denied(BAD_OAUTH2_SUBJECT_MSG),
            );
        }

        // What is the credential id here? The provider id?
        // How do we make sure that session plugin doesn't kill us?
        let cred_id = self.user_cred_id;

        // We need a way to bubble up extra session metadata now.
        // Need to pass up the expiry, token, refresh token.
        let ext_session_metadata = SessionExtMetadata::OAuth2 {
            access_token,
            refresh_token,
            access_expires_at,
        };

        (
            SessionState::Finished,
            CredState::Success {
                auth_type: AuthType::OAuth2Trust,
                cred_id,
                ext_session_metadata,
            },
        )
    }
}

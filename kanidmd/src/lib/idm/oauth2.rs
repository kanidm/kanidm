//! Oauth2 resource server configurations
//!
//! This contains the in memory and loaded set of active oauth2 resource server
//! integrations, which are then able to be used an accessed from the IDM layer
//! for operations involving oauth2 authentication processing.
//!

use crate::identity::IdentityId;
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerTransaction};
use crate::prelude::*;
use crate::value::OAUTHSCOPE_RE;
pub use compact_jwt::{JwkKeySet, OidcToken};
use compact_jwt::{JwsSigner, OidcClaims, OidcSubject};
use concread::cowcell::*;
use fernet::Fernet;
use hashbrown::HashMap;
use kanidm_proto::v1::{AuthType, UserAuthToken};
use openssl::sha;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::trace;
use url::{Origin, Url};
use webauthn_rs::base64_data::Base64UrlSafeData;

pub use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationRequest, CodeChallengeMethod, ConsentRequest, ErrorResponse,
    OidcDiscoveryResponse,
};
use kanidm_proto::oauth2::{
    ClaimType, DisplayValue, GrantType, IdTokenSignAlg, ResponseMode, ResponseType, SubjectType,
    TokenEndpointAuthMethod,
};

use std::convert::TryFrom;
use std::time::Duration;

lazy_static! {
    static ref CLASS_OAUTH2: PartialValue = PartialValue::new_class("oauth2_resource_server");
    static ref CLASS_OAUTH2_BASIC: PartialValue =
        PartialValue::new_class("oauth2_resource_server_basic");
    static ref URL_SERVICE_DOCUMENTATION: Url =
        Url::parse("https://kanidm.github.io/kanidm/oauth2.html")
            .expect("Failed to parse oauth2 service documentation url");
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Oauth2Error {
    // Non-standard - these are used to guide some control flow.
    AuthenticationRequired,
    InvalidClientId,
    InvalidOrigin,
    // Standard
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError(OperationError),
    TemporarilyUnavailable,
    // from https://datatracker.ietf.org/doc/html/rfc6750
    InvalidToken,
    InsufficientScope,
}

impl std::fmt::Display for Oauth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Oauth2Error::AuthenticationRequired => "authentication_required",
            Oauth2Error::InvalidClientId => "invalid_client_id",
            Oauth2Error::InvalidOrigin => "invalid_origin",
            Oauth2Error::InvalidRequest => "invalid_request",
            Oauth2Error::UnauthorizedClient => "unauthorized_client",
            Oauth2Error::AccessDenied => "access_denied",
            Oauth2Error::UnsupportedResponseType => "unsupported_response_type",
            Oauth2Error::InvalidScope => "invalid_scope",
            Oauth2Error::ServerError(_) => "server_error",
            Oauth2Error::TemporarilyUnavailable => "temporarily_unavailable",
            Oauth2Error::InvalidToken => "invalid_token",
            Oauth2Error::InsufficientScope => "insufficient_scope",
        })
    }
}

// == internal state formats that we encrypt and send.

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ConsentToken {
    pub client_id: String,
    // Must match the session id of the Uat,
    pub session_id: Uuid,
    // So we can ensure that we really match the same uat to prevent confusions.
    pub ident_id: IdentityId,
    // CSRF
    pub state: String,
    // The S256 code challenge.
    pub code_challenge: Option<Base64UrlSafeData>,
    // Where the RS wants us to go back to.
    pub redirect_uri: Url,
    // The scopes being granted
    pub scopes: Vec<String>,
    // We stash some details here for oidc.
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenExchangeCode {
    // We don't need the client_id here, because it's signed with an RS specific
    // key which gives us the assurance that it's the correct combination.
    pub uat: UserAuthToken,
    // The S256 code challenge.
    pub code_challenge: Option<Base64UrlSafeData>,
    // The original redirect uri
    pub redirect_uri: Url,
    // The scopes being granted
    pub scopes: Vec<String>,
    // We stash some details here for oidc.
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
enum Oauth2TokenType {
    Access(Oauth2AccessToken),
    Refresh,
}

impl fmt::Display for Oauth2TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Oauth2TokenType::Access(_) => write!(f, "access_token"),
            Oauth2TokenType::Refresh => write!(f, "refresh_token"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Oauth2AccessToken {
    pub scopes: Vec<String>,
    pub session_id: Uuid,
    pub auth_type: AuthType,
    pub expiry: time::OffsetDateTime,
    pub uuid: Uuid,
    pub iat: i64,
    pub nbf: i64,
    pub auth_time: Option<i64>,
}

#[derive(Debug)]
pub struct AuthorisePermitSuccess {
    // Where the RS wants us to go back to.
    pub redirect_uri: Url,
    // The CSRF as a string
    pub state: String,
    // The exchange code as a String
    pub code: String,
}

#[derive(Clone)]
pub struct Oauth2RS {
    name: String,
    displayname: String,
    uuid: Uuid,
    origin: Origin,
    // Do we need optional maps?
    scope_maps: BTreeMap<Uuid, BTreeSet<String>>,
    implicit_scopes: Vec<String>,
    // Client Auth Type (basic is all we support for now.
    authz_secret: String,
    // Our internal exchange encryption material for this rs.
    token_fernet: Fernet,
    jws_signer: JwsSigner,
    // jws_validator: JwsValidator,
    // Some clients, especially openid ones don't do pkce. SIGH.
    // Can we enforce nonce in this case?
    enable_pkce: bool,
    // For oidc we also need our issuer url.
    iss: Url,
    // For discovery we need to build and keep a number of values.
    authorization_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Url,
    jwks_uri: Url,
    scopes_supported: Vec<String>,
}

impl std::fmt::Debug for Oauth2RS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Oauth2RS")
            .field("name", &self.name)
            .field("displayname", &self.displayname)
            .field("uuid", &self.uuid)
            .field("origin", &self.origin)
            .field("scope_maps", &self.scope_maps)
            .field("implicit_scopes", &self.implicit_scopes)
            .finish()
    }
}

#[derive(Clone)]
struct Oauth2RSInner {
    origin: Url,
    fernet: Fernet,
    rs_set: HashMap<String, Oauth2RS>,
}

pub struct Oauth2ResourceServers {
    inner: CowCell<Oauth2RSInner>,
}

pub struct Oauth2ResourceServersReadTransaction {
    inner: CowCellReadTxn<Oauth2RSInner>,
}

pub struct Oauth2ResourceServersWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, Oauth2RSInner>,
}

impl TryFrom<(Vec<Arc<EntrySealedCommitted>>, Url)> for Oauth2ResourceServers {
    type Error = OperationError;

    fn try_from(value: (Vec<Arc<EntrySealedCommitted>>, Url)) -> Result<Self, Self::Error> {
        let (value, origin) = value;
        let fernet =
            Fernet::new(&Fernet::generate_key()).ok_or(OperationError::CryptographyError)?;
        let oauth2rs = Oauth2ResourceServers {
            inner: CowCell::new(Oauth2RSInner {
                origin,
                fernet,
                rs_set: HashMap::new(),
            }),
        };

        let mut oauth2rs_wr = oauth2rs.write();
        oauth2rs_wr.reload(value)?;
        oauth2rs_wr.commit();
        Ok(oauth2rs)
    }
}

impl Oauth2ResourceServers {
    pub fn read(&self) -> Oauth2ResourceServersReadTransaction {
        Oauth2ResourceServersReadTransaction {
            inner: self.inner.read(),
        }
    }

    pub fn write(&self) -> Oauth2ResourceServersWriteTransaction {
        Oauth2ResourceServersWriteTransaction {
            inner: self.inner.write(),
        }
    }
}

impl<'a> Oauth2ResourceServersWriteTransaction<'a> {
    pub fn reload(&mut self, value: Vec<Arc<EntrySealedCommitted>>) -> Result<(), OperationError> {
        let rs_set: Result<HashMap<_, _>, _> = value
            .into_iter()
            .map(|ent| {
                let uuid = *ent.get_uuid();
                admin_info!(?uuid, "Checking oauth2 configuration");
                // From each entry, attempt to make an oauth2 configuration.
                if !ent.attribute_equality("class", &CLASS_OAUTH2) {
                    admin_error!("Missing class oauth2_resource_server");
                    // Check we have oauth2_resource_server class
                    Err(OperationError::InvalidEntryState)
                } else if ent.attribute_equality("class", &CLASS_OAUTH2_BASIC) {
                    // If we have oauth2_resource_server_basic
                    // Now we know we can load the attrs.
                    trace!("name");
                    let name = ent
                        .get_ava_single_str("oauth2_rs_name")
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;
                    trace!("displayname");
                    let displayname = ent
                        .get_ava_single_str("displayname")
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;
                    trace!("origin");
                    let origin = ent
                        .get_ava_single_url("oauth2_rs_origin")
                        .map(|url| url.origin())
                        .ok_or(OperationError::InvalidValueState)?;
                    trace!("authz_secret");
                    let authz_secret = ent
                        .get_ava_single_str("oauth2_rs_basic_secret")
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;
                    trace!("token_key");
                    let token_fernet = ent
                        .get_ava_single_secret("oauth2_rs_token_key")
                        .ok_or(OperationError::InvalidValueState)
                        .and_then(|key| {
                            Fernet::new(key).ok_or(OperationError::CryptographyError)
                        })?;

                    trace!("scope_maps");
                    let scope_maps = ent
                        .get_ava_as_oauthscopemaps("oauth2_rs_scope_map")
                        .cloned()
                        .unwrap_or_else(BTreeMap::new);

                    trace!("implicit_scopes");
                    let implicit_scopes = ent
                        .get_ava_as_oauthscopes("oauth2_rs_implicit_scopes")
                        .map(|iter| iter.map(str::to_string).collect())
                        .unwrap_or_else(Vec::new);

                    trace!("oauth2_jwt_legacy_crypto_enable");
                    let jws_signer = if ent.get_ava_single_bool("oauth2_jwt_legacy_crypto_enable").unwrap_or(false) {
                        trace!("rs256_private_key_der");
                        ent
                            .get_ava_single_private_binary("rs256_private_key_der")
                            .ok_or(OperationError::InvalidValueState)
                            .and_then(|key_der| {
                                JwsSigner::from_rs256_der(key_der).map_err(|e| {
                                    admin_error!(err = ?e, "Unable to load Legacy RS256 JwsSigner from DER");
                                    OperationError::CryptographyError
                                })
                            })?
                    } else {
                        trace!("es256_private_key_der");
                        ent
                            .get_ava_single_private_binary("es256_private_key_der")
                            .ok_or(OperationError::InvalidValueState)
                            .and_then(|key_der| {
                                JwsSigner::from_es256_der(key_der).map_err(|e| {
                                    admin_error!(err = ?e, "Unable to load ES256 JwsSigner from DER");
                                    OperationError::CryptographyError
                                })
                            })?
                    };

                    /*
                    let jws_validator = jws_signer.get_validator().map_err(|e| {
                        admin_error!(err = ?e, "Unable to load JwsValidator from JwsSigner");
                        OperationError::CryptographyError
                    })?;
                    */

                    let enable_pkce = ent
                        .get_ava_single_bool("oauth2_allow_insecure_client_disable_pkce")
                        .map(|e| !e)
                        .unwrap_or(true);

                    let mut authorization_endpoint = self.inner.origin.clone();
                    authorization_endpoint.set_path("/ui/oauth2");

                    let mut token_endpoint = self.inner.origin.clone();
                    token_endpoint.set_path("/oauth2/token");

                    let mut userinfo_endpoint = self.inner.origin.clone();
                    userinfo_endpoint.set_path(&format!("/oauth2/openid/{}/userinfo", name));

                    let mut jwks_uri = self.inner.origin.clone();
                    jwks_uri.set_path(&format!("/oauth2/openid/{}/public_key.jwk", name));

                    let mut iss = self.inner.origin.clone();
                    iss.set_path(&format!("/oauth2/openid/{}", name));

                    let scopes_supported: BTreeSet<String> = implicit_scopes
                        .iter()
                        .cloned()
                        .chain(scope_maps.values().map(|bts| bts.iter()).flatten().cloned())
                        .collect();
                    let scopes_supported: Vec<_> = scopes_supported.into_iter().collect();

                    let client_id = name.clone();
                    let rscfg = Oauth2RS {
                        name,
                        displayname,
                        uuid,
                        origin,
                        scope_maps,
                        implicit_scopes,
                        authz_secret,
                        token_fernet,
                        jws_signer,
                        // jws_validator,
                        enable_pkce,
                        iss,
                        authorization_endpoint,
                        token_endpoint,
                        userinfo_endpoint,
                        jwks_uri,
                        scopes_supported,
                    };

                    Ok((client_id, rscfg))
                } else {
                    Err(OperationError::InvalidEntryState)
                }
            })
            .collect();

        rs_set.map(|mut rs_set| {
            // Delay getting the inner mut (which may clone) until we know we are ok.
            let inner_ref = self.inner.get_mut();
            // Swap them if we are ok
            std::mem::swap(&mut inner_ref.rs_set, &mut rs_set);
        })
    }

    pub fn commit(self) {
        self.inner.commit();
    }
}

impl Oauth2ResourceServersReadTransaction {
    pub fn check_oauth2_authorisation(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        auth_req: &AuthorisationRequest,
        ct: Duration,
    ) -> Result<ConsentRequest, Oauth2Error> {
        // due to identity processing we already know that:
        // * the session must be authenticated, and valid
        // * is within it's valid time window.
        trace!(?auth_req);

        if auth_req.response_type != "code" {
            admin_warn!("Invalid oauth2 response_type (should be 'code')");
            return Err(Oauth2Error::UnsupportedResponseType);
        }

        /*
         * 4.1.2.1.  Error Response
         *
         * If the request fails due to a missing, invalid, or mismatching
         * redirection URI, or if the client identifier is missing or invalid,
         * the authorization server SHOULD inform the resource owner of the
         * error and MUST NOT automatically redirect the user-agent to the
         * invalid redirection URI.
         */

        //
        let o2rs = self.inner.rs_set.get(&auth_req.client_id).ok_or_else(|| {
            admin_warn!(
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            Oauth2Error::InvalidClientId
        })?;

        // redirect_uri must be part of the client_id origin.
        if auth_req.redirect_uri.origin() != o2rs.origin {
            admin_warn!(
                origin = ?o2rs.origin,
                "Invalid oauth2 redirect_uri (must be related to origin of)"
            );
            return Err(Oauth2Error::InvalidOrigin);
        }

        let code_challenge = if let Some(pkce_request) = &auth_req.pkce_request {
            // CodeChallengeMethod must be S256
            if pkce_request.code_challenge_method != CodeChallengeMethod::S256 {
                admin_warn!("Invalid oauth2 code_challenge_method (must be 'S256')");
                return Err(Oauth2Error::InvalidRequest);
            }
            Some(pkce_request.code_challenge.clone())
        } else if o2rs.enable_pkce {
            security_error!(?o2rs.name, "No PKCE code challenge was provided with client in enforced PKCE mode.");
            return Err(Oauth2Error::InvalidRequest);
        } else {
            security_info!(?o2rs.name, "Insecure client configuration - pkce is not enforced.");
            None
        };

        // TODO: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
        // Are we going to provide the functions for these? Most of these can be "later".
        // IF CHANGED: Update OidcDiscoveryResponse!!!

        // TODO: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
        // prompt - if set to login, we need to force a re-auth. But we don't want to
        // if the user "only just" logged in, that's annoying. So we need a time window for
        // this, to detect when we should force it to the consent req.

        // TODO: display = popup vs touch vs wap etc.

        // TODO: max_age, pass through with consent req. If 0, force login.
        // Otherwise force a login re the uat timeout.

        // TODO: ui_locales / claims_locales for the ui. Only if we don't have a Uat that
        // would provide this.

        // TODO: id_token_hint - a past token which can be used as a hint.

        // NOTE: login_hint is handled in the UI code, not here.

        // Deny any uat with an auth method of anonymous
        if uat.auth_type == AuthType::Anonymous {
            admin_error!(
                "Invalid oauth2 request - refusing to allow user that authenticated with anonymous"
            );
            return Err(Oauth2Error::AccessDenied);
        }

        // scopes - you need to have every requested scope or this req is denied.
        let req_scopes: BTreeSet<_> = auth_req.scope.split_ascii_whitespace().collect();
        if req_scopes.is_empty() {
            admin_error!("Invalid oauth2 request - must contain at least one requested scope");
            return Err(Oauth2Error::InvalidRequest);
        }

        // TODO: Check the scopes by our scope RE rules.
        // Oauth2Error::InvalidScope
        if !req_scopes.iter().all(|s| OAUTHSCOPE_RE.is_match(s)) {
            admin_error!(
                "Invalid oauth2 request - requested scopes failed to pass validation rules"
            );
            return Err(Oauth2Error::InvalidScope);
        }

        let uat_scopes: BTreeSet<_> = o2rs
            .implicit_scopes
            .iter()
            .map(|s| s.as_str())
            .chain(
                o2rs.scope_maps
                    .iter()
                    .filter_map(|(u, m)| {
                        if ident.is_memberof(*u) {
                            Some(m.iter().map(|s| s.as_str()))
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .collect();

        // Needs to use s.to_string due to &&str which can't use the str::to_string
        let avail_scopes: Vec<String> = req_scopes
            .intersection(&uat_scopes)
            .map(|s| s.to_string())
            .collect();

        if avail_scopes.len() != req_scopes.len() {
            admin_warn!(
                %ident,
                %auth_req.scope,
                "Identity does not have access to the requested scopes"
            );
            return Err(Oauth2Error::AccessDenied);
        }

        // Subseqent we then return an encrypted session handle which allows
        // the user to indicate their consent to this authorisation.
        //
        // This session handle is what we use in "permit" to generate the redirect.

        let consent_req = ConsentToken {
            client_id: auth_req.client_id.clone(),
            ident_id: ident.get_event_origin_id(),
            session_id: uat.session_id,
            state: auth_req.state.clone(),
            code_challenge,
            redirect_uri: auth_req.redirect_uri.clone(),
            scopes: avail_scopes.clone(),
            nonce: auth_req.nonce.clone(),
        };

        let consent_data = serde_json::to_vec(&consent_req).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode consent data");
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let consent_token = self
            .inner
            .fernet
            .encrypt_at_time(&consent_data, ct.as_secs());

        Ok(ConsentRequest {
            client_name: o2rs.displayname.clone(),
            scopes: avail_scopes,
            consent_token,
        })
    }

    pub fn check_oauth2_authorise_permit(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        consent_token: &str,
        ct: Duration,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        // Decode the consent req with our system fernet key. Use a ttl of 5 minutes.
        let consent_req: ConsentToken = self
            .inner
            .fernet
            .decrypt_at_time(consent_token, Some(300), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise consent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            security_info!("consent request ident id does not match the identity of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our uat.
        if consent_req.session_id != uat.session_id {
            security_info!("consent request sessien id does not match the session id of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Get the resource server config based on this client_id.
        let o2rs = self
            .inner
            .rs_set
            .get(&consent_req.client_id)
            .ok_or_else(|| {
                admin_error!("Invalid consent request oauth2 client_id");
                OperationError::InvalidRequestState
            })?;

        // Extract the state, code challenge, redirect_uri

        let xchg_code = TokenExchangeCode {
            uat: uat.clone(),
            code_challenge: consent_req.code_challenge,
            redirect_uri: consent_req.redirect_uri.clone(),
            scopes: consent_req.scopes,
            nonce: consent_req.nonce,
        };

        // Encrypt the exchange token with the fernet key of the client resource server
        let code_data = serde_json::to_vec(&xchg_code).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode xchg_code data");
            OperationError::SerdeJsonError
        })?;

        let code = o2rs.token_fernet.encrypt_at_time(&code_data, ct.as_secs());

        Ok(AuthorisePermitSuccess {
            redirect_uri: consent_req.redirect_uri,
            state: consent_req.state,
            code,
        })
    }

    pub fn check_oauth2_authorise_reject(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        consent_token: &str,
        ct: Duration,
    ) -> Result<Url, OperationError> {
        // Decode the consent req with our system fernet key. Use a ttl of 5 minutes.
        let consent_req: ConsentToken = self
            .inner
            .fernet
            .decrypt_at_time(consent_token, Some(300), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise consent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            security_info!("consent request ident id does not match the identity of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our uat.
        if consent_req.session_id != uat.session_id {
            security_info!("consent request sessien id does not match the session id of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Get the resource server config based on this client_id.
        let _o2rs = self
            .inner
            .rs_set
            .get(&consent_req.client_id)
            .ok_or_else(|| {
                admin_error!("Invalid consent request oauth2 client_id");
                OperationError::InvalidRequestState
            })?;

        // All good, now confirm the rejection to the client application.
        Ok(consent_req.redirect_uri)
    }

    pub fn check_oauth2_token_exchange(
        &self,
        client_authz: Option<&str>,
        token_req: &AccessTokenRequest,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        if token_req.grant_type != "authorization_code" {
            admin_warn!("Invalid oauth2 grant_type (should be 'authorization_code')");
            return Err(Oauth2Error::InvalidRequest);
        }

        let (client_id, secret) = if let Some(client_authz) = client_authz {
            parse_basic_authz(client_authz)?
        } else {
            match (&token_req.client_id, &token_req.client_secret) {
                (Some(a), Some(b)) => (a.clone(), b.clone()),
                _ => {
                    security_info!(
                        "Invalid oauth2 authentication - no basic auth or missing auth post data"
                    );
                    return Err(Oauth2Error::AuthenticationRequired);
                }
            }
        };

        // Get the o2rs for the handle.
        let o2rs = self.inner.rs_set.get(&client_id).ok_or_else(|| {
            admin_warn!("Invalid oauth2 client_id");
            Oauth2Error::AuthenticationRequired
        })?;

        // check the secret.
        if o2rs.authz_secret != secret {
            security_info!("Invalid oauth2 client_id secret");
            return Err(Oauth2Error::AuthenticationRequired);
        }
        // We are authenticated! Yay! Now we can actually check things ...

        // Check the token_req is within the valid time, and correctly signed for
        // this client.

        let code_xchg: TokenExchangeCode = o2rs
            .token_fernet
            .decrypt_at_time(&token_req.code, Some(60), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt token exchange request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token exchange code - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        if let Some(code_challenge) = code_xchg.code_challenge {
            // Validate the code_verifier
            let code_verifier = token_req.code_verifier
                    .as_deref()
                    .ok_or_else(|| {
                        security_info!("PKCE code verification failed - code challenge is present, but not verifier was provided");
                        Oauth2Error::InvalidRequest
                    })?;
            let mut hasher = sha::Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let code_verifier_hash: Vec<u8> = hasher.finish().iter().copied().collect();

            if code_challenge.0 != code_verifier_hash {
                security_info!(
                    "PKCE code verification failed - this may indicate malicious activity"
                );
                return Err(Oauth2Error::InvalidRequest);
            }
        } else if o2rs.enable_pkce {
            security_info!(
                "PKCE code verification failed - no code challenge present in PKCE enforced mode"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        // Validate the redirect_uri is the same as the original.
        if token_req.redirect_uri != code_xchg.redirect_uri {
            security_info!("Invalid oauth2 redirect_uri (differs from original request uri)");
            return Err(Oauth2Error::InvalidRequest);
        }

        // ==== We are now GOOD TO GO! ====

        // Use this to grant the access token response.
        let odt_ct = OffsetDateTime::unix_epoch() + ct;

        let iat = ct.as_secs() as i64;

        // TODO: Make configurable from auth policy!
        let expires_in = if code_xchg.uat.expiry > odt_ct {
            // Becomes a duration.
            (code_xchg.uat.expiry - odt_ct).whole_seconds() as u32
        } else {
            security_info!(
                "User Auth Token has expired before we could publish the oauth2 response"
            );
            return Err(Oauth2Error::AccessDenied);
        };

        let scope = if code_xchg.scopes.is_empty() {
            None
        } else {
            Some(code_xchg.scopes.join(" "))
        };

        let scope_set: BTreeSet<String> = code_xchg.scopes.iter().cloned().collect();

        let id_token = if scope_set.contains("openid") {
            // TODO: Scopes map to claims:
            //
            // * profile - (name, family\_name, given\_name, middle\_name, nickname, preferred\_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated\_at)
            // * email - (email, email\_verified)
            // * address - (address)
            // * phone - (phone\_number, phone\_number\_verified)
            //
            // https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims

            // TODO: Can the user consent to which claims are released? Today as we don't support most
            // of them anyway, no, but in the future, we can stash these to the consent req.

            let (email, email_verified) = if scope_set.contains("email") {
                if let Some(mp) = code_xchg.uat.mail_primary {
                    (Some(mp), Some(true))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // TODO: If max_age was requested in the request, we MUST provide auth_time.

            // amr == auth method
            let amr = Some(vec![code_xchg.uat.auth_type.to_string()]);

            // TODO: Make configurable from auth policy!
            let exp = iat + (expires_in as i64);

            let iss = o2rs.iss.clone();

            let oidc = OidcToken {
                iss,
                sub: OidcSubject::U(code_xchg.uat.uuid),
                aud: client_id.clone(),
                iat,
                nbf: Some(iat),
                exp,
                auth_time: None,
                nonce: code_xchg.nonce.clone(),
                at_hash: None,
                acr: None,
                amr,
                azp: Some(client_id.clone()),
                jti: None,
                s_claims: OidcClaims {
                    // Map from displayname
                    name: Some(code_xchg.uat.displayname.clone()),
                    // Map from spn
                    preferred_username: Some(code_xchg.uat.spn.clone()),
                    scopes: code_xchg.scopes.clone(),
                    email,
                    email_verified,
                    ..Default::default()
                },
                claims: Default::default(),
            };

            trace!(?oidc);

            Some(
                oidc.sign_with_kid(&o2rs.jws_signer, &client_id)
                    .map(|jwt_signed| jwt_signed.to_string())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to encode uat data");
                        Oauth2Error::ServerError(OperationError::InvalidState)
                    })?,
            )
        } else {
            None
        };

        // TODO: Refresh tokens!
        let access_token_raw = Oauth2TokenType::Access(Oauth2AccessToken {
            scopes: code_xchg.scopes,
            session_id: code_xchg.uat.session_id,
            auth_type: code_xchg.uat.auth_type,
            expiry: code_xchg.uat.expiry,
            uuid: code_xchg.uat.uuid,
            iat,
            nbf: iat,
            auth_time: None,
        });

        let access_token_data = serde_json::to_vec(&access_token_raw).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode consent data");
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let access_token = o2rs
            .token_fernet
            .encrypt_at_time(&access_token_data, ct.as_secs());

        Ok(AccessTokenResponse {
            access_token,
            token_type: "bearer".to_string(),
            expires_in,
            refresh_token: None,
            scope,
            id_token,
        })
    }

    pub fn check_oauth2_token_introspect(
        &self,
        idms: &IdmServerProxyReadTransaction<'_>,
        client_authz: &str,
        intr_req: &AccessTokenIntrospectRequest,
        ct: Duration,
    ) -> Result<AccessTokenIntrospectResponse, Oauth2Error> {
        let (client_id, secret) = parse_basic_authz(client_authz)?;

        // Get the o2rs for the handle.
        let o2rs = self.inner.rs_set.get(&client_id).ok_or_else(|| {
            admin_warn!("Invalid oauth2 client_id");
            Oauth2Error::AuthenticationRequired
        })?;

        // check the secret.
        if o2rs.authz_secret != secret {
            security_info!("Invalid oauth2 client_id secret");
            return Err(Oauth2Error::AuthenticationRequired);
        }
        // We are authenticated! Yay! Now we can actually check things ...

        let token: Oauth2TokenType = o2rs
            .token_fernet
            .decrypt(&intr_req.token)
            .map_err(|_| {
                admin_error!("Failed to decrypt token introspection request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token exchange code - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        match token {
            Oauth2TokenType::Access(at) => {
                // Has this token expired?
                let odt_ct = OffsetDateTime::unix_epoch() + ct;
                if at.expiry <= odt_ct {
                    security_info!(?at.uuid, "access token has expired, returning inactive");
                    return Ok(AccessTokenIntrospectResponse::inactive());
                }
                let exp = at.iat + ((at.expiry - odt_ct).whole_seconds() as i64);

                // Is the user expired?
                let valid = idms
                    .check_account_uuid_valid(&at.uuid, ct)
                    .map_err(|_| admin_error!("Account is not valid"));

                let account = match valid {
                    Ok(Some(account)) => account,
                    _ => {
                        security_info!(?at.uuid, "access token has account not valid, returning inactive");
                        return Ok(AccessTokenIntrospectResponse::inactive());
                    }
                };

                // ==== good to generate response ====

                let scope = if at.scopes.is_empty() {
                    None
                } else {
                    Some(at.scopes.join(" "))
                };

                let token_type = Some("access_token".to_string());
                Ok(AccessTokenIntrospectResponse {
                    active: true,
                    scope,
                    client_id: Some(client_id.clone()),
                    username: Some(account.spn),
                    token_type,
                    exp: Some(exp),
                    iat: Some(at.iat),
                    nbf: Some(at.nbf),
                    sub: Some(at.uuid.to_string()),
                    aud: Some(client_id),
                    iss: None,
                    jti: None,
                })
            }
            Oauth2TokenType::Refresh => Ok(AccessTokenIntrospectResponse::inactive()),
        }
    }

    pub fn oauth2_openid_userinfo(
        &self,
        idms: &IdmServerProxyReadTransaction<'_>,
        client_id: &str,
        client_authz: &str,
        ct: Duration,
    ) -> Result<OidcToken, Oauth2Error> {
        let o2rs = self.inner.rs_set.get(client_id).ok_or_else(|| {
            admin_warn!(
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            Oauth2Error::InvalidClientId
        })?;

        let token: Oauth2TokenType = o2rs
            .token_fernet
            .decrypt(client_authz)
            .map_err(|_| {
                admin_error!("Failed to decrypt token introspection request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token exchange code - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        match token {
            Oauth2TokenType::Access(at) => {
                // Has this token expired?
                let odt_ct = OffsetDateTime::unix_epoch() + ct;
                if at.expiry <= odt_ct {
                    security_info!(?at.uuid, "access token has expired, returning inactive");
                    return Err(Oauth2Error::InvalidToken);
                }
                let exp = at.iat + ((at.expiry - odt_ct).whole_seconds() as i64);

                // Is the user expired?
                let valid = idms
                    .check_account_uuid_valid(&at.uuid, ct)
                    .map_err(|_| admin_error!("Account is not valid"));

                let account = match valid {
                    Ok(Some(account)) => account,
                    _ => {
                        security_info!(?at.uuid, "access token has account not valid, returning inactive");
                        return Err(Oauth2Error::InvalidToken);
                    }
                };

                let (email, email_verified) = if at.scopes.contains(&"email".to_string()) {
                    if let Some(mp) = account.mail_primary {
                        (Some(mp), Some(true))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                let amr = Some(vec![at.auth_type.to_string()]);

                let iss = o2rs.iss.clone();

                // ==== good to generate response ====

                Ok(OidcToken {
                    iss,
                    sub: OidcSubject::U(at.uuid),
                    aud: client_id.to_string(),
                    iat: at.iat,
                    nbf: Some(at.nbf),
                    exp,
                    auth_time: None,
                    nonce: None,
                    at_hash: None,
                    acr: None,
                    amr,
                    azp: Some(client_id.to_string()),
                    jti: None,
                    s_claims: OidcClaims {
                        // Map from displayname
                        name: Some(account.displayname.clone()),
                        // Map from spn
                        preferred_username: Some(account.spn),
                        scopes: at.scopes,
                        email,
                        email_verified,
                        ..Default::default()
                    },
                    claims: Default::default(),
                })
            }
            // https://openid.net/specs/openid-connect-basic-1_0.html#UserInfoErrorResponse
            Oauth2TokenType::Refresh => Err(Oauth2Error::InvalidToken),
        }
    }

    pub fn oauth2_openid_discovery(
        &self,
        client_id: &str,
    ) -> Result<OidcDiscoveryResponse, OperationError> {
        let o2rs = self.inner.rs_set.get(client_id).ok_or_else(|| {
            admin_warn!(
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            OperationError::NoMatchingEntries
        })?;

        let issuer = o2rs.iss.clone();

        let authorization_endpoint = o2rs.authorization_endpoint.clone();
        let token_endpoint = o2rs.token_endpoint.clone();
        let userinfo_endpoint = Some(o2rs.userinfo_endpoint.clone());
        let jwks_uri = o2rs.jwks_uri.clone();
        let scopes_supported = Some(o2rs.scopes_supported.clone());
        let response_types_supported = vec![ResponseType::Code];
        let response_modes_supported = vec![ResponseMode::Query];
        let grant_types_supported = vec![GrantType::AuthorisationCode];
        let subject_types_supported = vec![SubjectType::Public];

        let id_token_signing_alg_values_supported = match &o2rs.jws_signer {
            JwsSigner::ES256 { .. } => vec![IdTokenSignAlg::ES256],
            JwsSigner::RS256 { .. } => vec![IdTokenSignAlg::RS256],
            JwsSigner::HS256 { .. } => {
                admin_warn!("Invalid oauth2 configuration - HS256 is not supported!");
                vec![]
            }
        };

        let userinfo_signing_alg_values_supported = None;
        let token_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];
        let display_values_supported = Some(vec![DisplayValue::Page]);
        let claim_types_supported = vec![ClaimType::Normal];
        // What claims can we offer?
        let claims_supported = None;
        let service_documentation = Some(URL_SERVICE_DOCUMENTATION.clone());

        Ok(OidcDiscoveryResponse {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
            registration_endpoint: None,
            scopes_supported,
            response_types_supported,
            response_modes_supported,
            grant_types_supported,
            acr_values_supported: None,
            subject_types_supported,
            id_token_signing_alg_values_supported,
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported,
            token_endpoint_auth_signing_alg_values_supported: None,
            display_values_supported,
            claim_types_supported,
            claims_supported,
            service_documentation,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: false,
            // I think?
            request_parameter_supported: true,
            request_uri_parameter_supported: false,
            require_request_uri_registration: false,
            op_policy_uri: None,
            op_tos_uri: None,
        })
    }

    pub fn oauth2_openid_publickey(&self, client_id: &str) -> Result<JwkKeySet, OperationError> {
        let o2rs = self.inner.rs_set.get(client_id).ok_or_else(|| {
            admin_warn!(
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            OperationError::NoMatchingEntries
        })?;

        o2rs.jws_signer
            .public_key_as_jwk(Some(&o2rs.name))
            .map_err(|e| {
                admin_error!("Unable to retrieve public key for {} - {:?}", o2rs.name, e);
                OperationError::InvalidState
            })
            .map(|jwk| JwkKeySet { keys: vec![jwk] })
    }
}

fn parse_basic_authz(client_authz: &str) -> Result<(String, String), Oauth2Error> {
    // Check the client_authz
    let authz = base64::decode(&client_authz)
        .map_err(|_| {
            admin_error!("Basic authz invalid base64");
            Oauth2Error::AuthenticationRequired
        })
        .and_then(|data| {
            String::from_utf8(data).map_err(|_| {
                admin_error!("Basic authz invalid utf8");
                Oauth2Error::AuthenticationRequired
            })
        })?;

    // Get the first :, it should be our delim.
    //
    let mut split_iter = authz.split(':');

    let client_id = split_iter.next().ok_or_else(|| {
        admin_error!("Basic authz invalid format (corrupt input?)");
        Oauth2Error::AuthenticationRequired
    })?;
    let secret = split_iter.next().ok_or_else(|| {
        admin_error!("Basic authz invalid format (missing ':' seperator?)");
        Oauth2Error::AuthenticationRequired
    })?;

    Ok((client_id.to_string(), secret.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::event::CreateEvent;
    use crate::idm::oauth2::Oauth2Error;
    use crate::idm::server::{IdmServer, IdmServerTransaction};
    use crate::prelude::*;

    use crate::event::ModifyEvent;

    use kanidm_proto::oauth2::*;
    use kanidm_proto::v1::{AuthType, UserAuthToken};
    use webauthn_rs::base64_data::Base64UrlSafeData;

    use compact_jwt::{JwaAlg, Jwk, JwkUse, JwsValidator, OidcSubject, OidcUnverified};

    use openssl::sha;

    use std::convert::TryFrom;
    use std::str::FromStr;
    use std::time::Duration;

    const TEST_CURRENT_TIME: u64 = 6000;
    const UAT_EXPIRE: u64 = 5;
    const TOKEN_EXPIRE: u64 = 900;

    macro_rules! create_code_verifier {
        ($key:expr) => {{
            let code_verifier = $key.to_string();
            let mut hasher = sha::Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let code_challenge: Vec<u8> = hasher.finish().iter().copied().collect();
            (Some(code_verifier), code_challenge)
        }};
    }

    macro_rules! good_authorisation_request {
        (
            $idms_prox_read:expr,
            $ident:expr,
            $uat:expr,
            $ct:expr,
            $code_challenge:expr
        ) => {{
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: Some(PkceRequest {
                    code_challenge: Base64UrlSafeData($code_challenge),
                    code_challenge_method: CodeChallengeMethod::S256,
                }),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "openid".to_string(),
                nonce: Some("abcdef".to_string()),
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            $idms_prox_read
                .check_oauth2_authorisation($ident, $uat, &auth_req, $ct)
                .expect("Oauth2 authorisation failed")
        }};
    }

    // setup an oauth2 instance.
    fn setup_oauth2_resource_server(
        idms: &IdmServer,
        ct: Duration,
        enable_pkce: bool,
        enable_legacy_crypto: bool,
    ) -> (String, UserAuthToken, Identity) {
        let mut idms_prox_write = idms.proxy_write(ct);

        let uuid = Uuid::new_v4();

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("uuid", Value::new_uuid(uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                "oauth2_rs_implicit_scopes",
                Value::new_oauthscope("openid").expect("invalid oauthscope")
            ),
            // System admins
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_SYSTEM_ADMINS, btreeset!["read".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                "oauth2_allow_insecure_client_disable_pkce",
                Value::new_bool(!enable_pkce)
            ),
            (
                "oauth2_jwt_legacy_crypto_enable",
                Value::new_bool(enable_legacy_crypto)
            )
        );
        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(&uuid)
            .expect("Failed to retrieve oauth2 resource entry ");
        let secret = entry
            .get_ava_single_str("oauth2_rs_basic_secret")
            .map(str::to_string)
            .expect("No oauth2_rs_basic_secret found");

        // Setup the uat we'll be using.
        let account = idms_prox_write
            .target_to_account(&UUID_ADMIN)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(session_id, ct, AuthType::PasswordMfa)
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (secret, uat, ident)
    }

    fn setup_idm_admin(
        idms: &IdmServer,
        ct: Duration,
        authtype: AuthType,
    ) -> (UserAuthToken, Identity) {
        let mut idms_prox_write = idms.proxy_write(ct);
        let account = idms_prox_write
            .target_to_account(&UUID_IDM_ADMIN)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(session_id, ct, authtype)
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (uat, ident)
    }

    #[test]
    fn test_idm_oauth2_basic_function() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);

            let idms_prox_read = idms.proxy_read();

            // Get an ident/uat for now.

            // == Setup the authorisation request
            let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(&ident, &uat, &consent_request.consent_token, ct)
                .expect("Failed to perform oauth2 permit");

            // Check we are reflecting the CSRF properly.
            assert!(permit_success.state == "123");

            // == Submit the token exchange code.

            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
                // From the first step.
                code_verifier,
            };

            let token_response = idms_prox_read
                .check_oauth2_token_exchange(None, &token_req, ct)
                .expect("Failed to perform oauth2 token exchange");

            // 🎉 We got a token! In the future we can then check introspection from this point.
            assert!(token_response.token_type == "bearer");
        })
    }

    #[test]
    fn test_idm_oauth2_invalid_authorisation_requests() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            // Test invalid oauth2 authorisation states/requests.
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);

            let (anon_uat, anon_ident) = setup_idm_admin(idms, ct, AuthType::Anonymous);
            let (idm_admin_uat, idm_admin_ident) = setup_idm_admin(idms, ct, AuthType::PasswordMfa);

            // Need a uat from a user not in the group. Probs anonymous.
            let idms_prox_read = idms.proxy_read();

            let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let pkce_request = Some(PkceRequest {
                code_challenge: Base64UrlSafeData(code_challenge.clone()),
                code_challenge_method: CodeChallengeMethod::S256,
            });

            //  * response type != code.
            let auth_req = AuthorisationRequest {
                response_type: "NOTCODE".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: pkce_request.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "openid".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::UnsupportedResponseType
            );

            // * No pkce in pkce enforced mode.
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: None,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "openid".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * invalid rs name
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "NOT A REAL RESOURCE SERVER".to_string(),
                state: "123".to_string(),
                pkce_request: pkce_request.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "openid".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidClientId
            );

            //  * mis match origin in the redirect.
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: pkce_request.clone(),
                redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
                scope: "openid".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidOrigin
            );

            // Requested scope is not available
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: pkce_request.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "invalid_scope read".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AccessDenied
            );

            // Not a member of the group.
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: pkce_request.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "read openid".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&idm_admin_ident, &idm_admin_uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AccessDenied
            );

            // Deny Anonymous auth methods
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: pkce_request.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "read openid".to_string(),
                nonce: None,
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(&anon_ident, &anon_uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AccessDenied
            );
        })
    }

    #[test]
    fn test_idm_oauth2_invalid_authorisation_permit_requests() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            // Test invalid oauth2 authorisation states/requests.
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);

            let (uat2, ident2) = {
                let mut idms_prox_write = idms.proxy_write(ct);
                let account = idms_prox_write
                    .target_to_account(&UUID_IDM_ADMIN)
                    .expect("account must exist");
                let session_id = uuid::Uuid::new_v4();
                let uat2 = account
                    .to_userauthtoken(session_id, ct, AuthType::PasswordMfa)
                    .expect("Unable to create uat");
                let ident2 = idms_prox_write
                    .process_uat_to_identity(&uat2, ct)
                    .expect("Unable to process uat");
                (uat2, ident2)
            };

            let idms_prox_read = idms.proxy_read();

            let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // Invalid permits
            //  * expired token, aka past ttl.
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_permit(
                        &ident,
                        &uat,
                        &consent_request.consent_token,
                        ct + Duration::from_secs(TOKEN_EXPIRE),
                    )
                    .unwrap_err()
                    == OperationError::CryptographyError
            );

            //  * incorrect ident
            // We get another uat, but for a different user, and we'll introduce these
            // inconsistently to cause confusion.

            assert!(
                idms_prox_read
                    .check_oauth2_authorise_permit(
                        &ident2,
                        &uat,
                        &consent_request.consent_token,
                        ct,
                    )
                    .unwrap_err()
                    == OperationError::InvalidSessionState
            );

            //  * incorrect session id
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_permit(
                        &ident,
                        &uat2,
                        &consent_request.consent_token,
                        ct,
                    )
                    .unwrap_err()
                    == OperationError::InvalidSessionState
            );
        })
    }

    #[test]
    fn test_idm_oauth2_invalid_token_exchange_requests() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, mut uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);

            // ⚠️  We set the uat expiry time to 5 seconds from TEST_CURRENT_TIME. This
            // allows all our other tests to pass, but it means when we specifically put the
            // clock forward a fraction, the fernet tokens are still valid, but the uat
            // is not.
            // IE
            //   |---------------------|------------------|
            //   TEST_CURRENT_TIME     UAT_EXPIRE         TOKEN_EXPIRE
            //
            // This lets us check a variety of time based cases.
            uat.expiry = time::OffsetDateTime::unix_epoch()
                + Duration::from_secs(TEST_CURRENT_TIME + UAT_EXPIRE - 1);

            let idms_prox_read = idms.proxy_read();

            // == Setup the authorisation request
            let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(&ident, &uat, &consent_request.consent_token, ct)
                .expect("Failed to perform oauth2 permit");

            // == Submit the token exchange code.

            // Invalid token exchange
            //  * invalid client_authz (not base64)
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                client_secret: None,
                // From the first step.
                code_verifier: code_verifier.clone(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(Some("not base64"), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            //  * doesn't have :
            let client_authz = Some(base64::encode(format!("test_resource_server {}", secret)));
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            //  * invalid client_id
            let client_authz = Some(base64::encode(format!("NOT A REAL SERVER:{}", secret)));
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            //  * valid client_id, but invalid secret
            let client_authz = Some(base64::encode("test_resource_server:12345"));
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            // ✅ Now the valid client_authz is in place.
            let client_authz = Some(base64::encode(format!("test_resource_server:{}", secret)));
            //  * expired exchange code (took too long)
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(
                        client_authz.as_deref(),
                        &token_req,
                        ct + Duration::from_secs(TOKEN_EXPIRE)
                    )
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * Uat has expired!
            // NOTE: This is setup EARLY in the test, by manipulation of the UAT expiry.
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(
                        client_authz.as_deref(),
                        &token_req,
                        ct + Duration::from_secs(UAT_EXPIRE)
                    )
                    .unwrap_err()
                    == Oauth2Error::AccessDenied
            );

            //  * incorrect grant_type
            let token_req = AccessTokenRequest {
                grant_type: "INCORRECT GRANT TYPE".to_string(),
                code: permit_success.code.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                client_secret: None,
                code_verifier: code_verifier.clone(),
            };
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * Incorrect redirect uri
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code.clone(),
                redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
                client_id: None,
                client_secret: None,
                code_verifier,
            };
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * code verifier incorrect
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                client_secret: None,
                code_verifier: Some("12345".to_string()),
            };
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );
        })
    }

    #[test]
    fn test_idm_oauth2_token_introspect() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);
            let client_authz = Some(base64::encode(format!("test_resource_server:{}", secret)));

            let idms_prox_read = idms.proxy_read();

            // == Setup the authorisation request
            let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(&ident, &uat, &consent_request.consent_token, ct)
                .expect("Failed to perform oauth2 permit");

            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                client_secret: None,
                code_verifier,
            };
            let oauth2_token = idms_prox_read
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .expect("Unable to exchange for oauth2 token");

            // Okay, now we have the token, we can check it works with introspect.
            let intr_request = AccessTokenIntrospectRequest {
                token: oauth2_token.access_token.clone(),
                token_type_hint: None,
            };
            let intr_response = idms_prox_read
                .check_oauth2_token_introspect(client_authz.as_deref().unwrap(), &intr_request, ct)
                .expect("Failed to inspect token");

            eprintln!("👉  {:?}", intr_response);
            assert!(intr_response.active);
            assert!(intr_response.scope.as_deref() == Some("openid"));
            assert!(intr_response.client_id.as_deref() == Some("test_resource_server"));
            assert!(intr_response.username.as_deref() == Some("admin@example.com"));
            assert!(intr_response.token_type.as_deref() == Some("access_token"));
            assert!(intr_response.iat == Some(ct.as_secs() as i64));
            assert!(intr_response.nbf == Some(ct.as_secs() as i64));

            drop(idms_prox_read);
            // start a write,

            let idms_prox_write = idms.proxy_write(ct);
            // Expire the account, should cause introspect to return inactive.
            let v_expire = Value::new_datetime_epoch(Duration::from_secs(TEST_CURRENT_TIME - 1));
            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("admin"))),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("account_expire"),
                        v_expire,
                    )]),
                )
            };
            // go!
            assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
            assert!(idms_prox_write.commit().is_ok());

            // start a new read
            // check again.
            let idms_prox_read = idms.proxy_read();
            let intr_response = idms_prox_read
                .check_oauth2_token_introspect(&client_authz.unwrap(), &intr_request, ct)
                .expect("Failed to inspect token");

            assert!(!intr_response.active);
        })
    }

    #[test]
    fn test_idm_oauth2_authorisation_reject() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);

            let (uat2, ident2) = {
                let mut idms_prox_write = idms.proxy_write(ct);
                let account = idms_prox_write
                    .target_to_account(&UUID_IDM_ADMIN)
                    .expect("account must exist");
                let session_id = uuid::Uuid::new_v4();
                let uat2 = account
                    .to_userauthtoken(session_id, ct, AuthType::PasswordMfa)
                    .expect("Unable to create uat");
                let ident2 = idms_prox_write
                    .process_uat_to_identity(&uat2, ct)
                    .expect("Unable to process uat");
                (uat2, ident2)
            };

            let idms_prox_read = idms.proxy_read();
            let redirect_uri = Url::parse("https://demo.example.com/oauth2/result").unwrap();
            let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            // Check reject behaviour
            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            let reject_success = idms_prox_read
                .check_oauth2_authorise_reject(&ident, &uat, &consent_request.consent_token, ct)
                .expect("Failed to perform oauth2 reject");

            assert!(reject_success == redirect_uri);

            // Too much time past to reject
            let past_ct = Duration::from_secs(TEST_CURRENT_TIME + 301);
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_reject(
                        &ident,
                        &uat,
                        &consent_request.consent_token,
                        past_ct
                    )
                    .unwrap_err()
                    == OperationError::CryptographyError
            );

            // Invalid consent token
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_reject(&ident, &uat, "not a token", ct)
                    .unwrap_err()
                    == OperationError::CryptographyError
            );

            // Wrong UAT
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_reject(
                        &ident,
                        &uat2,
                        &consent_request.consent_token,
                        ct
                    )
                    .unwrap_err()
                    == OperationError::InvalidSessionState
            );
            // Wrong ident
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_reject(
                        &ident2,
                        &uat,
                        &consent_request.consent_token,
                        ct
                    )
                    .unwrap_err()
                    == OperationError::InvalidSessionState
            );
        })
    }

    #[test]
    fn test_idm_oauth2_openid_discovery() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, _uat, _ident) = setup_oauth2_resource_server(idms, ct, true, false);

            let idms_prox_read = idms.proxy_read();

            // check the discovery end point works as we expect
            assert!(
                idms_prox_read
                    .oauth2_openid_discovery("nosuchclient")
                    .unwrap_err()
                    == OperationError::NoMatchingEntries
            );

            assert!(
                idms_prox_read
                    .oauth2_openid_publickey("nosuchclient")
                    .unwrap_err()
                    == OperationError::NoMatchingEntries
            );

            let discovery = idms_prox_read
                .oauth2_openid_discovery("test_resource_server")
                .expect("Failed to get discovery");

            let mut jwkset = idms_prox_read
                .oauth2_openid_publickey("test_resource_server")
                .expect("Failed to get public key");

            let jwk = jwkset.keys.pop().expect("no such jwk");

            match jwk {
                Jwk::EC { alg, use_, kid, .. } => {
                    match (
                        alg.unwrap(),
                        &discovery.id_token_signing_alg_values_supported[0],
                    ) {
                        (JwaAlg::ES256, IdTokenSignAlg::ES256) => {}
                        _ => panic!(),
                    };
                    assert!(use_.unwrap() == JwkUse::Sig);
                    assert!(kid.unwrap() == "test_resource_server")
                }
                _ => panic!(),
            };

            assert!(
                discovery.issuer
                    == Url::parse("https://idm.example.com/oauth2/openid/test_resource_server")
                        .unwrap()
            );

            assert!(
                discovery.authorization_endpoint
                    == Url::parse("https://idm.example.com/ui/oauth2").unwrap()
            );

            assert!(
                discovery.token_endpoint
                    == Url::parse("https://idm.example.com/oauth2/token").unwrap()
            );

            assert!(
                discovery.userinfo_endpoint
                    == Some(
                        Url::parse(
                            "https://idm.example.com/oauth2/openid/test_resource_server/userinfo"
                        )
                        .unwrap()
                    )
            );

            assert!(
                discovery.jwks_uri
                    == Url::parse(
                        "https://idm.example.com/oauth2/openid/test_resource_server/public_key.jwk"
                    )
                    .unwrap()
            );

            eprintln!("{:?}", discovery.scopes_supported);
            assert!(
                discovery.scopes_supported == Some(vec!["openid".to_string(), "read".to_string()])
            );

            assert!(discovery.response_types_supported == vec![ResponseType::Code]);
            assert!(discovery.response_modes_supported == vec![ResponseMode::Query]);
            assert!(discovery.grant_types_supported == vec![GrantType::AuthorisationCode]);
            assert!(discovery.subject_types_supported == vec![SubjectType::Public]);
            assert!(discovery.id_token_signing_alg_values_supported == vec![IdTokenSignAlg::ES256]);
            assert!(discovery.userinfo_signing_alg_values_supported.is_none());
            assert!(
                discovery.token_endpoint_auth_methods_supported
                    == vec![
                        TokenEndpointAuthMethod::ClientSecretBasic,
                        TokenEndpointAuthMethod::ClientSecretPost
                    ]
            );
            assert!(discovery.display_values_supported == Some(vec![DisplayValue::Page]));
            assert!(discovery.claim_types_supported == vec![ClaimType::Normal]);
            assert!(discovery.claims_supported.is_none());
            assert!(discovery.service_documentation.is_some());

            assert!(discovery.registration_endpoint.is_none());
            assert!(discovery.acr_values_supported.is_none());
            assert!(discovery.id_token_encryption_alg_values_supported.is_none());
            assert!(discovery.id_token_encryption_enc_values_supported.is_none());
            assert!(discovery.userinfo_encryption_alg_values_supported.is_none());
            assert!(discovery.userinfo_encryption_enc_values_supported.is_none());
            assert!(discovery
                .request_object_signing_alg_values_supported
                .is_none());
            assert!(discovery
                .request_object_encryption_alg_values_supported
                .is_none());
            assert!(discovery
                .request_object_encryption_enc_values_supported
                .is_none());
            assert!(discovery
                .token_endpoint_auth_signing_alg_values_supported
                .is_none());
            assert!(discovery.claims_locales_supported.is_none());
            assert!(discovery.ui_locales_supported.is_none());
            assert!(discovery.op_policy_uri.is_none());
            assert!(discovery.op_tos_uri.is_none());
            assert!(!discovery.claims_parameter_supported);
            assert!(!discovery.request_uri_parameter_supported);
            assert!(!discovery.require_request_uri_registration);
            assert!(discovery.request_parameter_supported);
        })
    }

    #[test]
    fn test_idm_oauth2_openid_extensions() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, uat, ident) = setup_oauth2_resource_server(idms, ct, true, false);
            let client_authz = Some(base64::encode(format!("test_resource_server:{}", secret)));

            let idms_prox_read = idms.proxy_read();

            let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(&ident, &uat, &consent_request.consent_token, ct)
                .expect("Failed to perform oauth2 permit");

            // == Submit the token exchange code.
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                client_secret: None,
                // From the first step.
                code_verifier,
            };

            let token_response = idms_prox_read
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .expect("Failed to perform oauth2 token exchange");

            // 🎉 We got a token!
            assert!(token_response.token_type == "bearer");

            let id_token = token_response.id_token.expect("No id_token in response!");
            let access_token = token_response.access_token;

            let mut jwkset = idms_prox_read
                .oauth2_openid_publickey("test_resource_server")
                .expect("Failed to get public key");
            let public_jwk = jwkset.keys.pop().expect("no such jwk");

            let jws_validator =
                JwsValidator::try_from(&public_jwk).expect("failed to build validator");

            let oidc_unverified =
                OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

            let iat = ct.as_secs() as i64;

            let oidc = oidc_unverified
                .validate(&jws_validator, iat)
                .expect("Failed to verify oidc");

            // Are the id_token values what we expect?
            assert!(
                oidc.iss
                    == Url::parse("https://idm.example.com/oauth2/openid/test_resource_server")
                        .unwrap()
            );
            assert!(oidc.sub == OidcSubject::U(*UUID_ADMIN));
            assert!(oidc.aud == "test_resource_server");
            assert!(oidc.iat == iat);
            assert!(oidc.nbf == Some(iat));
            assert!(oidc.exp == iat + (AUTH_SESSION_EXPIRY as i64));
            assert!(oidc.auth_time.is_none());
            // Is nonce correctly passed through?
            assert!(oidc.nonce == Some("abcdef".to_string()));
            assert!(oidc.at_hash.is_none());
            assert!(oidc.acr.is_none());
            assert!(oidc.amr == Some(vec!["passwordmfa".to_string()]));
            assert!(oidc.azp == Some("test_resource_server".to_string()));
            assert!(oidc.jti.is_none());
            assert!(oidc.s_claims.name == Some("System Administrator".to_string()));
            assert!(oidc.s_claims.preferred_username == Some("admin@example.com".to_string()));
            assert!(oidc.s_claims.scopes == vec!["openid".to_string()]);
            assert!(oidc.claims.is_empty());
            // Does our access token work with the userinfo endpoint?
            // Do the id_token details line up to the userinfo?
            let userinfo = idms_prox_read
                .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
                .expect("failed to get userinfo");

            assert!(oidc.iss == userinfo.iss);
            assert!(oidc.sub == userinfo.sub);
            assert!(oidc.aud == userinfo.aud);
            assert!(oidc.iat == userinfo.iat);
            assert!(oidc.nbf == userinfo.nbf);
            assert!(oidc.exp == userinfo.exp);
            assert!(userinfo.auth_time.is_none());
            assert!(userinfo.nonce.is_none());
            assert!(userinfo.at_hash.is_none());
            assert!(userinfo.acr.is_none());
            assert!(oidc.amr == userinfo.amr);
            assert!(oidc.azp == userinfo.azp);
            assert!(userinfo.jti.is_none());
            assert!(oidc.s_claims == userinfo.s_claims);
            assert!(userinfo.claims.is_empty());
        })
    }

    //  Check insecure pkce behaviour.
    #[test]
    fn test_idm_oauth2_insecure_pkce() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, uat, ident) = setup_oauth2_resource_server(idms, ct, false, false);

            let idms_prox_read = idms.proxy_read();

            // == Setup the authorisation request
            let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            // Even in disable pkce mode, we will allow pkce
            let _consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // Check we allow none.
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: None,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "openid".to_string(),
                nonce: Some("abcdef".to_string()),
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .expect("Oauth2 authorisation failed");
        })
    }

    #[test]
    fn test_idm_oauth2_openid_legacy_crypto() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, uat, ident) = setup_oauth2_resource_server(idms, ct, false, true);
            let idms_prox_read = idms.proxy_read();
            // The public key url should offer an rs key
            // discovery should offer RS256
            let discovery = idms_prox_read
                .oauth2_openid_discovery("test_resource_server")
                .expect("Failed to get discovery");

            let mut jwkset = idms_prox_read
                .oauth2_openid_publickey("test_resource_server")
                .expect("Failed to get public key");

            let jwk = jwkset.keys.pop().expect("no such jwk");
            let public_jwk = jwk.clone();

            match jwk {
                Jwk::RSA { alg, use_, kid, .. } => {
                    match (
                        alg.unwrap(),
                        &discovery.id_token_signing_alg_values_supported[0],
                    ) {
                        (JwaAlg::RS256, IdTokenSignAlg::RS256) => {}
                        _ => panic!(),
                    };
                    assert!(use_.unwrap() == JwkUse::Sig);
                    assert!(kid.unwrap() == "test_resource_server")
                }
                _ => panic!(),
            };

            // Check that the id_token is signed with the correct key.
            let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let consent_request =
                good_authorisation_request!(idms_prox_read, &ident, &uat, ct, code_challenge);

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(&ident, &uat, &consent_request.consent_token, ct)
                .expect("Failed to perform oauth2 permit");

            // == Submit the token exchange code.
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
                // From the first step.
                code_verifier,
            };

            let token_response = idms_prox_read
                .check_oauth2_token_exchange(None, &token_req, ct)
                .expect("Failed to perform oauth2 token exchange");

            // 🎉 We got a token!
            assert!(token_response.token_type == "bearer");
            let id_token = token_response.id_token.expect("No id_token in response!");

            let jws_validator =
                JwsValidator::try_from(&public_jwk).expect("failed to build validator");

            let oidc_unverified =
                OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

            let iat = ct.as_secs() as i64;

            let oidc = oidc_unverified
                .validate(&jws_validator, iat)
                .expect("Failed to verify oidc");

            assert!(oidc.sub == OidcSubject::U(*UUID_ADMIN));
        })
    }
}

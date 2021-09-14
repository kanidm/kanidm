//! Oauth2 resource server configurations
//!
//! This contains the in memory and loaded set of active oauth2 resource server
//! integrations, which are then able to be used an accessed from the IDM layer
//! for operations involving oauth2 authentication processing.
//!

use crate::identity::IdentityId;
use crate::prelude::*;
use concread::cowcell::*;
use fernet::Fernet;
use hashbrown::HashMap;
use kanidm_proto::v1::UserAuthToken;
use openssl::sha;
use std::sync::Arc;
use time::OffsetDateTime;
use url::{Origin, Url};
use webauthn_rs::base64_data::Base64UrlSafeData;

pub use kanidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, CodeChallengeMethod,
    ConsentRequest, ErrorResponse,
};

use std::convert::TryFrom;
use std::time::Duration;

lazy_static! {
    static ref CLASS_OAUTH2: PartialValue = PartialValue::new_class("oauth2_resource_server");
    static ref CLASS_OAUTH2_BASIC: PartialValue =
        PartialValue::new_class("oauth2_resource_server_basic");
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Oauth2Error {
    // Non-standard
    AuthenticationRequired,
    // Standard
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError(OperationError),
    TemporarilyUnavailable,
}

impl std::fmt::Display for Oauth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Oauth2Error::AuthenticationRequired => "authentication_required",
            Oauth2Error::InvalidRequest => "invalid_request",
            Oauth2Error::UnauthorizedClient => "unauthorized_client",
            Oauth2Error::AccessDenied => "access_denied",
            Oauth2Error::UnsupportedResponseType => "unsupported_response_type",
            Oauth2Error::InvalidScope => "invalid_scope",
            Oauth2Error::ServerError(_) => "server_error",
            Oauth2Error::TemporarilyUnavailable => "temporarily_unavailable",
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
    pub state: Base64UrlSafeData,
    // The S256 code challenge.
    pub code_challenge: Base64UrlSafeData,
    // Where the RS wants us to go back to.
    pub redirect_uri: Url,
}

// consent token?

#[derive(Serialize, Deserialize, Debug)]
struct TokenExchangeCode {
    // We don't need the client_id here, because it's signed with an RS specific
    // key which gives us the assurance that it's the correct combination.
    pub uat: UserAuthToken,
    // The S256 code challenge.
    pub code_challenge: Base64UrlSafeData,
    // The original redirect uri
    pub redirect_uri: Url,
}

// consentPermitResponse

#[derive(Debug)]
pub struct AuthorisePermitSuccess {
    // Where the RS wants us to go back to.
    pub redirect_uri: Url,
    // The CSRF as a string
    pub state: Base64UrlSafeData,
    // The exchange code as a String
    pub code: String,
}

// The cache structure

#[derive(Clone)]
pub struct Oauth2RSBasic {
    name: String,
    uuid: Uuid,
    origin: Origin,
    authz_secret: String,
    token_fernet: Fernet,
}

impl std::fmt::Debug for Oauth2RSBasic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Oauth2RSBasic")
            .field("name", &self.name)
            .field("uuid", &self.uuid)
            .field("origin", &self.origin)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum Oauth2RS {
    Basic(Oauth2RSBasic),
}

#[derive(Clone)]
struct Oauth2RSInner {
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

impl TryFrom<Vec<Arc<EntrySealedCommitted>>> for Oauth2ResourceServers {
    type Error = OperationError;

    fn try_from(value: Vec<Arc<EntrySealedCommitted>>) -> Result<Self, Self::Error> {
        let fernet =
            Fernet::new(&Fernet::generate_key()).ok_or(OperationError::CryptographyError)?;
        let oauth2rs = Oauth2ResourceServers {
            inner: CowCell::new(Oauth2RSInner {
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
                // From each entry, attempt to make an oauth2 configuration.
                if !ent.attribute_equality("class", &CLASS_OAUTH2) {
                    // Check we have oauth2_resource_server class
                    Err(OperationError::InvalidEntryState)
                } else if ent.attribute_equality("class", &CLASS_OAUTH2_BASIC) {
                    // If we have oauth2_resource_server_basic
                    // Now we know we can load the attrs.
                    let uuid = *ent.get_uuid();
                    let name = ent
                        .get_ava_single_str("oauth2_rs_name")
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;
                    let origin = ent
                        .get_ava_single_url("oauth2_rs_origin")
                        .map(|url| url.origin())
                        .ok_or(OperationError::InvalidValueState)?;
                    let authz_secret = ent
                        .get_ava_single_str("oauth2_rs_basic_secret")
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;
                    let token_fernet = ent
                        .get_ava_single_secret("oauth2_rs_basic_token_key")
                        .ok_or(OperationError::InvalidValueState)
                        .and_then(|key| {
                            Fernet::new(key).ok_or(OperationError::CryptographyError)
                        })?;

                    // Currently unsure if this is how I want to handle this.
                    // let oauth2_rs_account_filter = ent.get_ava_single_protofilter("oauth2_rs_account_filter")

                    let client_id = name.clone();
                    let rscfg = Oauth2RS::Basic(Oauth2RSBasic {
                        name,
                        uuid,
                        origin,
                        authz_secret,
                        token_fernet,
                    });

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
        audit: &mut AuditScope,
        ident: &Identity,
        uat: &UserAuthToken,
        auth_req: &AuthorisationRequest,
        ct: Duration,
    ) -> Result<ConsentRequest, Oauth2Error> {
        // due to identity processing we already know that:
        // * the session must be authenticated, and valid
        // * is within it's valid time window.

        if auth_req.response_type != "code" {
            ladmin_warning!(audit, "Invalid oauth2 response_type (should be 'code')");
            return Err(Oauth2Error::UnsupportedResponseType);
        }

        // CodeChallengeMethod must be S256
        if auth_req.code_challenge_method != CodeChallengeMethod::S256 {
            ladmin_warning!(
                audit,
                "Invalid oauth2 code_challenge_method (must be 'S256')"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        let o2rs = self.inner.rs_set.get(&auth_req.client_id).ok_or_else(|| {
            ladmin_warning!(
                audit,
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            Oauth2Error::InvalidRequest
        })?;

        // scopes

        // user authorisation filter

        // Subseqent we then return an encrypted session handle which allows
        // the user to indicate their consent to this authorisation.
        //
        // This session handle is what we use in "permit" to generate the redirect.

        match o2rs {
            Oauth2RS::Basic(rsbasic) => {
                // redirect_uri must be part of the client_id origin.
                if auth_req.redirect_uri.origin() != rsbasic.origin {
                    ladmin_warning!(
                        audit,
                        "Invalid oauth2 redirect_uri (must be related to origin of {:?})",
                        rsbasic.origin
                    );
                    return Err(Oauth2Error::InvalidRequest);
                }
            }
        };

        let consent_req = ConsentToken {
            client_id: auth_req.client_id.clone(),
            ident_id: ident.get_event_origin_id(),
            session_id: uat.session_id,
            state: auth_req.state.clone(),
            code_challenge: auth_req.code_challenge.clone(),
            redirect_uri: auth_req.redirect_uri.clone(),
        };

        let consent_data = serde_json::to_vec(&consent_req).map_err(|e| {
            ladmin_error!(audit, "Unable to encode consent data {:?}", e);
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let consent_token = self
            .inner
            .fernet
            .encrypt_at_time(&consent_data, ct.as_secs());

        Ok(ConsentRequest {
            client_name: auth_req.client_id.clone(),
            scopes: Vec::new(),
            consent_token,
        })
    }

    pub fn check_oauth2_authorise_permit(
        &self,
        audit: &mut AuditScope,
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
                ladmin_error!(audit, "Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    ladmin_error!(audit, "Failed to deserialise consent request - {:?}", e);
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            lsecurity!(
                audit,
                "consent request ident id does not match the identity of our UAT."
            );
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our uat.
        if consent_req.session_id != uat.session_id {
            lsecurity!(
                audit,
                "consent request sessien id does not match the session id of our UAT."
            );
            return Err(OperationError::InvalidSessionState);
        }

        // Get the resource server config based on this client_id.
        let o2rs_fernet = match self.inner.rs_set.get(&consent_req.client_id) {
            Some(Oauth2RS::Basic(rsbasic)) => &rsbasic.token_fernet,
            None => {
                ladmin_error!(audit, "Invalid consent request oauth2 client_id");
                return Err(OperationError::InvalidRequestState);
            }
        };

        // Extract the state, code challenge, redirect_uri

        let xchg_code = TokenExchangeCode {
            uat: uat.clone(),
            code_challenge: consent_req.code_challenge,
            redirect_uri: consent_req.redirect_uri.clone(),
        };

        // Encrypt the exchange token with the fernet key of the client resource server
        let code_data = serde_json::to_vec(&xchg_code).map_err(|e| {
            ladmin_error!(audit, "Unable to encode xchg_code data {:?}", e);
            OperationError::SerdeJsonError
        })?;

        let code = o2rs_fernet.encrypt_at_time(&code_data, ct.as_secs());

        Ok(AuthorisePermitSuccess {
            redirect_uri: consent_req.redirect_uri,
            state: consent_req.state,
            code,
        })
    }

    pub fn check_oauth2_token_exchange(
        &self,
        audit: &mut AuditScope,
        client_authz: &str,
        token_req: &AccessTokenRequest,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        if token_req.grant_type != "authorization_code" {
            ladmin_warning!(
                audit,
                "Invalid oauth2 grant_type (should be 'authorization_code')"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        // Check the client_authz
        let authz = base64::decode(&client_authz)
            .map_err(|_| {
                ladmin_error!(audit, "Basic authz invalid base64");
                Oauth2Error::AuthenticationRequired
            })
            .and_then(|data| {
                String::from_utf8(data).map_err(|_| {
                    ladmin_error!(audit, "Basic authz invalid utf8");
                    Oauth2Error::AuthenticationRequired
                })
            })?;

        // Get the first :, it should be our delim.
        //
        let mut split_iter = authz.split(':');

        let client_id = split_iter.next().ok_or_else(|| {
            ladmin_error!(audit, "Basic authz invalid format (corrupt input?)");
            Oauth2Error::AuthenticationRequired
        })?;
        let secret = split_iter.next().ok_or_else(|| {
            ladmin_error!(audit, "Basic authz invalid format (missing ':' seperator?)");
            Oauth2Error::AuthenticationRequired
        })?;

        // Get the o2rs for the handle.
        let o2rs = self.inner.rs_set.get(client_id).ok_or_else(|| {
            ladmin_warning!(audit, "Invalid oauth2 client_id");
            Oauth2Error::AuthenticationRequired
        })?;

        // check the secret.
        let o2rs_fernet = match o2rs {
            Oauth2RS::Basic(rsbasic) => {
                if rsbasic.authz_secret != secret {
                    lsecurity!(audit, "Invalid oauth2 client_id secret");
                    return Err(Oauth2Error::AuthenticationRequired);
                }
                // We are authenticated! Yay! Now we can actually check things ...
                &rsbasic.token_fernet
            }
        };

        // Check the token_req is within the valid time, and correctly signed for
        // this client.

        let code_xchg: TokenExchangeCode = o2rs_fernet
            .decrypt_at_time(&token_req.code, Some(60), ct.as_secs())
            .map_err(|_| {
                ladmin_error!(audit, "Failed to decrypt token exchange request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    ladmin_error!(audit, "Failed to deserialise token exchange code - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        // Validate the code_verifier
        let mut hasher = sha::Sha256::new();
        hasher.update(token_req.code_verifier.as_bytes());
        let code_verifier_hash: Vec<u8> = hasher.finish().iter().copied().collect();

        if code_xchg.code_challenge.0 != code_verifier_hash {
            lsecurity!(
                audit,
                "PKCE code verification failed - this may indicate malicious activity"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        // Validate the redirect_uri is the same as the original.
        if token_req.redirect_uri != code_xchg.redirect_uri {
            ladmin_warning!(
                audit,
                "Invalid oauth2 redirect_uri (differs from original request uri)"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        // We are now GOOD TO GO!
        // Use this to grant the access token response.
        let odt_ct = OffsetDateTime::unix_epoch() + ct;

        let expires_in = if code_xchg.uat.expiry > odt_ct {
            // Becomes a duration.
            (code_xchg.uat.expiry - odt_ct).whole_seconds() as u32
        } else {
            lsecurity!(
                audit,
                "User Auth Token has expired before we could publish the oauth2 response"
            );
            return Err(Oauth2Error::AccessDenied);
        };

        let access_token = serde_json::to_vec(&code_xchg.uat)
            .map_err(|e| {
                ladmin_error!(audit, "Unable to encode uat data {:?}", e);
                Oauth2Error::ServerError(OperationError::SerdeJsonError)
            })
            .map(|data| o2rs_fernet.encrypt_at_time(&data, ct.as_secs()))?;

        Ok(AccessTokenResponse {
            access_token,
            token_type: "bearer".to_string(),
            expires_in,
            refresh_token: None,
            scope: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::event::CreateEvent;
    use crate::idm::oauth2::Oauth2Error;
    use crate::idm::server::{IdmServer, IdmServerTransaction};
    use crate::prelude::*;

    use kanidm_proto::oauth2::*;
    use kanidm_proto::v1::{AuthType, UserAuthToken};
    use webauthn_rs::base64_data::Base64UrlSafeData;

    use openssl::sha;

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
            (code_verifier, code_challenge)
        }};
    }

    macro_rules! good_authorisation_request {
        (
            $audit:expr,
            $idms_prox_read:expr,
            $ident:expr,
            $uat:expr,
            $ct:expr,
            $code_challenge:expr
        ) => {{
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: Base64UrlSafeData(vec![1, 2, 3]),
                code_challenge: Base64UrlSafeData($code_challenge),
                code_challenge_method: CodeChallengeMethod::S256,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "".to_string(),
            };

            $idms_prox_read
                .check_oauth2_authorisation($audit, $ident, $uat, &auth_req, $ct)
                .expect("Oauth2 authorisation failed")
        }};
    }

    // setup an oauth2 instance.
    fn setup_oauth2_resource_server(
        audit: &mut AuditScope,
        idms: &IdmServer,
        ct: Duration,
    ) -> (String, UserAuthToken, Identity) {
        let mut idms_prox_write = idms.proxy_write(ct);

        let uuid = Uuid::new_v4();

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("uuid", Value::new_uuid(uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            )
        );
        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(audit, &ce).is_ok());

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(audit, &uuid)
            .expect("Failed to retrieve oauth2 resource entry ");
        let secret = entry
            .get_ava_single_str("oauth2_rs_basic_secret")
            .map(str::to_string)
            .expect("No oauth2_rs_basic_secret found");

        // Setup the uat we'll be using.
        let account = idms_prox_write
            .target_to_account(audit, &UUID_ADMIN)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(session_id, ct, AuthType::PasswordMfa)
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(audit, &uat, ct)
            .expect("Unable to process uat");

        idms_prox_write.commit(audit).expect("failed to commit");

        (secret, uat, ident)
    }

    #[test]
    fn test_idm_oauth2_basic_function() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed,
                       audit: &mut AuditScope| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, uat, ident) = setup_oauth2_resource_server(audit, idms, ct);

            let idms_prox_read = idms.proxy_read();

            // Get an ident/uat for now.

            // == Setup the authorisation request
            let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let consent_request = good_authorisation_request!(
                audit,
                idms_prox_read,
                &ident,
                &uat,
                ct,
                code_challenge
            );

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(
                    audit,
                    &ident,
                    &uat,
                    &consent_request.consent_token,
                    ct,
                )
                .expect("Failed to perform oauth2 permit");

            // Check we are reflecting the CSRF properly.
            assert!(permit_success.state.0 == vec![1, 2, 3]);

            // == Submit the token exchange code.

            let client_authz = base64::encode(format!("test_resource_server:{}", secret));
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                // From the first step.
                code_verifier,
            };

            let token_response = idms_prox_read
                .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                .expect("Failed to perform oauth2 token exchange");

            // 🎉 We got a token! In the future we can then check introspection from this point.
            assert!(token_response.token_type == "bearer");
        })
    }

    #[test]
    fn test_idm_oauth2_invalid_authorisation_requests() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed,
                       audit: &mut AuditScope| {
            // Test invalid oauth2 authorisation states/requests.
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, uat, ident) = setup_oauth2_resource_server(audit, idms, ct);

            let idms_prox_read = idms.proxy_read();

            let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            //  * response type != code.
            let auth_req = AuthorisationRequest {
                response_type: "NOTCODE".to_string(),
                client_id: "test_resource_server".to_string(),
                state: Base64UrlSafeData(vec![1, 2, 3]),
                code_challenge: Base64UrlSafeData(code_challenge.clone()),
                code_challenge_method: CodeChallengeMethod::S256,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "".to_string(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(audit, &ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::UnsupportedResponseType
            );

            //  * invalid rs name
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "NOT A REAL RESOURCE SERVER".to_string(),
                state: Base64UrlSafeData(vec![1, 2, 3]),
                code_challenge: Base64UrlSafeData(code_challenge.clone()),
                code_challenge_method: CodeChallengeMethod::S256,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: "".to_string(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(audit, &ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * mis match origin in the redirect.
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: Base64UrlSafeData(vec![1, 2, 3]),
                code_challenge: Base64UrlSafeData(code_challenge),
                code_challenge_method: CodeChallengeMethod::S256,
                redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
                scope: "".to_string(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_authorisation(audit, &ident, &uat, &auth_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );
        })
    }

    #[test]
    fn test_idm_oauth2_invalid_authorisation_permit_requests() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed,
                       audit: &mut AuditScope| {
            // Test invalid oauth2 authorisation states/requests.
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (_secret, uat, ident) = setup_oauth2_resource_server(audit, idms, ct);

            let (uat2, ident2) = {
                let mut idms_prox_write = idms.proxy_write(ct);
                let account = idms_prox_write
                    .target_to_account(audit, &UUID_IDM_ADMIN)
                    .expect("account must exist");
                let session_id = uuid::Uuid::new_v4();
                let uat2 = account
                    .to_userauthtoken(session_id, ct, AuthType::PasswordMfa)
                    .expect("Unable to create uat");
                let ident2 = idms_prox_write
                    .process_uat_to_identity(audit, &uat2, ct)
                    .expect("Unable to process uat");
                (uat2, ident2)
            };

            let idms_prox_read = idms.proxy_read();

            let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

            let consent_request = good_authorisation_request!(
                audit,
                idms_prox_read,
                &ident,
                &uat,
                ct,
                code_challenge
            );

            // Invalid permits
            //  * expired token, aka past ttl.
            assert!(
                idms_prox_read
                    .check_oauth2_authorise_permit(
                        audit,
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
                        audit,
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
                        audit,
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
                       _idms_delayed: &mut IdmServerDelayed,
                       audit: &mut AuditScope| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let (secret, mut uat, ident) = setup_oauth2_resource_server(audit, idms, ct);

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
            let consent_request = good_authorisation_request!(
                audit,
                idms_prox_read,
                &ident,
                &uat,
                ct,
                code_challenge
            );

            // == Manually submit the consent token to the permit for the permit_success
            let permit_success = idms_prox_read
                .check_oauth2_authorise_permit(
                    audit,
                    &ident,
                    &uat,
                    &consent_request.consent_token,
                    ct,
                )
                .expect("Failed to perform oauth2 permit");

            // == Submit the token exchange code.

            // Invalid token exchange
            //  * invalid client_authz (not base64)
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code.clone(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                // From the first step.
                code_verifier: code_verifier.clone(),
            };

            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, "not base64", &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            //  * doesn't have :
            let client_authz = base64::encode(format!("test_resource_server {}", secret));
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            //  * invalid client_id
            let client_authz = base64::encode(format!("NOT A REAL SERVER:{}", secret));
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            //  * valid client_id, but invalid secret
            let client_authz = base64::encode("test_resource_server:12345");
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::AuthenticationRequired
            );

            // ✅ Now the valid client_authz is in place.
            let client_authz = base64::encode(format!("test_resource_server:{}", secret));
            //  * expired exchange code (took too long)
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(
                        audit,
                        &client_authz,
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
                        audit,
                        &client_authz,
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
                code_verifier: code_verifier.clone(),
            };
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * Incorrect redirect uri
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code.clone(),
                redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
                client_id: None,
                code_verifier,
            };
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );

            //  * code verifier incorrect
            let token_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                client_id: None,
                code_verifier: "12345".to_string(),
            };
            assert!(
                idms_prox_read
                    .check_oauth2_token_exchange(audit, &client_authz, &token_req, ct)
                    .unwrap_err()
                    == Oauth2Error::InvalidRequest
            );
        })
    }
}

//! Oauth2 RFC protocol definitions.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::SpaceSeparator;
use serde_with::{
    formats, rust::deserialize_ignore_any, serde_as, skip_serializing_none, StringWithSeparator,
};
use url::Url;
use uuid::Uuid;

/// How many seconds a device code is valid for.
pub const OAUTH2_DEVICE_CODE_EXPIRY_SECONDS: u64 = 300;
/// How often a client device can query the status of the token
pub const OAUTH2_DEVICE_CODE_INTERVAL_SECONDS: u64 = 5;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum CodeChallengeMethod {
    // default to plain if not requested as S256. Reject the auth?
    // plain
    // BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    S256,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PkceRequest {
    #[serde_as(as = "Base64<UrlSafe, formats::Unpadded>")]
    pub code_challenge: Vec<u8>,
    pub code_challenge_method: CodeChallengeMethod,
}

/// An OAuth2 client redirects to the authorisation server with Authorisation Request
/// parameters.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorisationRequest {
    // Must be "code". (or token, see 4.2.1)
    pub response_type: ResponseType,
    /// Response mode.
    ///
    /// Optional; defaults to `query` for `response_type=code` (Auth Code), and
    /// `fragment` for `response_type=token` (Implicit Grant, which we probably
    /// won't support).
    ///
    /// Reference:
    /// [OAuth 2.0 Multiple Response Type Encoding Practices: Response Modes](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes)
    pub response_mode: Option<ResponseMode>,
    pub client_id: String,
    pub state: Option<String>,
    #[serde(flatten)]
    pub pkce_request: Option<PkceRequest>,
    pub redirect_uri: Url,
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    pub scope: BTreeSet<String>,
    // OIDC adds a nonce parameter that is optional.
    pub nonce: Option<String>,
    // OIDC also allows other optional params
    #[serde(flatten)]
    pub oidc_ext: AuthorisationRequestOidc,
    // Needs to be hoisted here due to serde flatten bug #3185
    pub max_age: Option<i64>,
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_json::value::Value>,
}

impl AuthorisationRequest {
    /// Get the `response_mode` appropriate for this request, taking into
    /// account defaults from the `response_type` parameter.
    ///
    /// Returns `None` if the selection is invalid.
    ///
    /// Reference:
    /// [OAuth 2.0 Multiple Response Type Encoding Practices: Response Modes](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes)
    pub const fn get_response_mode(&self) -> Option<ResponseMode> {
        match (self.response_mode, self.response_type) {
            // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#id_token
            // The default Response Mode for this Response Type is the fragment
            // encoding and the query encoding MUST NOT be used.
            (None, ResponseType::IdToken) => Some(ResponseMode::Fragment),
            (Some(ResponseMode::Query), ResponseType::IdToken) => None,

            // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
            (None, ResponseType::Code) => Some(ResponseMode::Query),
            // https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
            (None, ResponseType::Token) => Some(ResponseMode::Fragment),

            // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
            // In no case should a set of Authorization Response parameters
            // whose default Response Mode is the fragment encoding be encoded
            // using the query encoding.
            (Some(ResponseMode::Query), ResponseType::Token) => None,

            // Allow others.
            (Some(m), _) => Some(m),
        }
    }
}

/// An OIDC client redirects to the authorisation server with Authorisation Request
/// parameters.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthorisationRequestOidc {
    pub display: Option<String>,
    pub prompt: Option<String>,
    pub ui_locales: Option<()>,
    pub claims_locales: Option<()>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr: Option<String>,
}

/// In response to an Authorisation request, the user may be prompted to consent to the
/// scopes requested by the OAuth2 client. If they have previously consented, they will
/// immediately proceed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthorisationResponse {
    ConsentRequested {
        // A pretty-name of the client
        client_name: String,
        // A list of scopes requested / to be issued.
        scopes: BTreeSet<String>,
        // Extra PII that may be requested
        pii_scopes: BTreeSet<String>,
        // The users displayname (?)
        // pub display_name: String,
        // The token we need to be given back to allow this to proceed
        consent_token: String,
    },
    Permitted,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum GrantTypeReq {
    AuthorizationCode {
        // As sent by the authorisationCode
        code: String,
        // Must be the same as the original redirect uri.
        redirect_uri: Url,
        code_verifier: Option<String>,
    },
    ClientCredentials {
        #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
        scope: Option<BTreeSet<String>>,
    },
    RefreshToken {
        refresh_token: String,
        #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
        scope: Option<BTreeSet<String>>,
    },
    /// ref <https://www.rfc-editor.org/rfc/rfc8628#section-3.4>
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode {
        device_code: String,
        // #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
        scope: Option<BTreeSet<String>>,
    },
}

/// An Access Token request. This requires a set of grant-type parameters to satisfy the request.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenRequest {
    #[serde(flatten)]
    pub grant_type: GrantTypeReq,
    // REQUIRED, if the client is not authenticating with the
    //  authorization server as described in Section 3.2.1.
    #[serde(flatten)]
    pub client_post_auth: ClientPostAuth,
}

impl From<GrantTypeReq> for AccessTokenRequest {
    fn from(req: GrantTypeReq) -> AccessTokenRequest {
        AccessTokenRequest {
            grant_type: req,
            client_post_auth: ClientPostAuth::default(),
        }
    }
}

#[derive(Serialize, Debug, Clone, Deserialize)]
#[skip_serializing_none]
pub struct OAuth2RFC9068Token<V>
where
    V: Clone,
{
    /// The issuer of this token
    pub iss: String,
    /// Unique id of the subject
    pub sub: Uuid,
    /// client_id of the oauth2 rp
    pub aud: String,
    /// Expiry in UTC epoch seconds
    pub exp: i64,
    /// Not valid before.
    pub nbf: i64,
    /// Issued at time.
    pub iat: i64,
    /// JWT ID <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7> - we set it to the session ID
    pub jti: Uuid,
    pub client_id: String,
    #[serde(flatten)]
    pub extensions: V,
}

/// Extensions for RFC 9068 Access Token
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuth2RFC9068TokenExtensions {
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,

    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    pub scope: BTreeSet<String>,

    pub nonce: Option<String>,

    pub session_id: Uuid,
    pub parent_session_id: Option<Uuid>,
}

/// The response for an access token
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: AccessTokenType,
    /// Expiration relative to `now` in seconds.
    pub expires_in: u32,
    pub refresh_token: Option<String>,
    /// Space separated list of scopes that were approved, if this differs from the
    /// original request.
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    pub scope: BTreeSet<String>,
    /// If the `openid` scope was requested, an `id_token` may be present in the response.
    pub id_token: Option<String>,
}

/// Access token types, per [IANA Registry - OAuth Access Token Types](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-types)
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(try_from = "&str")]
pub enum AccessTokenType {
    Bearer,
    PoP,
    #[serde(rename = "N_A")]
    NA,
    DPoP,
}

impl TryFrom<&str> for AccessTokenType {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "bearer" => Ok(AccessTokenType::Bearer),
            "pop" => Ok(AccessTokenType::PoP),
            "n_a" => Ok(AccessTokenType::NA),
            "dpop" => Ok(AccessTokenType::DPoP),
            _ => Err(format!("Unknown AccessTokenType: {s}")),
        }
    }
}

/// Request revocation of an Access or Refresh token. On success the response is OK 200
/// with no body.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct TokenRevokeRequest {
    pub token: String,
    /// Not required for Kanidm.
    /// <https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2>
    pub token_type_hint: Option<String>,

    #[serde(flatten)]
    pub client_post_auth: ClientPostAuth,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default)]
/// <https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1>
pub struct ClientPostAuth {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl From<(String, Option<String>)> for ClientPostAuth {
    fn from((client_id, client_secret): (String, Option<String>)) -> Self {
        ClientPostAuth {
            client_id: Some(client_id),
            client_secret,
        }
    }
}

impl From<(&str, Option<&str>)> for ClientPostAuth {
    fn from((client_id, client_secret): (&str, Option<&str>)) -> Self {
        ClientPostAuth {
            client_id: Some(client_id.to_string()),
            client_secret: client_secret.map(|s| s.to_string()),
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default)]
/// <https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1>
pub struct ClientAuth {
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl From<(&str, Option<&str>)> for ClientAuth {
    fn from((client_id, client_secret): (&str, Option<&str>)) -> Self {
        ClientAuth {
            client_id: client_id.to_string(),
            client_secret: client_secret.map(|s| s.to_string()),
        }
    }
}

/// Request to introspect the identity of the account associated to a token.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectRequest {
    pub token: String,
    /// Not required for Kanidm.
    /// <https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2>
    pub token_type_hint: Option<String>,

    // For when they want to use POST auth
    // https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    #[serde(flatten)]
    pub client_post_auth: ClientPostAuth,
}

/// Response to an introspection request. If the token is inactive or revoked, only
/// `active` will be set to the value of `false`.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectResponse {
    pub active: bool,
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    pub scope: BTreeSet<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<AccessTokenType>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    // JWT ID <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7> set to session ID
    pub jti: Uuid,
}

impl AccessTokenIntrospectResponse {
    pub fn inactive() -> Self {
        AccessTokenIntrospectResponse {
            active: false,
            scope: BTreeSet::default(),
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: uuid::Uuid::new_v4(),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    // Auth Code flow
    // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
    Code,
    // Implicit Grant flow
    // https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1
    Token,
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#id_token
    IdToken,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Query,
    Fragment,
    FormPost,
    #[serde(other, deserialize_with = "deserialize_ignore_any")]
    Invalid,
}

fn response_modes_supported_default() -> Vec<ResponseMode> {
    vec![ResponseMode::Query, ResponseMode::Fragment]
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorisationCode,
    Implicit,
}

fn grant_types_supported_default() -> Vec<GrantType> {
    vec![GrantType::AuthorisationCode, GrantType::Implicit]
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    Pairwise,
    Public,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum PkceAlg {
    S256,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
/// Algorithms supported for token signatures. Prefers `ES256`
pub enum IdTokenSignAlg {
    // WE REFUSE TO SUPPORT NONE. DON'T EVEN ASK. IT WON'T HAPPEN.
    ES256,
    RS256,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
    ClientSecretJwt,
    PrivateKeyJwt,
}

fn token_endpoint_auth_methods_supported_default() -> Vec<TokenEndpointAuthMethod> {
    vec![TokenEndpointAuthMethod::ClientSecretBasic]
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisplayValue {
    Page,
    Popup,
    Touch,
    Wap,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
// https://openid.net/specs/openid-connect-core-1_0.html#ClaimTypes
pub enum ClaimType {
    Normal,
    Aggregated,
    Distributed,
}

fn claim_types_supported_default() -> Vec<ClaimType> {
    vec![ClaimType::Normal]
}

fn claims_parameter_supported_default() -> bool {
    false
}

fn request_parameter_supported_default() -> bool {
    false
}

fn request_uri_parameter_supported_default() -> bool {
    false
}

fn require_request_uri_parameter_supported_default() -> bool {
    false
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OidcWebfingerRel {
    pub rel: String,
    pub href: String,
}

/// The response to an Webfinger request. Only a subset of the body is defined here.
/// <https://datatracker.ietf.org/doc/html/rfc7033#section-4.4>
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct OidcWebfingerResponse {
    pub subject: String,
    pub links: Vec<OidcWebfingerRel>,
}

/// The response to an OpenID connect discovery request
/// <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct OidcDiscoveryResponse {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Option<Url>,
    pub jwks_uri: Url,
    pub registration_endpoint: Option<Url>,
    pub scopes_supported: Option<Vec<String>>,
    // https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
    pub response_types_supported: Vec<ResponseType>,
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
    #[serde(default = "response_modes_supported_default")]
    pub response_modes_supported: Vec<ResponseMode>,
    // Need to fill in as authorization_code only else a default is assumed.
    #[serde(default = "grant_types_supported_default")]
    pub grant_types_supported: Vec<GrantType>,
    pub acr_values_supported: Option<Vec<String>>,
    // https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<IdTokenSignAlg>,
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    // Defaults to client_secret_basic
    #[serde(default = "token_endpoint_auth_methods_supported_default")]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    pub display_values_supported: Option<Vec<DisplayValue>>,
    // Default to normal.
    #[serde(default = "claim_types_supported_default")]
    pub claim_types_supported: Vec<ClaimType>,
    pub claims_supported: Option<Vec<String>>,
    pub service_documentation: Option<Url>,
    pub claims_locales_supported: Option<Vec<String>>,
    pub ui_locales_supported: Option<Vec<String>>,
    // Default false.
    #[serde(default = "claims_parameter_supported_default")]
    pub claims_parameter_supported: bool,

    pub op_policy_uri: Option<Url>,
    pub op_tos_uri: Option<Url>,

    // these are related to RFC9101 JWT-Secured Authorization Request support
    #[serde(default = "request_parameter_supported_default")]
    pub request_parameter_supported: bool,
    #[serde(default = "request_uri_parameter_supported_default")]
    pub request_uri_parameter_supported: bool,
    #[serde(default = "require_request_uri_parameter_supported_default")]
    pub require_request_uri_registration: bool,

    pub code_challenge_methods_supported: Vec<PkceAlg>,

    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
    // "content type that contains a set of Claims as its members that are a subset of the Metadata
    //  values defined in Section 3. Other Claims MAY also be returned. "
    //
    // In addition, we also return the following claims in kanidm

    // rfc7009
    pub revocation_endpoint: Option<Url>,
    pub revocation_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,

    // rfc7662
    pub introspection_endpoint: Option<Url>,
    pub introspection_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<IdTokenSignAlg>>,

    /// Ref <https://www.rfc-editor.org/rfc/rfc8628#section-4>
    pub device_authorization_endpoint: Option<Url>,
}

/// The response to an OAuth2 rfc8414 metadata request
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct Oauth2Rfc8414MetadataResponse {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,

    pub jwks_uri: Option<Url>,

    // rfc7591 reg endpoint.
    pub registration_endpoint: Option<Url>,

    pub scopes_supported: Option<Vec<String>>,

    // For Oauth2 should be Code, Token.
    pub response_types_supported: Vec<ResponseType>,
    #[serde(default = "response_modes_supported_default")]
    pub response_modes_supported: Vec<ResponseMode>,
    #[serde(default = "grant_types_supported_default")]
    pub grant_types_supported: Vec<GrantType>,

    #[serde(default = "token_endpoint_auth_methods_supported_default")]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,

    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<IdTokenSignAlg>>,

    pub service_documentation: Option<Url>,
    pub ui_locales_supported: Option<Vec<String>>,

    pub op_policy_uri: Option<Url>,
    pub op_tos_uri: Option<Url>,

    // rfc7009
    pub revocation_endpoint: Option<Url>,
    pub revocation_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,

    // rfc7662
    pub introspection_endpoint: Option<Url>,
    pub introspection_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<IdTokenSignAlg>>,

    // RFC7636
    pub code_challenge_methods_supported: Vec<PkceAlg>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub error_uri: Option<Url>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Ref <https://www.rfc-editor.org/rfc/rfc8628#section-3.2>
pub struct DeviceAuthorizationResponse {
    /// Base64-encoded bundle of 16 bytes
    device_code: String,
    /// xxx-yyy-zzz where x/y/z are digits. Stored internally as a u32 because we'll drop the dashes and parse as a number.
    user_code: String,
    verification_uri: Url,
    verification_uri_complete: Url,
    expires_in: u64,
    interval: u64,
}

impl DeviceAuthorizationResponse {
    pub fn new(verification_uri: Url, device_code: [u8; 16], user_code: String) -> Self {
        let mut verification_uri_complete = verification_uri.clone();
        verification_uri_complete
            .query_pairs_mut()
            .append_pair("user_code", &user_code);

        let device_code = STANDARD.encode(device_code);

        Self {
            verification_uri_complete,
            device_code,
            user_code,
            verification_uri,
            expires_in: OAUTH2_DEVICE_CODE_EXPIRY_SECONDS,
            interval: OAUTH2_DEVICE_CODE_INTERVAL_SECONDS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessTokenRequest, GrantTypeReq};
    use url::Url;

    #[test]
    fn test_oauth2_access_token_req() {
        let atr: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: "demo code".to_string(),
            redirect_uri: Url::parse("http://[::1]").unwrap(),
            code_verifier: None,
        }
        .into();

        println!("{:?}", serde_json::to_string(&atr).expect("JSON failure"));
    }

    #[test]
    fn test_oauth2_access_token_type_serde() {
        for testcase in ["bearer", "Bearer", "BeArEr"] {
            let at: super::AccessTokenType =
                serde_json::from_str(&format!("\"{testcase}\"")).expect("Failed to parse");
            assert_eq!(at, super::AccessTokenType::Bearer);
        }

        for testcase in ["dpop", "dPoP", "DPOP", "DPoP"] {
            let at: super::AccessTokenType =
                serde_json::from_str(&format!("\"{testcase}\"")).expect("Failed to parse");
            assert_eq!(at, super::AccessTokenType::DPoP);
        }

        {
            let testcase = "cheese";
            let at = serde_json::from_str::<super::AccessTokenType>(&format!("\"{testcase}\""));
            assert!(at.is_err())
        }
    }
}

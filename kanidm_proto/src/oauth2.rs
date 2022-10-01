use std::collections::BTreeMap;

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum CodeChallengeMethod {
    // default to plain if not requested as S256. Reject the auth?
    // plain
    // BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    S256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PkceRequest {
    pub code_challenge: Base64UrlSafeData,
    pub code_challenge_method: CodeChallengeMethod,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorisationRequest {
    // Must be "code". (or token, see 4.2.1)
    pub response_type: String,
    pub client_id: String,
    pub state: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub pkce_request: Option<PkceRequest>,
    pub redirect_uri: Url,
    pub scope: String,
    // OIDC adds a nonce parameter that is optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    // OIDC also allows other optional params
    #[serde(flatten)]
    pub oidc_ext: AuthorisationRequestOidc,
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_json::value::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthorisationRequestOidc {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

/// When we request to authorise, it can either prompt us for consent,
/// or it can immediately be granted due the past grant.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthorisationResponse {
    ConsentRequested {
        // A pretty-name of the client
        client_name: String,
        // A list of scopes requested / to be issued.
        scopes: Vec<String>,
        // Extra PII that may be requested
        pii_scopes: Vec<String>,
        // The users displayname (?)
        // pub display_name: String,
        // The token we need to be given back to allow this to proceed
        consent_token: String,
    },
    Permitted,
}

// The resource server then contacts the token endpoint with
//
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenRequest {
    // must be authorization_code
    pub grant_type: String,
    // As sent by the authorisationCode
    pub code: String,
    // Must be the same as the original redirect uri.
    pub redirect_uri: Url,
    // REQUIRED, if the client is not authenticating with the
    //  authorization server as described in Section 3.2.1.
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

// We now check code_verifier is the same via the formula.

// If and only if it checks out, we proceed.

// Returned as a json body

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenResponse {
    // Could be  Base64UrlSafeData
    pub access_token: String,
    // Enum?
    pub token_type: String,
    // seconds.
    pub expires_in: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Space seperated list of scopes that were approved, if this differs from the
    /// original request.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Oidc puts the token here.
    pub id_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectRequest {
    pub token: String,
    /// Generally not needed. See:
    /// <https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl AccessTokenIntrospectResponse {
    pub fn inactive() -> Self {
        AccessTokenIntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
    Token,
    IdToken,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Query,
    Fragment,
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
#[serde(rename_all = "UPPERCASE")]
// WE REFUSE TO SUPPORT NONE. DONT EVEN ASK. IT WONT HAPPEN.
pub enum IdTokenSignAlg {
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
    true
}

fn require_request_uri_parameter_supported_default() -> bool {
    false
}

#[derive(Serialize, Deserialize, Debug)]
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
pub struct OidcDiscoveryResponse {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,
    pub jwks_uri: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    // https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
    pub response_types_supported: Vec<ResponseType>,
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
    #[serde(default = "response_modes_supported_default")]
    pub response_modes_supported: Vec<ResponseMode>,
    // Need to fill in as authorization_code only else a default is assumed.
    #[serde(default = "grant_types_supported_default")]
    pub grant_types_supported: Vec<GrantType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,
    // https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<IdTokenSignAlg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    // Defaults to client_secret_basic
    #[serde(default = "token_endpoint_auth_methods_supported_default")]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_values_supported: Option<Vec<DisplayValue>>,
    // Default to normal.
    #[serde(default = "claim_types_supported_default")]
    pub claim_types_supported: Vec<ClaimType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,
    // Default false.
    #[serde(default = "claims_parameter_supported_default")]
    pub claims_parameter_supported: bool,
    #[serde(default = "request_parameter_supported_default")]
    pub request_parameter_supported: bool,
    #[serde(default = "request_uri_parameter_supported_default")]
    pub request_uri_parameter_supported: bool,
    #[serde(default = "require_request_uri_parameter_supported_default")]
    pub require_request_uri_registration: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<Url>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<Url>,
}

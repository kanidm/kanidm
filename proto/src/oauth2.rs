use std::collections::{BTreeMap, BTreeSet};

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use serde_with::formats::SpaceSeparator;
use serde_with::{serde_as, skip_serializing_none, StringWithSeparator};
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

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorisationRequest {
    // Must be "code". (or token, see 4.2.1)
    pub response_type: String,
    pub client_id: String,
    pub state: String,
    #[serde(flatten)]
    pub pkce_request: Option<PkceRequest>,
    pub redirect_uri: Url,
    pub scope: String,
    // OIDC adds a nonce parameter that is optional.
    pub nonce: Option<String>,
    // OIDC also allows other optional params
    #[serde(flatten)]
    pub oidc_ext: AuthorisationRequestOidc,
    #[serde(flatten)]
    pub unknown_keys: BTreeMap<String, serde_json::value::Value>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthorisationRequestOidc {
    pub display: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub ui_locales: Option<()>,
    pub claims_locales: Option<()>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
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
// this is the equivalent of serde(skip_serializing_if = "Option::is_none") applied to ALL the options
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
    RefreshToken {
        refresh_token: String,
        #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
        scope: Option<BTreeSet<String>>,
    },
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenRequest {
    #[serde(flatten)]
    pub grant_type: GrantTypeReq,
    // REQUIRED, if the client is not authenticating with the
    //  authorization server as described in Section 3.2.1.
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl From<GrantTypeReq> for AccessTokenRequest {
    fn from(req: GrantTypeReq) -> AccessTokenRequest {
        AccessTokenRequest {
            grant_type: req,
            client_id: None,
            client_secret: None,
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct TokenRevokeRequest {
    pub token: String,
    /// Generally not needed. See:
    /// <https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2>
    pub token_type_hint: Option<String>,
}

// The corresponding Response to a revoke request is empty body with 200.

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenResponse {
    // Could be  Base64UrlSafeData
    pub access_token: String,
    // Enum?
    pub token_type: String,
    // seconds.
    pub expires_in: u32,
    pub refresh_token: Option<String>,
    /// Space separated list of scopes that were approved, if this differs from the
    /// original request.
    pub scope: Option<String>,
    /// Oidc puts the token here.
    pub id_token: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectRequest {
    pub token: String,
    /// Generally not needed. See:
    /// <https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2>
    pub token_type_hint: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
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
// WE REFUSE TO SUPPORT NONE. DONT EVEN ASK. IT WON'T HAPPEN.
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
    false
}

fn require_request_uri_parameter_supported_default() -> bool {
    false
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
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
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub error_uri: Option<Url>,
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
}

use url::Url;
use webauthn_rs::base64_data::Base64UrlSafeData;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum CodeChallengeMethod {
    // default to plain if not requested as S256. Reject the auth?
    // plain
    // BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    S256,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorisationRequest {
    // Must be "code". (or token, see 4.2.1)
    pub response_type: String,
    pub client_id: String,
    pub state: String,
    // base64?
    pub code_challenge: Base64UrlSafeData,
    // Probably also should be an enum.
    pub code_challenge_method: CodeChallengeMethod,
    // Uri?
    pub redirect_uri: Url,
    pub scope: String,
    // OIDC adds a nonce parameter that is optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    // OIDC also allows other optional params
    #[serde(flatten)]
    pub oidc_ext: AuthorisationRequestOidc,
}

#[derive(Serialize, Deserialize, Debug, Default)]
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

/// We ask our user to consent to this Authorisation Request with the
/// following data.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConsentRequest {
    // A pretty-name of the client
    pub client_name: String,
    // A list of scopes requested / to be issued.
    pub scopes: Vec<String>,
    // The users displayname (?)
    // pub display_name: String,
    // The token we need to be given back to allow this to proceed
    pub consent_token: String,
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
    //
    pub code_verifier: String,
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
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenIntrospectRequest {
    pub token: String,
    /// https://datatracker.ietf.org/doc/html/rfc7009#section-4.1.2
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<Url>,
}

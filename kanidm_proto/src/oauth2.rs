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
    pub state: Base64UrlSafeData,
    // base64?
    pub code_challenge: Base64UrlSafeData,
    // Probably also should be an enum.
    pub code_challenge_method: CodeChallengeMethod,
    // Uri?
    pub redirect_uri: Url,
    // appears to be + seperated?
    pub scope: String,
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
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<Url>,
}

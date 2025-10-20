use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use utoipa::ToSchema;
use uuid::Uuid;

use webauthn_rs_proto::PublicKeyCredential;
use webauthn_rs_proto::RequestChallengeResponse;

/// Authentication to Kanidm is a stepped process.
///
/// The session is first initialised with the requested username.
///
/// In response the list of supported authentication mechanisms is provided.
///
/// The user chooses the authentication mechanism to proceed with.
///
/// The server responds with a challenge that the user provides a credential
/// to satisfy. This challenge and response process continues until a credential
/// fails to validate, an error occurs, or successful authentication is complete.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthStep {
    /// Initialise a new authentication session
    Init(String),
    /// Initialise a new authentication session with extra flags
    /// for requesting different types of session tokens or
    /// immediate access to privileges.
    Init2 {
        username: String,
        issue: AuthIssueSession,
        #[serde(default)]
        /// If true, the session will have r/w access.
        privileged: bool,
    },
    /// Request the named authentication mechanism to proceed
    Begin(AuthMech),
    /// Provide a credential in response to a challenge
    Cred(AuthCredential),
}

/// The response to an AuthStep request.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    /// You need to select how you want to proceed.
    Choose(Vec<AuthMech>),
    /// Continue to auth, allowed mechanisms/challenges listed.
    Continue(Vec<AuthAllowed>),
    /// Something was bad, your session is terminated and no cookie.
    Denied(String),
    /// Everything is good, your bearer token has been issued and is within.
    Success(String),
}

/// The credential challenge provided by a user.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),

    #[schema(value_type = HashMap<String, Value>)]
    SecurityKey(Box<PublicKeyCredential>),
    BackupCode(String),
    // Should this just be discoverable?
    #[schema(value_type = String)]
    Passkey(Box<PublicKeyCredential>),
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthCredential::Anonymous => write!(fmt, "Anonymous"),
            AuthCredential::Password(_) => write!(fmt, "Password(_)"),
            AuthCredential::Totp(_) => write!(fmt, "TOTP(_)"),
            AuthCredential::SecurityKey(_) => write!(fmt, "SecurityKey(_)"),
            AuthCredential::BackupCode(_) => write!(fmt, "BackupCode(_)"),
            AuthCredential::Passkey(_) => write!(fmt, "Passkey(_)"),
        }
    }
}

/// The mechanisms that may proceed in this authentication
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthMech {
    Anonymous,
    Password,
    PasswordBackupCode,
    // Now represents TOTP.
    #[serde(rename = "passwordmfa")]
    PasswordTotp,
    PasswordSecurityKey,
    Passkey,
}

impl AuthMech {
    pub fn to_value(&self) -> &'static str {
        match self {
            AuthMech::Anonymous => "anonymous",
            AuthMech::Password => "password",
            AuthMech::PasswordTotp => "passwordmfa",
            AuthMech::PasswordBackupCode => "passwordbackupcode",
            AuthMech::PasswordSecurityKey => "passwordsecuritykey",
            AuthMech::Passkey => "passkey",
        }
    }
}

impl PartialEq for AuthMech {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl fmt::Display for AuthMech {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMech::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthMech::Password => write!(f, "Password"),
            AuthMech::PasswordTotp => write!(f, "TOTP and Password"),
            AuthMech::PasswordBackupCode => write!(f, "Backup Code and Password"),
            AuthMech::PasswordSecurityKey => write!(f, "Security Key and Password"),
            AuthMech::Passkey => write!(f, "Passkey"),
        }
    }
}

/// The type of session that should be issued to the client.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthIssueSession {
    /// Issue a bearer token for this client. This is the default.
    Token,
    /// Issue a cookie for this client.
    Cookie,
}

/// A request for the next step of an authentication.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthRequest {
    pub step: AuthStep,
}

/// A challenge containing the list of allowed authentication types
/// that can satisfy the next step. These may have inner types with
/// required context.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthAllowed {
    Anonymous,
    BackupCode,
    Password,
    Totp,

    #[schema(value_type = HashMap<String, Value>)]
    SecurityKey(RequestChallengeResponse),
    #[schema(value_type = HashMap<String, Value>)]
    Passkey(RequestChallengeResponse),
}

impl PartialEq for AuthAllowed {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl From<&AuthAllowed> for u8 {
    fn from(a: &AuthAllowed) -> u8 {
        match a {
            AuthAllowed::Anonymous => 0,
            AuthAllowed::Password => 1,
            AuthAllowed::BackupCode => 2,
            AuthAllowed::Totp => 3,
            AuthAllowed::Passkey(_) => 4,
            AuthAllowed::SecurityKey(_) => 5,
        }
    }
}

impl Eq for AuthAllowed {}

impl Ord for AuthAllowed {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_ord: u8 = self.into();
        let other_ord: u8 = other.into();
        self_ord.cmp(&other_ord)
    }
}

impl PartialOrd for AuthAllowed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for AuthAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthAllowed::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthAllowed::Password => write!(f, "Password"),
            AuthAllowed::BackupCode => write!(f, "Backup Code"),
            AuthAllowed::Totp => write!(f, "TOTP"),
            AuthAllowed::SecurityKey(_) => write!(f, "Security Token"),
            AuthAllowed::Passkey(_) => write!(f, "Passkey"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub sessionid: Uuid,
    pub state: AuthState,
}

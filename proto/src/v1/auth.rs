use std::cmp::Ordering;
use std::fmt;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use webauthn_rs_proto::PublicKeyCredential;
use webauthn_rs_proto::RequestChallengeResponse;

// Login is a multi-step process potentially. First the client says who they
// want to request
//
// we respond with a set of possible authentications that can proceed, and perhaps
// we indicate which options must/may?
//
// The client can then step and negotiate each.
//
// This continues until a LoginSuccess, or LoginFailure is returned.
//
// On loginSuccess, we send a cookie, and that allows the token to be
// generated. The cookie can be shared between servers.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),
    SecurityKey(Box<PublicKeyCredential>),
    BackupCode(String),
    // Should this just be discoverable?
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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthMech {
    Anonymous,
    Password,
    PasswordMfa,
    Passkey,
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
            AuthMech::PasswordMfa => write!(f, "TOTP/Backup Code and Password"),
            AuthMech::Passkey => write!(f, "Passkey"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
// TODO: what is this actually used for?
pub enum AuthIssueSession {
    Token,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthStep {
    /// "I want to authenticate with this username"
    Init(String),
    /// A new way to issue sessions. Doing this as a new init type
    /// to prevent breaking existing clients. Allows requesting of the type
    /// of session that will be issued at the end if successful.
    Init2 {
        username: String,
        issue: AuthIssueSession,
        #[serde(default)]
        /// If true, the session will have r/w access.
        privileged: bool,
    },
    /// We want to talk to you like this.
    Begin(AuthMech),
    /// Provide a response to a challenge.
    Cred(AuthCredential),
}

// Request auth for identity X with roles Y?
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthRequest {
    pub step: AuthStep,
}

// Respond with the list of auth types and nonce, etc.
// It can also contain a denied, or success.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthAllowed {
    Anonymous,
    BackupCode,
    Password,
    Totp,
    SecurityKey(RequestChallengeResponse),
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
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    /// You need to select how you want to talk to me.
    Choose(Vec<AuthMech>),
    /// Continue to auth, allowed mechanisms/challenges listed.
    Continue(Vec<AuthAllowed>),
    /// Something was bad, your session is terminated and no cookie.
    Denied(String),
    /// Everything is good, your bearer token has been issued and is within the result.
    Success(String),
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub sessionid: Uuid,
    pub state: AuthState,
}


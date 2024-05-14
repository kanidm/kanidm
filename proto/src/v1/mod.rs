//! Kanidm Version 1
//!
//! Items defined in this module will remain stable, or change in ways that are forward
//! compatible with newer releases.

#![allow(non_upper_case_globals)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Display;
use utoipa::ToSchema;
use uuid::Uuid;

mod auth;
mod unix;

pub use self::auth::*;
pub use self::unix::*;

/// The type of Account in use.
#[derive(Clone, Copy, Debug, ToSchema)]
pub enum AccountType {
    Person,
    ServiceAccount,
}

impl Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::Person => f.write_str("person"),
            AccountType::ServiceAccount => f.write_str("service_account"),
        }
    }
}

/* ===== higher level types ===== */
// These are all types that are conceptually layers on top of entry and
// friends. They allow us to process more complex requests and provide
// domain specific fields for the purposes of IDM, over the normal
// entry/ava/filter types. These related deeply to schema.

/// The current purpose of a User Auth Token. It may be read-only, read-write
/// or privilige capable (able to step up to read-write after re-authentication).
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatPurposeStatus {
    ReadOnly,
    ReadWrite,
    PrivilegeCapable,
}

/// The expiry of the User Auth Token.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatStatusState {
    #[serde(with = "time::serde::timestamp")]
    ExpiresAt(time::OffsetDateTime),
    NeverExpires,
    Revoked,
}

impl fmt::Display for UatStatusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UatStatusState::ExpiresAt(odt) => write!(f, "expires at {}", odt),
            UatStatusState::NeverExpires => write!(f, "never expires"),
            UatStatusState::Revoked => write!(f, "revoked"),
        }
    }
}

/// The status of a User Auth Token
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct UatStatus {
    pub account_id: Uuid,
    pub session_id: Uuid,
    pub state: UatStatusState,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    pub purpose: UatPurposeStatus,
}

impl fmt::Display for UatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account_id: {}", self.account_id)?;
        writeln!(f, "session_id: {}", self.session_id)?;
        writeln!(f, "state: {}", self.state)?;
        writeln!(f, "issued_at: {}", self.issued_at)?;
        match &self.purpose {
            UatPurposeStatus::ReadOnly => writeln!(f, "purpose: read only")?,
            UatPurposeStatus::ReadWrite => writeln!(f, "purpose: read write")?,
            UatPurposeStatus::PrivilegeCapable => writeln!(f, "purpose: privilege capable")?,
        }
        Ok(())
    }
}

/// A request to generate a new API token for a service account
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ApiTokenGenerate {
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub read_write: bool,
}

/* ===== low level proto types ===== */

/// A limited view of an entry in Kanidm.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default, ToSchema)]
pub struct Entry {
    pub attrs: BTreeMap<String, Vec<String>>,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        self.attrs
            .iter()
            .try_for_each(|(k, vs)| vs.iter().try_for_each(|v| writeln!(f, "{}: {}", k, v)))
    }
}

/// A response to a whoami request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub struct WhoamiResponse {
    // Should we just embed the entry? Or destructure it?
    pub youare: Entry,
}

impl WhoamiResponse {
    pub fn new(youare: Entry) -> Self {
        WhoamiResponse { youare }
    }
}

// Simple string value provision.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SingleStringRequest {
    pub value: String,
}

impl SingleStringRequest {
    pub fn new(s: String) -> Self {
        SingleStringRequest { value: s }
    }
}

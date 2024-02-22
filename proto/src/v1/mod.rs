#![allow(non_upper_case_globals)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use utoipa::ToSchema;
use uuid::Uuid;

mod auth;
mod unix;

pub use self::auth::*;
pub use self::unix::*;

// These proto implementations are here because they have public definitions
#[derive(Clone, Copy, Debug, ToSchema)]
pub enum AccountType {
    Person,
    ServiceAccount,
}

impl ToString for AccountType {
    fn to_string(&self) -> String {
        match self {
            AccountType::Person => "person".to_string(),
            AccountType::ServiceAccount => "service_account".to_string(),
        }
    }
}

/* ===== higher level types ===== */
// These are all types that are conceptually layers on top of entry and
// friends. They allow us to process more complex requests and provide
// domain specific fields for the purposes of IDM, over the normal
// entry/ava/filter types. These related deeply to schema.

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Claim {
    pub name: String,
    pub uuid: String,
    // These can be ephemeral, or shortlived in a session.
    // some may even need requesting.
    // pub expiry: DateTime
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatPurposeStatus {
    ReadOnly,
    ReadWrite,
    PrivilegeCapable,
}

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
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ApiTokenGenerate {
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub read_write: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct BackupCodesView {
    pub backup_codes: Vec<String>,
}

/* ===== low level proto types ===== */

// ProtoEntry vs Entry
// There is a good future reason for this separation. It allows changing
// the in memory server core entry type, without affecting the protoEntry type
//

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

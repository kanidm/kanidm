use super::UiHint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use serde_with::skip_serializing_none;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UatPurpose {
    ReadOnly,
    ReadWrite {
        /// If none, there is no expiry, and this is always rw. If there is
        /// an expiry, check that the current time < expiry.
        #[serde(with = "time::serde::timestamp::option")]
        expiry: Option<time::OffsetDateTime>,
    },
}

/// The currently authenticated user, and any required metadata for them
/// to properly authorise them. This is similar in nature to oauth and the krb
/// PAC/PAD structures. This information is transparent to clients and CAN
/// be parsed by them!
///
/// This structure and how it works will *very much* change over time from this
/// point onward! This means on updates, that sessions will invalidate in many
/// cases.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[skip_serializing_none]
#[serde(rename_all = "lowercase")]
pub struct UserAuthToken {
    pub session_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    /// If none, there is no expiry, and this is always valid. If there is
    /// an expiry, check that the current time < expiry.
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    pub purpose: UatPurpose,
    pub uuid: Uuid,
    pub displayname: String,
    pub spn: String,
    pub mail_primary: Option<String>,
    pub ui_hints: BTreeSet<UiHint>,

    pub limit_search_max_results: Option<u64>,
    pub limit_search_max_filter_test: Option<u64>,
}

impl fmt::Display for UserAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "display: {}", self.displayname)?;
        if let Some(exp) = self.expiry {
            writeln!(f, "expiry: {}", exp)?;
        } else {
            writeln!(f, "expiry: -")?;
        }
        match &self.purpose {
            UatPurpose::ReadOnly => writeln!(f, "purpose: read only")?,
            UatPurpose::ReadWrite {
                expiry: Some(expiry),
            } => writeln!(f, "purpose: read write (expiry: {})", expiry)?,
            UatPurpose::ReadWrite { expiry: None } => {
                writeln!(f, "purpose: read write (expiry: none)")?
            }
        }
        Ok(())
    }
}

impl PartialEq for UserAuthToken {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
    }
}

impl Eq for UserAuthToken {}

impl UserAuthToken {
    pub fn name(&self) -> &str {
        self.spn.split_once('@').map(|x| x.0).unwrap_or(&self.spn)
    }

    /// Show if the uat at a current point in time has active read-write
    /// capabilities.
    pub fn purpose_readwrite_active(&self, ct: time::OffsetDateTime) -> bool {
        match self.purpose {
            UatPurpose::ReadWrite { expiry: Some(exp) } => ct < exp,
            _ => false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiTokenPurpose {
    #[default]
    ReadOnly,
    ReadWrite,
    Synchronise,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ApiToken {
    // The account this is associated with.
    pub account_id: Uuid,
    pub token_id: Uuid,
    pub label: String,
    #[serde(with = "time::serde::timestamp::option")]
    pub expiry: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    // Defaults to ReadOnly if not present
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

impl fmt::Display for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account_id: {}", self.account_id)?;
        writeln!(f, "token_id: {}", self.token_id)?;
        writeln!(f, "label: {}", self.label)?;
        writeln!(f, "issued at: {}", self.issued_at)?;
        if let Some(expiry) = self.expiry {
            // if this fails we're in trouble!
            #[allow(clippy::expect_used)]
            let expiry_str = expiry
                .to_offset(
                    time::UtcOffset::local_offset_at(OffsetDateTime::UNIX_EPOCH)
                        .unwrap_or(time::UtcOffset::UTC),
                )
                .format(&time::format_description::well_known::Rfc3339)
                .expect("Failed to format timestamp to RFC3339");
            writeln!(f, "token expiry: {}", expiry_str)
        } else {
            writeln!(f, "token expiry: never")
        }
    }
}

impl PartialEq for ApiToken {
    fn eq(&self, other: &Self) -> bool {
        self.token_id == other.token_id
    }
}

impl Eq for ApiToken {}

// This is similar to uat, but omits claims (they have no role in radius), and adds
// the radius secret field.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct RadiusAuthToken {
    pub name: String,
    pub displayname: String,
    pub uuid: String,
    pub secret: String,
    pub groups: Vec<Group>,
}

impl fmt::Display for RadiusAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "secret: {}", self.secret)?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "group: {}", g))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ScimSyncToken {
    // uuid of the token?
    pub token_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Group {
    pub spn: String,
    pub uuid: String,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ spn: {}, ", self.spn)?;
        write!(f, "uuid: {} ]", self.uuid)
    }
}

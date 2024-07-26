#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub mod constants;
pub mod filter;
pub mod group;
pub mod user;

pub mod prelude {
    pub use crate::constants::*;
    pub use crate::user::MultiValueAttr;
    pub use crate::{ScimAttr, ScimComplexAttr, ScimEntry, ScimEntryGeneric, ScimMeta, ScimValue};
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum ScimAttr {
    Bool(bool),
    Integer(i64),
    Decimal(f64),
    String(String),
    // These can't be implicitly decoded because we may not know the intent, but we can *encode* them.
    // That's why "String" is above this because it catches anything during deserialization before
    // this point.
    DateTime(OffsetDateTime),
    Binary(Vec<u8>),
    Reference(Url),
}

impl From<ScimAttr> for ScimValue {
    fn from(sa: ScimAttr) -> Self {
        ScimValue::Simple(sa)
    }
}

impl Eq for ScimAttr {}

impl PartialEq for ScimAttr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ScimAttr::String(l), ScimAttr::String(r)) => l == r,
            (ScimAttr::Bool(l), ScimAttr::Bool(r)) => l == r,
            (ScimAttr::Decimal(l), ScimAttr::Decimal(r)) => l == r,
            (ScimAttr::Integer(l), ScimAttr::Integer(r)) => l == r,
            (ScimAttr::DateTime(l), ScimAttr::DateTime(r)) => l == r,
            (ScimAttr::Binary(l), ScimAttr::Binary(r)) => l == r,
            (ScimAttr::Reference(l), ScimAttr::Reference(r)) => l == r,
            _ => false,
        }
    }
}

pub type ScimComplexAttr = BTreeMap<String, ScimAttr>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum ScimValue {
    Simple(ScimAttr),
    Complex(ScimComplexAttr),
    MultiSimple(Vec<ScimAttr>),
    MultiComplex(Vec<ScimComplexAttr>),
}

impl ScimValue {
    pub fn len(&self) -> usize {
        match self {
            ScimValue::Simple(_) | ScimValue::Complex(_) => 1,
            ScimValue::MultiSimple(a) => a.len(),
            ScimValue::MultiComplex(a) => a.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimMeta {
    pub resource_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub location: Url,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScimEntry {
    pub schemas: Vec<String>,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimEntryGeneric {
    pub schemas: Vec<String>,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
    #[serde(flatten)]
    pub attrs: BTreeMap<String, ScimValue>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RFC7643_USER;

    #[test]
    fn parse_scim_entry() {
        let _ = tracing_subscriber::fmt::try_init();

        let u: ScimEntryGeneric =
            serde_json::from_str(RFC7643_USER).expect("Failed to parse RFC7643_USER");

        tracing::trace!(?u);

        let s = serde_json::to_string_pretty(&u).expect("Failed to serialise RFC7643_USER");
        eprintln!("{}", s);
    }
}

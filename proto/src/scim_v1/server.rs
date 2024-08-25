use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

use scim_proto::ScimEntryHeader;

use crate::attribute::Attribute;
use base64urlsafedata::Base64UrlSafeData;
use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

/// A generic ScimEntry that we receive from a client. This retains attribute
/// values in a generic state awaiting processing by schema aware transforms
#[derive(Deserialize, Debug, Clone, ToSchema)]
pub struct ScimEntryGeneric {
    #[serde(flatten)]
    pub header: ScimEntryHeader,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

/// A strongly typed ScimEntry that is for transmission to clients. This uses
/// Kanidm internal strong types for values allowing direct serialisation and
/// transmission.
#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimEntryKanidm {
    #[serde(flatten)]
    pub header: ScimEntryHeader,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, ScimValueKanidm>,
}

/// This is a strongly typed ScimValue for Kanidm. It is for serialisation only
/// since on a deserialisation path we can not know the intent of the sender
/// to how we deserialise strings. Additionally during deserialisation we need
/// to accept optional or partial types too.
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(untagged)]
pub enum ScimValueKanidm {
    Bool(bool),

    Uint32(u32),
    Integer(i64),

    Decimal(f64),
    String(String),
    #[serde(with = "time::serde::rfc3339")]
    DateTime(OffsetDateTime),

    Binary(Base64UrlSafeData),
    Reference(Url),

    Uuid(Uuid),
    // Other strong outbound types.
}

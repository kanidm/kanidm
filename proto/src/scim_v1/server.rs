use serde::{Deserialize, Serialize};
use serde_with::{base64, formats, serde_as};
use std::collections::BTreeMap;
use utoipa::ToSchema;

use scim_proto::ScimEntryHeader;

use crate::attribute::Attribute;
use serde_json::Value as JsonValue;
use time::format_description::well_known::Rfc3339;
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

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimAddress {
    pub formatted: String,
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimMail {
    pub primary: bool,
    pub value: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimApplicationPassword {
    pub uuid: Uuid,
    pub application_uuid: Uuid,
    pub label: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimBinary {
    pub label: String,
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub value: Vec<u8>,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimCertificate {
    #[serde_as(as = "Hex")]
    pub s256: Vec<u8>,
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub der: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimAuditString {
    #[serde_as(as = "Rfc3339")]
    pub date_time: OffsetDateTime,
    pub value: String,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct ScimSshPublicKey {
    pub label: String,
    pub value: String,
}

/// This is a strongly typed ScimValue for Kanidm. It is for serialisation only
/// since on a deserialisation path we can not know the intent of the sender
/// to how we deserialise strings. Additionally during deserialisation we need
/// to accept optional or partial types too.
#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(untagged)]
pub enum ScimValueKanidm {
    Bool(bool),

    Uint32(u32),
    Integer(i64),

    Decimal(f64),
    String(String),
    DateTime(#[serde_as(as = "Rfc3339")] OffsetDateTime),

    /*
    Binary(
        #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
        Vec<u8>
    ),
    */
    Reference(Url),

    Uuid(Uuid),
    // Other strong outbound types.
    ArrayString(Vec<String>),

    ArrayDateTime(#[serde_as(as = "Vec<Rfc3339>")] Vec<OffsetDateTime>),

    ArrayUuid(Vec<Uuid>),

    ArrayAddress(Vec<ScimAddress>),

    ArrayMail(Vec<ScimMail>),

    ArrayApplicationPassword(Vec<ScimApplicationPassword>),

    ArrayAuditString(Vec<ScimAuditString>),

    ArrayBinary(Vec<ScimBinary>),

    ArrayCertificate(Vec<ScimCertificate>),

    ArraySshPublicKey(Vec<ScimSshPublicKey>),
}

impl From<bool> for ScimValueKanidm {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<OffsetDateTime> for ScimValueKanidm {
    fn from(odt: OffsetDateTime) -> Self {
        Self::DateTime(odt)
    }
}

impl From<Vec<OffsetDateTime>> for ScimValueKanidm {
    fn from(set: Vec<OffsetDateTime>) -> Self {
        Self::ArrayDateTime(set)
    }
}

impl From<String> for ScimValueKanidm {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<Vec<String>> for ScimValueKanidm {
    fn from(set: Vec<String>) -> Self {
        Self::ArrayString(set)
    }
}

impl From<Uuid> for ScimValueKanidm {
    fn from(u: Uuid) -> Self {
        Self::Uuid(u)
    }
}

impl From<Vec<Uuid>> for ScimValueKanidm {
    fn from(set: Vec<Uuid>) -> Self {
        Self::ArrayUuid(set)
    }
}

impl From<u32> for ScimValueKanidm {
    fn from(u: u32) -> Self {
        Self::Uint32(u)
    }
}

impl From<Vec<ScimAddress>> for ScimValueKanidm {
    fn from(set: Vec<ScimAddress>) -> Self {
        Self::ArrayAddress(set)
    }
}

impl From<Vec<ScimMail>> for ScimValueKanidm {
    fn from(set: Vec<ScimMail>) -> Self {
        Self::ArrayMail(set)
    }
}

impl From<Vec<ScimApplicationPassword>> for ScimValueKanidm {
    fn from(set: Vec<ScimApplicationPassword>) -> Self {
        Self::ArrayApplicationPassword(set)
    }
}

impl From<Vec<ScimAuditString>> for ScimValueKanidm {
    fn from(set: Vec<ScimAuditString>) -> Self {
        Self::ArrayAuditString(set)
    }
}

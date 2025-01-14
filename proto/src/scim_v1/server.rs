use super::ScimMail;
use super::ScimOauth2ClaimMapJoinChar;
use super::ScimSshPublicKey;
use crate::attribute::Attribute;
use crate::internal::UiHint;
use scim_proto::ScimEntryHeader;
use serde::Serialize;
use serde_with::{base64, formats, hex::Hex, serde_as, skip_serializing_none};
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

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
pub enum ScimAttributeEffectiveAccess {
    /// All attributes on the entry have this permission granted
    Grant,
    /// All attributes on the entry have this permission denied
    Denied,
    /// The following attributes on the entry have this permission granted
    Allow(BTreeSet<Attribute>),
}

impl ScimAttributeEffectiveAccess {
    /// Check if the effective access allows or denies this attribute
    pub fn check(&self, attr: &Attribute) -> bool {
        match self {
            Self::Grant => true,
            Self::Denied => true,
            Self::Allow(set) => set.contains(attr),
        }
    }
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimEffectiveAccess {
    /// The identity that inherits the effective permission
    pub ident: Uuid,
    /// The target that the effective permission affects
    pub target: Uuid,
    /// If the ident may delete the target entry
    pub delete: bool,
    /// The set of effective access over search events
    pub search: ScimAttributeEffectiveAccess,
    /// The set of effective access over modify present events
    pub modify_present: ScimAttributeEffectiveAccess,
    /// The set of effective access over modify remove events
    pub modify_remove: ScimAttributeEffectiveAccess,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimAddress {
    pub formatted: String,
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimApplicationPassword {
    pub uuid: Uuid,
    pub application_uuid: Uuid,
    pub label: String,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimBinary {
    pub label: String,
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub value: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimCertificate {
    #[serde_as(as = "Hex")]
    pub s256: Vec<u8>,
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub der: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimAuditString {
    #[serde_as(as = "Rfc3339")]
    pub date_time: OffsetDateTime,
    pub value: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ScimIntentTokenState {
    Valid,
    InProgress,
    Consumed,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimIntentToken {
    pub token_id: String,
    pub state: ScimIntentTokenState,
    #[serde_as(as = "Rfc3339")]
    pub expires: OffsetDateTime,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimKeyInternal {
    pub key_id: String,
    pub status: String,
    pub usage: String,
    #[serde_as(as = "Rfc3339")]
    pub valid_from: OffsetDateTime,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimAuthSession {
    pub id: Uuid,
    #[serde_as(as = "Option<Rfc3339>")]
    pub expires: Option<OffsetDateTime>,
    #[serde_as(as = "Option<Rfc3339>")]
    pub revoked: Option<OffsetDateTime>,
    #[serde_as(as = "Rfc3339")]
    pub issued_at: OffsetDateTime,
    pub issued_by: Uuid,
    pub credential_id: Uuid,
    pub auth_type: String,
    pub session_scope: String,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2Session {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub client_id: Uuid,
    #[serde_as(as = "Rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde_as(as = "Option<Rfc3339>")]
    pub expires: Option<OffsetDateTime>,
    #[serde_as(as = "Option<Rfc3339>")]
    pub revoked: Option<OffsetDateTime>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimApiToken {
    pub id: Uuid,
    pub label: String,
    #[serde_as(as = "Option<Rfc3339>")]
    pub expires: Option<OffsetDateTime>,
    #[serde_as(as = "Rfc3339")]
    pub issued_at: OffsetDateTime,
    pub issued_by: Uuid,
    pub scope: String,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ScopeMap {
    pub group: String,
    pub group_uuid: Uuid,
    pub scopes: BTreeSet<String>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ClaimMap {
    pub group: String,
    pub group_uuid: Uuid,
    pub claim: String,
    pub join_char: ScimOauth2ClaimMapJoinChar,
    pub values: BTreeSet<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimReference {
    pub uuid: Uuid,
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
    Reference(Url),
    Uuid(Uuid),
    EntryReference(ScimReference),
    EntryReferences(Vec<ScimReference>),

    // Other strong outbound types.
    ArrayString(Vec<String>),
    ArrayDateTime(#[serde_as(as = "Vec<Rfc3339>")] Vec<OffsetDateTime>),
    ArrayUuid(Vec<Uuid>),
    ArrayBinary(Vec<ScimBinary>),
    ArrayCertificate(Vec<ScimCertificate>),

    Address(Vec<ScimAddress>),
    Mail(Vec<ScimMail>),
    ApplicationPassword(Vec<ScimApplicationPassword>),
    AuditString(Vec<ScimAuditString>),
    SshPublicKey(Vec<ScimSshPublicKey>),
    AuthSession(Vec<ScimAuthSession>),
    OAuth2Session(Vec<ScimOAuth2Session>),
    ApiToken(Vec<ScimApiToken>),
    IntentToken(Vec<ScimIntentToken>),
    OAuth2ScopeMap(Vec<ScimOAuth2ScopeMap>),
    OAuth2ClaimMap(Vec<ScimOAuth2ClaimMap>),
    KeyInternal(Vec<ScimKeyInternal>),
    UiHints(Vec<UiHint>),
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

impl From<Vec<UiHint>> for ScimValueKanidm {
    fn from(set: Vec<UiHint>) -> Self {
        Self::UiHints(set)
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

impl From<&str> for ScimValueKanidm {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
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
        Self::Address(set)
    }
}

impl From<Vec<ScimMail>> for ScimValueKanidm {
    fn from(set: Vec<ScimMail>) -> Self {
        Self::Mail(set)
    }
}

impl From<Vec<ScimApplicationPassword>> for ScimValueKanidm {
    fn from(set: Vec<ScimApplicationPassword>) -> Self {
        Self::ApplicationPassword(set)
    }
}

impl From<Vec<ScimAuditString>> for ScimValueKanidm {
    fn from(set: Vec<ScimAuditString>) -> Self {
        Self::AuditString(set)
    }
}

impl From<Vec<ScimBinary>> for ScimValueKanidm {
    fn from(set: Vec<ScimBinary>) -> Self {
        Self::ArrayBinary(set)
    }
}

impl From<Vec<ScimCertificate>> for ScimValueKanidm {
    fn from(set: Vec<ScimCertificate>) -> Self {
        Self::ArrayCertificate(set)
    }
}

impl From<Vec<ScimSshPublicKey>> for ScimValueKanidm {
    fn from(set: Vec<ScimSshPublicKey>) -> Self {
        Self::SshPublicKey(set)
    }
}

impl From<Vec<ScimAuthSession>> for ScimValueKanidm {
    fn from(set: Vec<ScimAuthSession>) -> Self {
        Self::AuthSession(set)
    }
}

impl From<Vec<ScimOAuth2Session>> for ScimValueKanidm {
    fn from(set: Vec<ScimOAuth2Session>) -> Self {
        Self::OAuth2Session(set)
    }
}

impl From<Vec<ScimApiToken>> for ScimValueKanidm {
    fn from(set: Vec<ScimApiToken>) -> Self {
        Self::ApiToken(set)
    }
}

impl From<Vec<ScimIntentToken>> for ScimValueKanidm {
    fn from(set: Vec<ScimIntentToken>) -> Self {
        Self::IntentToken(set)
    }
}

impl From<Vec<ScimOAuth2ScopeMap>> for ScimValueKanidm {
    fn from(set: Vec<ScimOAuth2ScopeMap>) -> Self {
        Self::OAuth2ScopeMap(set)
    }
}

impl From<Vec<ScimOAuth2ClaimMap>> for ScimValueKanidm {
    fn from(set: Vec<ScimOAuth2ClaimMap>) -> Self {
        Self::OAuth2ClaimMap(set)
    }
}

impl From<Vec<ScimKeyInternal>> for ScimValueKanidm {
    fn from(set: Vec<ScimKeyInternal>) -> Self {
        Self::KeyInternal(set)
    }
}

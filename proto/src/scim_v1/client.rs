//! These are types that a client will send to the server.
use super::ScimEntryGetQuery;
use super::ScimOauth2ClaimMapJoinChar;
use crate::attribute::{Attribute, SubAttribute};
use scim_proto::ScimEntryHeader;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::formats::PreferMany;
use serde_with::OneOrMany;
use serde_with::{base64, formats, serde_as, skip_serializing_none};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

pub type ScimSshPublicKeys = Vec<ScimSshPublicKey>;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScimSshPublicKey {
    pub label: String,
    pub value: SshPublicKey,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScimReference {
    pub uuid: Option<Uuid>,
    pub value: Option<String>,
}

impl<T> From<T> for ScimReference
where
    T: AsRef<str>,
{
    fn from(value: T) -> Self {
        ScimReference {
            uuid: None,
            value: Some(value.as_ref().to_string()),
        }
    }
}

pub type ScimReferences = Vec<ScimReference>;

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct ScimDateTime {
    #[serde_as(as = "Rfc3339")]
    pub date_time: OffsetDateTime,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScimCertificate {
    #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
    pub der: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScimAddress {
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ClaimMap {
    pub group: Option<String>,
    pub group_uuid: Option<Uuid>,
    pub claim: String,
    pub join_char: ScimOauth2ClaimMapJoinChar,
    pub values: BTreeSet<String>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimOAuth2ScopeMap {
    pub group: Option<String>,
    pub group_uuid: Option<Uuid>,
    pub scopes: BTreeSet<String>,
}

#[serde_as]
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntryApplicationPost {
    pub name: String,
    pub displayname: String,
    pub linked_group: ScimReference,
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScimEntryApplication {
    #[serde(flatten)]
    pub header: ScimEntryHeader,

    pub name: String,
    pub displayname: String,

    pub linked_group: Vec<super::ScimReference>,

    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[serde_as]
#[derive(Deserialize, Clone, Debug)]
pub struct ScimListApplication {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub resources: Vec<ScimEntryApplication>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ScimEntryPutKanidm {
    pub id: Uuid,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, Option<super::server::ScimValueKanidm>>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScimStrings(#[serde_as(as = "OneOrMany<_, PreferMany>")] pub Vec<String>);

#[derive(Debug, Clone, Deserialize, Default, ToSchema)]
pub struct ScimEntryPostGeneric {
    /// Create an attribute to contain the following value state.
    #[serde(flatten)]
    #[schema(value_type = Object, additional_properties = true)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScimEntryPutGeneric {
    // id is only used to target the entry in question
    pub id: Uuid,

    #[serde(flatten)]
    /// Non-standard extension - allow query options to be set in a put request. This
    /// is because a put request also returns the entry state post put, so we want
    /// to allow putters to adjust and control what is returned here.
    pub query: ScimEntryGetQuery,

    // external_id can't be set by put
    // meta is skipped on put
    // Schemas are decoded as part of "attrs".
    /// Update an attribute to contain the following value state.
    /// If the attribute is None, it is removed.
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, Option<JsonValue>>,
}

impl TryFrom<ScimEntryPutKanidm> for ScimEntryPutGeneric {
    type Error = serde_json::Error;

    fn try_from(value: ScimEntryPutKanidm) -> Result<Self, Self::Error> {
        let ScimEntryPutKanidm { id, attrs } = value;

        let attrs = attrs
            .into_iter()
            .map(|(attr, value)| {
                if let Some(v) = value {
                    serde_json::to_value(v).map(|json_value| (attr, Some(json_value)))
                } else {
                    Ok((attr, None))
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(ScimEntryPutGeneric {
            id,
            attrs,
            query: Default::default(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AttrPath {
    pub a: Attribute,
    pub s: Option<SubAttribute>,
}

impl From<Attribute> for AttrPath {
    fn from(a: Attribute) -> Self {
        Self { a, s: None }
    }
}

impl From<(Attribute, SubAttribute)> for AttrPath {
    fn from((a, s): (Attribute, SubAttribute)) -> Self {
        Self { a, s: Some(s) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ScimFilter {
    Or(Box<ScimFilter>, Box<ScimFilter>),
    And(Box<ScimFilter>, Box<ScimFilter>),
    Not(Box<ScimFilter>),

    Present(AttrPath),
    Equal(AttrPath, JsonValue),
    NotEqual(AttrPath, JsonValue),
    Contains(AttrPath, JsonValue),
    StartsWith(AttrPath, JsonValue),
    EndsWith(AttrPath, JsonValue),
    Greater(AttrPath, JsonValue),
    Less(AttrPath, JsonValue),
    GreaterOrEqual(AttrPath, JsonValue),
    LessOrEqual(AttrPath, JsonValue),

    Complex(Attribute, Box<ScimComplexFilter>),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ScimComplexFilter {
    Or(Box<ScimComplexFilter>, Box<ScimComplexFilter>),
    And(Box<ScimComplexFilter>, Box<ScimComplexFilter>),
    Not(Box<ScimComplexFilter>),

    Present(SubAttribute),
    Equal(SubAttribute, JsonValue),
    NotEqual(SubAttribute, JsonValue),
    Contains(SubAttribute, JsonValue),
    StartsWith(SubAttribute, JsonValue),
    EndsWith(SubAttribute, JsonValue),
    Greater(SubAttribute, JsonValue),
    Less(SubAttribute, JsonValue),
    GreaterOrEqual(SubAttribute, JsonValue),
    LessOrEqual(SubAttribute, JsonValue),
}

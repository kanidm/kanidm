//! These are types that a client will send to the server.
use super::ScimOauth2ClaimMapJoinChar;
use crate::attribute::Attribute;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::formats::PreferMany;
use serde_with::OneOrMany;
use serde_with::{base64, formats, serde_as, skip_serializing_none};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
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

#[derive(Serialize, Debug, Clone)]
pub struct ScimEntryPutKanidm {
    pub id: Uuid,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, Option<super::server::ScimValueKanidm>>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScimStrings(#[serde_as(as = "OneOrMany<_, PreferMany>")] pub Vec<String>);

#[derive(Debug, Clone, Deserialize)]
pub struct ScimEntryPutGeneric {
    // id is only used to target the entry in question
    pub id: Uuid,
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

        Ok(ScimEntryPutGeneric { id, attrs })
    }
}

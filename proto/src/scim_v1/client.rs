//! These are types that a client will send to the server.
use crate::attribute::Attribute;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::collections::BTreeMap;
use uuid::Uuid;

pub type ScimSshPublicKeys = Vec<ScimSshPublicKey>;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimSshPublicKey {
    pub label: String,
    pub value: SshPublicKey,
}

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

/*
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

use scim_proto::ScimEntryHeader;

use serde_json::Value as JsonValue;
use crate::attribute::Attribute;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ScimEntryGeneric {
    #[serde(flatten)]
    pub header: ScimEntryHeader,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}
*/

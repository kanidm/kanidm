use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub use scim_proto::prelude::{ScimEntry, ScimError};
use scim_proto::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ScimSyncState {
    Refresh,
    Active { cookie: Base64UrlSafeData },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ScimSyncRequest {
    pub from_state: ScimSyncState,
    pub to_state: ScimSyncState,

    // How do I want to represent different entities to kani? Split by type? All in one?
    pub entries: Vec<ScimEntry>,
    // Delete uuids?
    pub delete_uuids: Vec<Uuid>,
}

pub const SCIM_SCHEMA_SYNC_PERSON: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:sync:person";

#[derive(Serialize, Debug, Clone)]
#[serde(into = "ScimEntry")]
pub struct ScimSyncPerson {
    pub id: Uuid,
    pub external_id: Option<String>,
    pub user_name: String,
    pub display_name: String,
    pub gidnumber: Option<u32>,
    pub homedirectory: Option<String>,
    pub password_import: Option<String>,
    pub login_shell: Option<String>,
}

/*
impl TryFrom<ScimEntry> for ScimSyncPerson {
    type Error = ScimError;

    fn try_from(_value: ScimEntry) -> Result<Self, Self::Error> {
        todo!();
    }
}
*/

impl Into<ScimEntry> for ScimSyncPerson {
    fn into(self) -> ScimEntry {
        let ScimSyncPerson {
            id,
            external_id,
            user_name,
            display_name,
            gidnumber,
            homedirectory,
            password_import,
            login_shell,
        } = self;

        let schemas = vec![SCIM_SCHEMA_SYNC_PERSON.to_string()];

        let mut attrs = BTreeMap::default();

        set_string!(attrs, "userName", user_name);
        set_string!(attrs, "displayName", display_name);
        set_option_u32!(attrs, "gidNumber", gidnumber);
        set_option_string!(attrs, "homeDirectory", homedirectory);
        set_option_string!(attrs, "passwordImport", password_import);
        set_option_string!(attrs, "loginShell", login_shell);

        ScimEntry {
            schemas,
            id,
            external_id,
            meta: None,
            attrs,
        }
    }
}

pub const SCIM_SCHEMA_SYNC_GROUP: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group";

#[derive(Serialize, Debug, Clone)]
pub struct ScimExternalMember {
    pub external_id: String,
}

impl Into<ScimComplexAttr> for ScimExternalMember {
    fn into(self) -> ScimComplexAttr {
        let ScimExternalMember { external_id } = self;
        let mut attrs = BTreeMap::default();

        attrs.insert(
            "external_id".to_string(),
            ScimSimpleAttr::String(external_id),
        );

        ScimComplexAttr { attrs }
    }
}

#[derive(Serialize, Debug, Clone)]
#[serde(into = "ScimEntry")]
pub struct ScimSyncGroup {
    pub id: Uuid,
    pub external_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub gidnumber: Option<u32>,
    pub members: Vec<ScimExternalMember>,
}

/*
impl TryFrom<ScimEntry> for ScimSyncPerson {
    type Error = ScimError;

    fn try_from(_value: ScimEntry) -> Result<Self, Self::Error> {
        todo!();
    }
}
*/

impl Into<ScimEntry> for ScimSyncGroup {
    fn into(self) -> ScimEntry {
        let ScimSyncGroup {
            id,
            external_id,
            name,
            description,
            gidnumber,
            members,
        } = self;

        let schemas = vec![SCIM_SCHEMA_SYNC_GROUP.to_string()];

        let mut attrs = BTreeMap::default();

        set_string!(attrs, "name", name);
        set_option_u32!(attrs, "gidNumber", gidnumber);
        set_option_string!(attrs, "description", description);
        set_multi_complex!(attrs, "members", members);

        ScimEntry {
            schemas,
            id,
            external_id,
            meta: None,
            attrs,
        }
    }
}

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub use scim_proto::prelude::{ScimAttr, ScimComplexAttr, ScimEntry, ScimError, ScimSimpleAttr};
use scim_proto::*;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ScimSyncState {
    Refresh,
    Active { cookie: Base64UrlSafeData },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ScimSyncRequest {
    pub from_state: ScimSyncState,
    pub to_state: ScimSyncState,

    // How do I want to represent different entities to kani? Split by type? All in one?
    pub entries: Vec<ScimEntry>,
    // Delete uuids?
    pub delete_uuids: Vec<Uuid>,
}

impl ScimSyncRequest {
    pub fn need_refresh(from_state: ScimSyncState) -> Self {
        ScimSyncRequest {
            from_state,
            to_state: ScimSyncState::Refresh,
            entries: Vec::default(),
            delete_uuids: Vec::default(),
        }
    }
}

pub const SCIM_SCHEMA_SYNC: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:";
pub const SCIM_SCHEMA_SYNC_PERSON: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:person";
pub const SCIM_SCHEMA_SYNC_ACCOUNT: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:account";
pub const SCIM_SCHEMA_SYNC_POSIXACCOUNT: &str =
    "urn:ietf:params:scim:schemas:kanidm:1.0:posixaccount";

#[derive(Serialize, Debug, Clone)]
#[serde(into = "ScimEntry")]
pub struct ScimSyncPerson {
    pub id: Uuid,
    pub external_id: Option<String>,
    pub user_name: String,
    pub display_name: String,
    pub gidnumber: Option<u32>,
    pub password_import: Option<String>,
    pub login_shell: Option<String>,
}

// Need to allow this because clippy is broken and doesn't realise scimentry is out of crate
// so this can't be fulfilled
#[allow(clippy::from_over_into)]
impl Into<ScimEntry> for ScimSyncPerson {
    fn into(self) -> ScimEntry {
        let ScimSyncPerson {
            id,
            external_id,
            user_name,
            display_name,
            gidnumber,
            password_import,
            login_shell,
        } = self;

        let schemas = if gidnumber.is_some() {
            vec![
                SCIM_SCHEMA_SYNC_PERSON.to_string(),
                SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                SCIM_SCHEMA_SYNC_POSIXACCOUNT.to_string(),
            ]
        } else {
            vec![
                SCIM_SCHEMA_SYNC_PERSON.to_string(),
                SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
            ]
        };

        let mut attrs = BTreeMap::default();

        set_string!(attrs, "name", user_name);
        set_string!(attrs, "displayname", display_name);
        set_option_u32!(attrs, "gidnumber", gidnumber);
        set_option_string!(attrs, "password_import", password_import);
        set_option_string!(attrs, "loginshell", login_shell);

        ScimEntry {
            schemas,
            id,
            external_id,
            meta: None,
            attrs,
        }
    }
}

pub const SCIM_SCHEMA_SYNC_GROUP: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:group";
pub const SCIM_SCHEMA_SYNC_POSIXGROUP: &str = "urn:ietf:params:scim:schemas:kanidm:1.0:posixgroup";

#[derive(Serialize, Debug, Clone)]
pub struct ScimExternalMember {
    pub external_id: String,
}

// Need to allow this because clippy is broken and doesn't realise scimentry is out of crate
// so this can't be fulfilled
#[allow(clippy::from_over_into)]
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

// Need to allow this because clippy is broken and doesn't realise scimentry is out of crate
// so this can't be fulfilled
#[allow(clippy::from_over_into)]
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

        let schemas = if gidnumber.is_some() {
            vec![
                SCIM_SCHEMA_SYNC_GROUP.to_string(),
                SCIM_SCHEMA_SYNC_POSIXGROUP.to_string(),
            ]
        } else {
            vec![SCIM_SCHEMA_SYNC_GROUP.to_string()]
        };

        let mut attrs = BTreeMap::default();

        set_string!(attrs, "name", name);
        set_option_u32!(attrs, "gidnumber", gidnumber);
        set_option_string!(attrs, "description", description);
        set_multi_complex!(attrs, "member", members);

        ScimEntry {
            schemas,
            id,
            external_id,
            meta: None,
            attrs,
        }
    }
}

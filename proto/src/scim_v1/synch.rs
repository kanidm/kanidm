use serde::{Deserialize, Serialize};
use serde_with::{base64, formats, serde_as};
use utoipa::ToSchema;
use uuid::Uuid;

use scim_proto::user::MultiValueAttr;
use scim_proto::{ScimEntry, ScimEntryHeader};
use serde_with::skip_serializing_none;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub enum ScimSyncState {
    Refresh,
    Active {
        #[serde_as(as = "base64::Base64<base64::UrlSafe, formats::Unpadded>")]
        cookie: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub enum ScimSyncRetentionMode {
    /// No actions are to be taken - only update or create entries in the
    /// entries set.
    Ignore,
    /// All entries that have their uuid present in this set are retained.
    /// Anything not present will be deleted.
    Retain(Vec<Uuid>),
    /// Any entry with its UUID in this set will be deleted. Anything not
    /// present will be retained.
    Delete(Vec<Uuid>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ScimSyncRequest {
    pub from_state: ScimSyncState,
    pub to_state: ScimSyncState,

    // These entries are created with serde_json::to_value(ScimSyncGroup) for
    // example. This is how we can mix/match the different types.
    pub entries: Vec<ScimEntry>,

    pub retain: ScimSyncRetentionMode,
}

impl ScimSyncRequest {
    pub fn need_refresh(from_state: ScimSyncState) -> Self {
        ScimSyncRequest {
            from_state,
            to_state: ScimSyncState::Refresh,
            entries: Vec::default(),
            retain: ScimSyncRetentionMode::Ignore,
        }
    }
}

pub const SCIM_SCHEMA_SYNC_1: &str = "urn:ietf:params:scim:schemas:kanidm:sync:1:";
pub const SCIM_SCHEMA_SYNC_ACCOUNT: &str = "urn:ietf:params:scim:schemas:kanidm:sync:1:account";
pub const SCIM_SCHEMA_SYNC_GROUP: &str = "urn:ietf:params:scim:schemas:kanidm:sync:1:group";
pub const SCIM_SCHEMA_SYNC_PERSON: &str = "urn:ietf:params:scim:schemas:kanidm:sync:1:person";
pub const SCIM_SCHEMA_SYNC_POSIXACCOUNT: &str =
    "urn:ietf:params:scim:schemas:kanidm:sync:1:posixaccount";
pub const SCIM_SCHEMA_SYNC_POSIXGROUP: &str =
    "urn:ietf:params:scim:schemas:kanidm:sync:1:posixgroup";

pub const SCIM_ALGO: &str = "algo";
pub const SCIM_DIGITS: &str = "digits";
pub const SCIM_SECRET: &str = "secret";
pub const SCIM_STEP: &str = "step";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimTotp {
    /// maps to "label" in kanidm.
    pub external_id: String,
    pub secret: String,
    pub algo: String,
    pub step: u32,
    pub digits: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimSshPubKey {
    pub label: String,
    pub value: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimSyncPerson {
    #[serde(flatten)]
    pub entry: ScimEntryHeader,

    pub user_name: String,
    pub display_name: String,
    pub gidnumber: Option<u32>,
    pub password_import: Option<String>,
    pub unix_password_import: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub totp_import: Vec<ScimTotp>,
    pub login_shell: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mail: Vec<MultiValueAttr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_publickey: Vec<ScimSshPubKey>,
    pub account_valid_from: Option<String>,
    pub account_expire: Option<String>,
}

impl TryInto<ScimEntry> for ScimSyncPerson {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<ScimEntry, Self::Error> {
        serde_json::to_value(self).and_then(serde_json::from_value)
    }
}

pub struct ScimSyncPersonBuilder {
    inner: ScimSyncPerson,
}

impl ScimSyncPerson {
    pub fn builder(id: Uuid, user_name: String, display_name: String) -> ScimSyncPersonBuilder {
        ScimSyncPersonBuilder {
            inner: ScimSyncPerson {
                entry: ScimEntryHeader {
                    schemas: vec![
                        SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                        SCIM_SCHEMA_SYNC_PERSON.to_string(),
                    ],
                    id,
                    external_id: None,
                    meta: None,
                },
                user_name,
                display_name,
                gidnumber: None,
                password_import: None,
                unix_password_import: None,
                totp_import: Vec::with_capacity(0),
                login_shell: None,
                mail: Vec::with_capacity(0),
                ssh_publickey: Vec::with_capacity(0),
                account_valid_from: None,
                account_expire: None,
            },
        }
    }
}

impl ScimSyncPersonBuilder {
    pub fn set_password_import(mut self, password_import: Option<String>) -> Self {
        self.inner.password_import = password_import;
        self
    }

    pub fn set_unix_password_import(mut self, unix_password_import: Option<String>) -> Self {
        self.inner.unix_password_import = unix_password_import;
        self
    }

    pub fn set_totp_import(mut self, totp_import: Vec<ScimTotp>) -> Self {
        self.inner.totp_import = totp_import;
        self
    }

    pub fn set_mail(mut self, mail: Vec<MultiValueAttr>) -> Self {
        self.inner.mail = mail;
        self
    }

    pub fn set_ssh_publickey(mut self, ssh_publickey: Vec<ScimSshPubKey>) -> Self {
        self.inner.ssh_publickey = ssh_publickey;
        self
    }

    pub fn set_login_shell(mut self, login_shell: Option<String>) -> Self {
        self.inner.login_shell = login_shell;
        self
    }

    pub fn set_account_valid_from(mut self, account_valid_from: Option<String>) -> Self {
        self.inner.account_valid_from = account_valid_from;
        self
    }

    pub fn set_account_expire(mut self, account_expire: Option<String>) -> Self {
        self.inner.account_expire = account_expire;
        self
    }

    pub fn set_gidnumber(mut self, gidnumber: Option<u32>) -> Self {
        self.inner.gidnumber = gidnumber;
        if self.inner.gidnumber.is_some() {
            self.inner.entry.schemas = vec![
                SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                SCIM_SCHEMA_SYNC_PERSON.to_string(),
                SCIM_SCHEMA_SYNC_POSIXACCOUNT.to_string(),
            ];
        } else {
            self.inner.entry.schemas = vec![
                SCIM_SCHEMA_SYNC_ACCOUNT.to_string(),
                SCIM_SCHEMA_SYNC_PERSON.to_string(),
            ];
        }
        self
    }

    pub fn set_external_id(mut self, external_id: Option<String>) -> Self {
        self.inner.entry.external_id = external_id;
        self
    }

    pub fn build(self) -> ScimSyncPerson {
        self.inner
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimExternalMember {
    pub external_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimSyncGroup {
    #[serde(flatten)]
    pub entry: ScimEntryHeader,

    pub name: String,
    pub description: Option<String>,
    pub gidnumber: Option<u32>,
    pub members: Vec<ScimExternalMember>,
}

impl TryInto<ScimEntry> for ScimSyncGroup {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<ScimEntry, Self::Error> {
        serde_json::to_value(self).and_then(serde_json::from_value)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimSyncGroupBuilder {
    inner: ScimSyncGroup,
}

impl ScimSyncGroup {
    pub fn builder(name: String, id: Uuid) -> ScimSyncGroupBuilder {
        ScimSyncGroupBuilder {
            inner: ScimSyncGroup {
                entry: ScimEntryHeader {
                    schemas: vec![SCIM_SCHEMA_SYNC_GROUP.to_string()],
                    id,
                    external_id: None,
                    meta: None,
                },
                name,
                description: None,
                gidnumber: None,
                members: Vec::with_capacity(0),
            },
        }
    }
}

impl ScimSyncGroupBuilder {
    pub fn set_description(mut self, desc: Option<String>) -> Self {
        self.inner.description = desc;
        self
    }

    pub fn set_gidnumber(mut self, gidnumber: Option<u32>) -> Self {
        self.inner.gidnumber = gidnumber;
        if self.inner.gidnumber.is_some() {
            self.inner.entry.schemas = vec![
                SCIM_SCHEMA_SYNC_GROUP.to_string(),
                SCIM_SCHEMA_SYNC_POSIXGROUP.to_string(),
            ];
        } else {
            self.inner.entry.schemas = vec![SCIM_SCHEMA_SYNC_GROUP.to_string()];
        }
        self
    }

    pub fn set_members<I>(mut self, member_iter: I) -> Self
    where
        I: Iterator<Item = String>,
    {
        self.inner.members = member_iter
            .map(|external_id| ScimExternalMember { external_id })
            .collect();
        self
    }

    pub fn set_external_id(mut self, external_id: Option<String>) -> Self {
        self.inner.entry.external_id = external_id;
        self
    }

    pub fn build(self) -> ScimSyncGroup {
        self.inner
    }
}

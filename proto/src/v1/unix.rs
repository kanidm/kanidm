use serde::{Deserialize, Serialize};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use sshkeys::{KeyType, KeyTypeKind, PublicKeyKind};
use std::fmt::{self, Display};
use utoipa::ToSchema;
use uuid::Uuid;

use serde_with::skip_serializing_none;

use crate::constants::{ATTR_GROUP, ATTR_LDAP_SSHPUBLICKEY};

#[allow(dead_code)]
#[derive(ToSchema)]
#[schema(as = KeyTypeKind, value_type = String)]
pub struct KeyTypeKindSchema(KeyTypeKind);

#[derive(ToSchema)]
#[schema(as = KeyType)]
pub struct KeyTypeSchema {
    pub name: &'static str,
    pub short_name: &'static str,
    pub is_cert: bool,
    pub is_sk: bool,
    #[schema(value_type = String)]
    pub kind: KeyTypeKind,
    pub plain: &'static str,
}

#[allow(dead_code)]
#[derive(ToSchema)]
#[schema(as = PublicKeyKind, value_type = String)]
pub struct PublicKeyKindSchema(PublicKeyKind);

#[derive(ToSchema)]
#[schema(as = SshPublicKey)]
pub struct SshPublicKeySchema {
    #[schema(value_type = String)]
    pub key_type: KeyType,
    #[schema(value_type = String)]
    pub kind: PublicKeyKind,
    pub comment: Option<String>,
}

/// A token representing the details of a unix group
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct UnixGroupToken {
    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    pub gidnumber: u32,
}

impl Display for UnixGroupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[ spn: {}, gidnumber: {}, name: {}, uuid: {} ]",
            self.spn, self.gidnumber, self.name, self.uuid
        )
    }
}

/// Request addition of unix attributes to a group.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct GroupUnixExtend {
    pub gidnumber: Option<u32>,
}

/// A token representing the details of a unix user
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct UnixUserToken {
    pub name: String,
    pub spn: String,
    pub displayname: String,
    pub gidnumber: u32,
    pub uuid: Uuid,
    pub shell: Option<String>,
    pub groups: Vec<UnixGroupToken>,
    #[schema(value_type = Vec<String>)]
    pub sshkeys: Vec<SshPublicKey>,
    // The default value of bool is false.
    #[serde(default)]
    pub valid: bool,
}

impl Display for UnixUserToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "gidnumber: {}", self.gidnumber)?;
        match &self.shell {
            Some(s) => writeln!(f, "shell: {s}")?,
            None => writeln!(f, "shell: <none>")?,
        }
        self.sshkeys
            .iter()
            .try_for_each(|s| writeln!(f, "{ATTR_LDAP_SSHPUBLICKEY}: {s}"))?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "{ATTR_GROUP}: {g}"))
    }
}

/// Request addition of unix attributes to an account
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountUnixExtend {
    pub gidnumber: Option<u32>,
    // TODO: rename shell to loginshell everywhere we can find
    /// The internal attribute is "loginshell" but we use shell in the API currently
    #[serde(alias = "loginshell")]
    pub shell: Option<String>,
}

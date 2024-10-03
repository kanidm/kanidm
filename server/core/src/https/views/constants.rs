use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileMenuItems {
    UserProfile,
    SshKeys,
    Credentials,
    UnixPassword,
}

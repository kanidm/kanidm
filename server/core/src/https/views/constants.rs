use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileMenuItems {
    UserProfile,
    SshKeys,
    Credentials,
    UnixPassword,
}

#[allow(dead_code)]
pub(crate) enum Urls {
    CredReset,
    Profile,
    SshKeys,
    ProfileUnlock,
    Credentials,
    UnixPassword,
    UpdateCredentials,
}

impl AsRef<str> for Urls {
    fn as_ref(&self) -> &str {
        match self {
            Self::CredReset => "/ui/reset",
            Self::Profile => "/ui/profile",
            Self::ProfileUnlock => "/ui/profile/unlock",
            Self::SshKeys => "/ui/profile/ssh_keys",
            Self::Credentials => "/ui/profile/credentials",
            Self::UnixPassword => "/ui/profile/unix_password",
            Self::UpdateCredentials => "/ui/update_credentials",
        }
    }
}

impl std::fmt::Display for Urls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

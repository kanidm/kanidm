use serde::{Deserialize, Serialize};

#[derive(PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileMenuItems {
    UserProfile,
    Credentials,
    UnixPassword,
}

#[allow(dead_code)]
pub(crate) enum Urls {
    Apps,
    CredReset,
    Profile,
    UpdateCredentials,
    Oauth2Resume,
    Login,
}

impl AsRef<str> for Urls {
    fn as_ref(&self) -> &str {
        match self {
            Self::Apps => "/ui/apps",
            Self::CredReset => "/ui/reset",
            Self::Profile => "/ui/profile",
            Self::UpdateCredentials => "/ui/update_credentials",
            Self::Oauth2Resume => "/ui/oauth2/resume",
            Self::Login => "/ui/login",
        }
    }
}

impl std::fmt::Display for Urls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

use crate::v1::ApiTokenPurpose;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
/// This is a description of a linked or connected application for a user. This is
/// used in the UI to render applications on the dashboard for a user to access.
pub enum AppLink {
    Oauth2 {
        name: String,
        display_name: String,
        redirect_url: Url,
        // Where the icon can be retrieved from.
        icon: Option<Url>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ScimSyncToken {
    // uuid of the token?
    pub token_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

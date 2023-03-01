use serde::{Deserialize, Serialize};
use url::Url;

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

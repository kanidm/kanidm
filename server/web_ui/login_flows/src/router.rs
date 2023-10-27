#![allow(clippy::disallowed_types)] // because `Routable` uses a hashmap
use serde::{Deserialize, Serialize};
use yew_router::Routable;

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum LoginRoute {
    #[at("/ui/login")]
    Login,
    #[at("/ui/reauth")]
    Reauth,

    #[at("/ui/oauth2")]
    Oauth2,

    #[not_found]
    #[at("/ui/login/404")]
    NotFound,
}

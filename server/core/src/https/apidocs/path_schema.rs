//! Path schema objects for the API documentation.

use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct UuidOrName {
    id: String,
}

#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct TokenId {
    token_id: String,
}
#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct Id {
    id: String,
}
#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct Attr {
    attr: String,
}

#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct RsName {
    // The short name of the OAuth2 resource server to target
    rs_name: String,
}

#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct GroupName {
    // The short name of the group to target
    group: String,
}

//! Path schema objects for the API documentation.

use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

#[derive(IntoParams, Serialize, Deserialize, Debug)]
pub(crate) struct UuidOrName {
    id: String,
}

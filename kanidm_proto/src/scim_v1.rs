use base64urlsafedata::Base64UrlSafeData;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum ScimSyncState {
    Initial,
    Active { cookie: Base64UrlSafeData },
}

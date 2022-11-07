use base64urlsafedata::Base64UrlSafeData;
use scim_proto::ScimEntry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub enum ScimSyncState {
    Initial,
    Active { cookie: Base64UrlSafeData },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScimSyncRequest {
    from_state: ScimSyncState,
    to_state: ScimSyncState,

    // How do I want to represent different entities to kani? Split by type? All in one?
    entries: Vec<ScimEntry>,
    // Delete uuids?
    delete_uuids: Vec<Uuid>,
}

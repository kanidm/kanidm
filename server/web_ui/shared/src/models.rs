use gloo::storage::{
    // LocalStorage as PersistentStorage,
    SessionStorage as TemporaryStorage,
    Storage,
};
use kanidm_proto::v1::{CUSessionToken, CUStatus};

/// Pulls the "cred_update_session" element from the browser's temporary storage
pub fn get_cred_update_session() -> Option<(CUSessionToken, CUStatus)> {
    let l: Result<(CUSessionToken, CUStatus), _> = TemporaryStorage::get("cred_update_session");
    l.ok()
}

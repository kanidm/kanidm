use std::time::Duration;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq, PartialOrd, Ord)]
pub struct Cid {
    // Mental note: Derive ord always checks in order of struct fields.
    pub ts: Duration,
    pub d_uuid: Uuid,
    pub s_uuid: Uuid,
}

impl Cid {
    pub fn new(d_uuid: Uuid, s_uuid: Uuid, ts: Duration) -> Self {
        Cid { d_uuid, s_uuid, ts }
    }
}

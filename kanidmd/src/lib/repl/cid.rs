use std::time::Duration;
use uuid::Uuid;

#[derive(Debug)]
pub struct Cid {
    d_uuid: Uuid,
    s_uuid: Uuid,
    ts: Duration,
}

impl Cid {
    pub fn new(d_uuid: Uuid, s_uuid: Uuid, ts: Duration) -> Self {
        Cid { d_uuid, s_uuid, ts }
    }
}

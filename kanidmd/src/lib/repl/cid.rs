use kanidm_proto::v1::OperationError;
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
    #[cfg(test)]
    pub(crate) fn new(d_uuid: Uuid, s_uuid: Uuid, ts: Duration) -> Self {
        Cid { d_uuid, s_uuid, ts }
    }

    pub fn new_lamport(d_uuid: Uuid, s_uuid: Uuid, ts: Duration, max_ts: &Duration) -> Self {
        let ts = if ts > *max_ts {
            ts
        } else {
            *max_ts + Duration::from_nanos(1)
        };
        Cid { d_uuid, s_uuid, ts }
    }

    #[cfg(test)]
    pub unsafe fn new_zero() -> Self {
        Cid {
            d_uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            s_uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            ts: Duration::new(0, 0),
        }
    }

    pub fn sub_secs(&self, secs: u64) -> Result<Self, OperationError> {
        self.ts
            .checked_sub(Duration::from_secs(secs))
            .map(|r| Cid {
                d_uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
                s_uuid: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
                ts: r,
            })
            .ok_or(OperationError::InvalidReplCID)
    }
}

#[cfg(test)]
mod tests {
    use crate::repl::cid::Cid;
    use std::cmp::Ordering;
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn test_cid_ordering() {
        // Check diff ts
        let cid_a = Cid::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Duration::new(5, 0),
        );
        let cid_b = Cid::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Duration::new(15, 0),
        );

        assert!(cid_a.cmp(&cid_a) == Ordering::Equal);
        assert!(cid_a.cmp(&cid_b) == Ordering::Less);
        assert!(cid_b.cmp(&cid_a) == Ordering::Greater);

        // check same ts diff d_uuid
        let cid_c = Cid::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Duration::new(5, 0),
        );
        let cid_d = Cid::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Duration::new(5, 0),
        );

        assert!(cid_c.cmp(&cid_c) == Ordering::Equal);
        assert!(cid_c.cmp(&cid_d) == Ordering::Less);
        assert!(cid_d.cmp(&cid_c) == Ordering::Greater);

        // check same ts, d_uuid, diff s_uuid
        let cid_e = Cid::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
            Duration::new(5, 0),
        );
        let cid_f = Cid::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Duration::new(5, 0),
        );

        assert!(cid_e.cmp(&cid_e) == Ordering::Equal);
        assert!(cid_e.cmp(&cid_f) == Ordering::Less);
        assert!(cid_f.cmp(&cid_e) == Ordering::Greater);
    }

    #[test]
    fn test_cid_lamport() {
        let d_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let s_uuid = d_uuid.clone();

        let ts5 = Duration::new(5, 0);
        let ts10 = Duration::new(10, 0);
        let ts15 = Duration::new(15, 0);

        let cid_z = unsafe { Cid::new_zero() };

        let cid_a = Cid::new_lamport(d_uuid, s_uuid, ts5.clone(), &ts5);
        assert!(cid_a.cmp(&cid_z) == Ordering::Greater);
        let cid_b = Cid::new_lamport(d_uuid, s_uuid, ts15.clone(), &ts10);
        assert!(cid_b.cmp(&cid_a) == Ordering::Greater);
        // Even with an older ts, we should still step forward.
        let cid_c = Cid::new_lamport(d_uuid, s_uuid, ts10, &ts15);
        assert!(cid_c.cmp(&cid_b) == Ordering::Greater);
    }
}

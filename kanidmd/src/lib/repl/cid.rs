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
}

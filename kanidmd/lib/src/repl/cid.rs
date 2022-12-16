use std::fmt;
use std::time::Duration;

use crate::prelude::*;
use kanidm_proto::v1::OperationError;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq, PartialOrd, Ord, Hash)]
pub struct Cid {
    // Mental note: Derive ord always checks in order of struct fields.
    pub ts: Duration,
    pub d_uuid: Uuid,
    pub s_uuid: Uuid,
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}-{}", self.ts.as_nanos(), self.d_uuid, self.s_uuid)
    }
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
        Cid { ts, d_uuid, s_uuid }
    }

    #[cfg(test)]
    pub unsafe fn new_zero() -> Self {
        Self::new_count(0)
    }

    #[cfg(test)]
    pub unsafe fn new_count(c: u64) -> Self {
        Cid {
            d_uuid: uuid!("00000000-0000-0000-0000-000000000000"),
            s_uuid: uuid!("00000000-0000-0000-0000-000000000000"),
            ts: Duration::new(c, 0),
        }
    }

    #[cfg(test)]
    pub fn new_random_s_d(ts: Duration) -> Self {
        Cid {
            d_uuid: Uuid::new_v4(),
            s_uuid: Uuid::new_v4(),
            ts,
        }
    }

    #[allow(clippy::expect_used)]
    pub fn sub_secs(&self, secs: u64) -> Result<Self, OperationError> {
        self.ts
            .checked_sub(Duration::from_secs(secs))
            .map(|r| Cid {
                d_uuid: uuid!("00000000-0000-0000-0000-000000000000"),
                s_uuid: uuid!("00000000-0000-0000-0000-000000000000"),
                ts: r,
            })
            .ok_or(OperationError::InvalidReplChangeId)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::cmp::Ordering;
    use std::time::Duration;

    use crate::repl::cid::Cid;

    #[test]
    fn test_cid_ordering() {
        // Check diff ts
        let cid_a = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(5, 0),
        );
        let cid_b = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(15, 0),
        );

        assert!(cid_a.cmp(&cid_a) == Ordering::Equal);
        assert!(cid_a.cmp(&cid_b) == Ordering::Less);
        assert!(cid_b.cmp(&cid_a) == Ordering::Greater);

        // check same ts diff d_uuid
        let cid_c = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000000"),
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(5, 0),
        );
        let cid_d = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(5, 0),
        );

        assert!(cid_c.cmp(&cid_c) == Ordering::Equal);
        assert!(cid_c.cmp(&cid_d) == Ordering::Less);
        assert!(cid_d.cmp(&cid_c) == Ordering::Greater);

        // check same ts, d_uuid, diff s_uuid
        let cid_e = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            uuid!("00000000-0000-0000-0000-000000000000"),
            Duration::new(5, 0),
        );
        let cid_f = Cid::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            uuid!("00000000-0000-0000-0000-000000000001"),
            Duration::new(5, 0),
        );

        assert!(cid_e.cmp(&cid_e) == Ordering::Equal);
        assert!(cid_e.cmp(&cid_f) == Ordering::Less);
        assert!(cid_f.cmp(&cid_e) == Ordering::Greater);
    }

    #[test]
    fn test_cid_lamport() {
        let d_uuid = uuid!("00000000-0000-0000-0000-000000000001");
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

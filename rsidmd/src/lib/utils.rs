use uuid::{Builder, Uuid};
use std::time::{Duration};

pub type SID = [u8; 4];

fn uuid_from_u64_u32(a: u64, b: u32, sid: &SID) -> Uuid {
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&a.to_be_bytes());
    v.extend_from_slice(&b.to_be_bytes());
    v.extend_from_slice(sid);

    Builder::from_slice(v.as_slice()).unwrap().build()
}

// SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
pub fn uuid_from_duration(d: Duration, sid: &SID) -> Uuid {
    uuid_from_u64_u32(d.as_secs(), d.subsec_nanos(), sid)
}


#[cfg(test)]
mod tests {
    use std::time::Duration;
    use crate::utils::uuid_from_duration;

    #[test]
    fn test_utils_uuid_from_duration() {
        let u1 = uuid_from_duration(Duration::from_secs(1), &[0xff; 4]);
        assert_eq!("00000000-0000-0001-0000-0000ffffffff", u1.to_hyphenated().to_string());

        let u2 = uuid_from_duration(Duration::from_secs(1000), &[0xff; 4]);
        assert_eq!("00000000-0000-03e8-0000-0000ffffffff", u2.to_hyphenated().to_string());
    }
}




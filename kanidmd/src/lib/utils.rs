use std::time::Duration;
use std::time::SystemTime;
use uuid::{Builder, Uuid};

use rand::distributions::Distribution;
use rand::{thread_rng, Rng};

#[derive(Debug)]
pub struct DistinctAlpha;

pub type SID = [u8; 4];

pub fn uuid_to_gid_u32(u: &Uuid) -> u32 {
    let b_ref = u.as_bytes();
    let mut x: [u8; 4] = [0; 4];
    x.clone_from_slice(&b_ref[12..16]);
    u32::from_be_bytes(x)
}

fn uuid_from_u64_u32(a: u64, b: u32, sid: SID) -> Uuid {
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&a.to_be_bytes());
    v.extend_from_slice(&b.to_be_bytes());
    v.extend_from_slice(&sid);

    Builder::from_slice(v.as_slice()).unwrap().build()
}

pub fn uuid_from_duration(d: Duration, sid: SID) -> Uuid {
    uuid_from_u64_u32(d.as_secs(), d.subsec_nanos(), sid)
}

pub fn password_from_random() -> String {
    let rand_string: String = thread_rng().sample_iter(&DistinctAlpha).take(48).collect();
    rand_string
}

pub fn readable_password_from_random() -> String {
    let mut trng = thread_rng();
    format!(
        "{}-{}-{}-{}",
        trng.sample_iter(&DistinctAlpha).take(4).collect::<String>(),
        trng.sample_iter(&DistinctAlpha).take(4).collect::<String>(),
        trng.sample_iter(&DistinctAlpha).take(4).collect::<String>(),
        trng.sample_iter(&DistinctAlpha).take(4).collect::<String>(),
    )
}

#[allow(dead_code)]
pub fn uuid_from_now(sid: SID) -> Uuid {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    uuid_from_duration(d, sid)
}

impl Distribution<char> for DistinctAlpha {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
        const RANGE: u32 = 55;
        const GEN_ASCII_STR_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ\
                abcdefghjkpqrstuvwxyz\
                0123456789";
        // This probably needs to be checked for entropy/quality
        loop {
            let var = rng.next_u32() >> (32 - 6);
            if var < RANGE {
                return GEN_ASCII_STR_CHARSET[var as usize] as char;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{uuid_from_duration, uuid_to_gid_u32};
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn test_utils_uuid_from_duration() {
        let u1 = uuid_from_duration(Duration::from_secs(1), [0xff; 4]);
        assert_eq!(
            "00000000-0000-0001-0000-0000ffffffff",
            u1.to_hyphenated().to_string()
        );

        let u2 = uuid_from_duration(Duration::from_secs(1000), [0xff; 4]);
        assert_eq!(
            "00000000-0000-03e8-0000-0000ffffffff",
            u2.to_hyphenated().to_string()
        );
    }

    #[test]
    fn test_utils_uuid_to_gid_u32() {
        let u1 = Uuid::parse_str("00000000-0000-0001-0000-000000000000").unwrap();
        let r1 = uuid_to_gid_u32(&u1);
        assert!(r1 == 0);

        let u2 = Uuid::parse_str("00000000-0000-0001-0000-0000ffffffff").unwrap();
        let r2 = uuid_to_gid_u32(&u2);
        assert!(r2 == 0xffffffff);

        let u3 = Uuid::parse_str("00000000-0000-0001-0000-ffff12345678").unwrap();
        let r3 = uuid_to_gid_u32(&u3);
        assert!(r3 == 0x12345678);
    }
}

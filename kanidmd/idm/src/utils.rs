use hashbrown::HashSet;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use filetime::FileTime;
use touch::file as touch_file;
use uuid::{Builder, Uuid};

use rand::distributions::Distribution;
use rand::{thread_rng, Rng};

#[cfg(not(target_family = "windows"))]
use std::fs::Metadata;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
// #[cfg(target_os = "windows")]
// use std::os::windows::fs::MetadataExt;

#[cfg(target_family = "unix")]
use users::{get_current_gid, get_current_uid};

#[derive(Debug)]
pub struct DistinctAlpha;

pub type Sid = [u8; 4];

pub fn uuid_to_gid_u32(u: Uuid) -> u32 {
    let b_ref = u.as_bytes();
    let mut x: [u8; 4] = [0; 4];
    x.clone_from_slice(&b_ref[12..16]);
    u32::from_be_bytes(x)
}

fn uuid_from_u64_u32(a: u64, b: u32, sid: Sid) -> Uuid {
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&a.to_be_bytes());
    v.extend_from_slice(&b.to_be_bytes());
    v.extend_from_slice(&sid);

    #[allow(clippy::expect_used)]
    Builder::from_slice(v.as_slice())
        .expect("invalid slice for uuid builder")
        .into_uuid()
}

pub fn uuid_from_duration(d: Duration, sid: Sid) -> Uuid {
    uuid_from_u64_u32(d.as_secs(), d.subsec_nanos(), sid)
}

pub fn password_from_random() -> String {
    let rand_string: String = thread_rng().sample_iter(&DistinctAlpha).take(48).collect();
    rand_string
}

pub fn backup_code_from_random() -> HashSet<String> {
    (0..8)
        .into_iter()
        .map(|_| readable_password_from_random())
        .collect()
}

pub fn readable_password_from_random() -> String {
    // 2^112 bits, means we need at least 55^20 to have as many bits of entropy.
    // this leads us to 4 groups of 5 to create 55^20
    let mut trng = thread_rng();
    format!(
        "{}-{}-{}-{}",
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
    )
}

pub fn duration_from_epoch_now() -> Duration {
    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("invalid duration from epoch now")
}

pub fn touch_file_or_quit(file_path: &str) {
    /*
    Attempt to touch the file file_path, will quit the application if it fails for any reason.

    Will also create a new file if it doesn't already exist.
    */
    if PathBuf::from(file_path).exists() {
        let t = FileTime::from_system_time(SystemTime::now());
        match filetime::set_file_times(file_path, t, t) {
            Ok(_) => debug!(
                "Successfully touched existing file {}, can continue",
                file_path
            ),
            Err(e) => {
                match e.kind() {
                    ErrorKind::PermissionDenied => {
                        // we bail here because you won't be able to write them back...
                        error!("Permission denied writing to {}, quitting.", file_path)
                    }
                    _ => {
                        error!(
                            "Failed to write to {} due to error: {:?} ... quitting.",
                            file_path, e
                        )
                    }
                }
                std::process::exit(1);
            }
        }
    } else {
        match touch_file::write(file_path, "", false) {
            Ok(_) => debug!("Successfully touched new file {}", file_path),
            Err(e) => {
                error!(
                    "Failed to write to {} due to error: {:?} ... quitting.",
                    file_path, e
                );
                std::process::exit(1);
            }
        };
    }
}

/*
#[allow(dead_code)]
pub fn uuid_from_now(sid: Sid) -> Uuid {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    uuid_from_duration(d, sid)
}
*/

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

#[cfg(target_family = "unix")]
pub fn file_permissions_readonly(meta: &Metadata) -> bool {
    // Who are we running as?
    let cuid = get_current_uid();
    let cgid = get_current_gid();

    // Who owns the file?
    // Who is the group owner of the file?
    let f_gid = meta.st_gid();
    let f_uid = meta.st_uid();

    let f_mode = meta.st_mode();

    !(
        // If we are the owner, we have write perms as we can alter the DAC rights
        cuid == f_uid ||
        // If we are the group owner, check the mode bits do not have write.
        (cgid == f_gid && (f_mode & 0o0020) != 0) ||
        // Finally, check that everyone bits don't have write.
        ((f_mode & 0o0002) != 0)
    )
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
            u1.as_hyphenated().to_string()
        );

        let u2 = uuid_from_duration(Duration::from_secs(1000), [0xff; 4]);
        assert_eq!(
            "00000000-0000-03e8-0000-0000ffffffff",
            u2.as_hyphenated().to_string()
        );
    }

    #[test]
    fn test_utils_uuid_to_gid_u32() {
        let u1 = Uuid::parse_str("00000000-0000-0001-0000-000000000000").unwrap();
        let r1 = uuid_to_gid_u32(u1);
        assert!(r1 == 0);

        let u2 = Uuid::parse_str("00000000-0000-0001-0000-0000ffffffff").unwrap();
        let r2 = uuid_to_gid_u32(u2);
        assert!(r2 == 0xffffffff);

        let u3 = Uuid::parse_str("00000000-0000-0001-0000-ffff12345678").unwrap();
        let r3 = uuid_to_gid_u32(u3);
        assert!(r3 == 0x12345678);
    }
}

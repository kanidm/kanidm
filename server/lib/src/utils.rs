//! `utils.rs` - the projects kitchen junk drawer.

use crate::prelude::*;
use hashbrown::HashSet;
use rand::distributions::{Distribution, Uniform};
use rand::{thread_rng, Rng};
use std::ops::Range;

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
    uuid::Builder::from_slice(v.as_slice())
        .expect("invalid slice for uuid builder")
        .into_uuid()
}

pub fn uuid_from_duration(d: Duration, sid: Sid) -> Uuid {
    uuid_from_u64_u32(d.as_secs(), d.subsec_nanos(), sid)
}

pub(crate) fn password_from_random_len(len: u32) -> String {
    thread_rng()
        .sample_iter(&DistinctAlpha)
        .take(len as usize)
        .collect::<String>()
}

pub fn password_from_random() -> String {
    password_from_random_len(48)
}

pub fn backup_code_from_random() -> HashSet<String> {
    (0..8).map(|_| readable_password_from_random()).collect()
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

impl Distribution<char> for DistinctAlpha {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
        const RANGE: u32 = 55;
        const GEN_ASCII_STR_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ\
                abcdefghjkpqrstuvwxyz\
                0123456789";

        let range = Uniform::new(0, RANGE);

        let n = range.sample(rng);
        GEN_ASCII_STR_CHARSET[n as usize] as char
    }
}

pub(crate) struct GraphemeClusterIter<'a> {
    value: &'a str,
    char_bounds: Vec<usize>,
    window: usize,
    range: Range<usize>,
}

impl<'a> GraphemeClusterIter<'a> {
    pub fn new(value: &'a str, window: usize) -> Self {
        let char_bounds = if value.len() < window {
            Vec::with_capacity(0)
        } else {
            let mut char_bounds = Vec::with_capacity(value.len());
            for idx in 0..value.len() {
                if value.is_char_boundary(idx) {
                    char_bounds.push(idx);
                }
            }
            char_bounds.push(value.len());
            char_bounds
        };

        let window_max = char_bounds.len().checked_sub(window).unwrap_or(0);
        let range = 0..window_max;

        GraphemeClusterIter {
            value,
            char_bounds,
            window,
            range,
        }
    }
}

impl<'a> Iterator for GraphemeClusterIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        self.range.next().map(|idx| {
            let min = self.char_bounds[idx];
            let max = self.char_bounds[idx + self.window];
            &self.value[min..max]
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let clusters = self.char_bounds.len().checked_sub(1).unwrap_or(0);
        (clusters, Some(clusters))
    }
}

pub(crate) fn trigraph_iter(value: &str) -> impl Iterator<Item = &str> {
    GraphemeClusterIter::new(value, 3)
        .chain(GraphemeClusterIter::new(value, 2))
        .chain(GraphemeClusterIter::new(value, 1))
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::time::Duration;

    use crate::utils::{uuid_from_duration, uuid_to_gid_u32, GraphemeClusterIter};

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
        let u1 = uuid!("00000000-0000-0001-0000-000000000000");
        let r1 = uuid_to_gid_u32(u1);
        assert!(r1 == 0);

        let u2 = uuid!("00000000-0000-0001-0000-0000ffffffff");
        let r2 = uuid_to_gid_u32(u2);
        assert!(r2 == 0xffffffff);

        let u3 = uuid!("00000000-0000-0001-0000-ffff12345678");
        let r3 = uuid_to_gid_u32(u3);
        assert!(r3 == 0x12345678);
    }

    #[test]
    fn test_utils_grapheme_cluster_iter() {
        let d = "❤️🧡💛💚💙💜";

        let gc_expect = vec!["❤", "\u{fe0f}", "🧡", "💛", "💚", "💙", "💜"];
        let gc: Vec<_> = GraphemeClusterIter::new(d, 1).collect();
        assert_eq!(gc, gc_expect);

        let gc_expect = vec!["❤\u{fe0f}", "\u{fe0f}🧡", "🧡💛", "💛💚", "💚💙", "💙💜"];
        let gc: Vec<_> = GraphemeClusterIter::new(d, 2).collect();
        assert_eq!(gc, gc_expect);

        let gc_expect = vec!["❤\u{fe0f}🧡", "\u{fe0f}🧡💛", "🧡💛💚", "💛💚💙", "💚💙💜"];
        let gc: Vec<_> = GraphemeClusterIter::new(d, 3).collect();
        assert_eq!(gc, gc_expect);

        let d = "🤷🏿‍♂️";

        let gc_expect = vec!["🤷", "🏿", "\u{200d}", "♂", "\u{fe0f}"];
        let gc: Vec<_> = GraphemeClusterIter::new(d, 1).collect();
        assert_eq!(gc, gc_expect);

        let gc_expect = vec!["🤷🏿", "🏿\u{200d}", "\u{200d}♂", "♂\u{fe0f}"];
        let gc: Vec<_> = GraphemeClusterIter::new(d, 2).collect();
        assert_eq!(gc, gc_expect);

        let gc_expect = vec!["🤷🏿\u{200d}", "🏿\u{200d}♂", "\u{200d}♂\u{fe0f}"];
        let gc: Vec<_> = GraphemeClusterIter::new(d, 3).collect();
        assert_eq!(gc, gc_expect);
    }
}

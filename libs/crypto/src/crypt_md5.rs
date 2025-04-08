use md5::{Digest, Md5};
use std::cmp::min;

/// Maximium salt length.
const MD5_MAGIC: &str = "$1$";
const MD5_TRANSPOSE: &[u8] = b"\x0c\x06\x00\x0d\x07\x01\x0e\x08\x02\x0f\x09\x03\x05\x0a\x04\x0b";

const CRYPT_HASH64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn md5_sha2_hash64_encode(bs: &[u8]) -> String {
    let ngroups = bs.len().div_ceil(3);
    let mut out = String::with_capacity(ngroups * 4);
    for g in 0..ngroups {
        let mut g_idx = g * 3;
        let mut enc = 0u32;
        for _ in 0..3 {
            let b = (if g_idx < bs.len() { bs[g_idx] } else { 0 }) as u32;
            enc >>= 8;
            enc |= b << 16;
            g_idx += 1;
        }
        for _ in 0..4 {
            out.push(char::from_u32(CRYPT_HASH64[(enc & 0x3F) as usize] as u32).unwrap_or('!'));
            enc >>= 6;
        }
    }
    match bs.len() % 3 {
        1 => {
            out.pop();
            out.pop();
        }
        2 => {
            out.pop();
        }
        _ => (),
    }
    out
}

pub fn do_md5_crypt(pass: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut dgst_b = Md5::new();
    dgst_b.update(pass);
    dgst_b.update(salt);
    dgst_b.update(pass);
    let mut hash_b = dgst_b.finalize();

    let mut dgst_a = Md5::new();
    dgst_a.update(pass);
    dgst_a.update(MD5_MAGIC.as_bytes());
    dgst_a.update(salt);

    let mut plen = pass.len();
    while plen > 0 {
        dgst_a.update(&hash_b[..min(plen, 16)]);
        if plen < 16 {
            break;
        }
        plen -= 16;
    }

    plen = pass.len();
    while plen > 0 {
        if plen & 1 == 0 {
            dgst_a.update(&pass[..1])
        } else {
            dgst_a.update([0u8])
        }
        plen >>= 1;
    }

    let mut hash_a = dgst_a.finalize();

    for r in 0..1000 {
        let mut dgst_a = Md5::new();
        if r % 2 == 1 {
            dgst_a.update(pass);
        } else {
            dgst_a.update(hash_a);
        }
        if r % 3 > 0 {
            dgst_a.update(salt);
        }
        if r % 7 > 0 {
            dgst_a.update(pass);
        }
        if r % 2 == 0 {
            dgst_a.update(pass);
        } else {
            dgst_a.update(hash_a);
        }
        hash_a = dgst_a.finalize();
    }

    for (i, &ti) in MD5_TRANSPOSE.iter().enumerate() {
        hash_b[i] = hash_a[ti as usize];
    }

    md5_sha2_hash64_encode(&hash_b).into_bytes()
}

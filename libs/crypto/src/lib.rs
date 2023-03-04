use base64::engine::GeneralPurpose;
use base64::{alphabet, Engine};
use tracing::{debug, error, warn};

use base64::engine::general_purpose;
use base64urlsafedata::Base64UrlSafeData;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

use kanidm_proto::v1::OperationError;
use openssl::hash::{self, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::sha::Sha512;

// NIST 800-63.b salt should be 112 bits -> 14  8u8.
// I choose tinfoil hat though ...
const PBKDF2_SALT_LEN: usize = 24;

const PBKDF2_MIN_NIST_SALT_LEN: usize = 14;

// Min number of rounds for a pbkdf2
pub const PBKDF2_MIN_NIST_COST: usize = 10000;

// 64 * u8 -> 512 bits of out.
const PBKDF2_KEY_LEN: usize = 64;
const PBKDF2_MIN_NIST_KEY_LEN: usize = 32;
const PBKDF2_SHA1_MIN_KEY_LEN: usize = 19;

const DS_SSHA512_SALT_LEN: usize = 8;
const DS_SSHA512_HASH_LEN: usize = 64;

#[derive(Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum DbPasswordV1 {
    PBKDF2(usize, Vec<u8>, Vec<u8>),
    PBKDF2_SHA1(usize, Vec<u8>, Vec<u8>),
    PBKDF2_SHA512(usize, Vec<u8>, Vec<u8>),
    SSHA512(Vec<u8>, Vec<u8>),
    NT_MD4(Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ReplPasswordV1 {
    PBKDF2 {
        cost: usize,
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    PBKDF2_SHA1 {
        cost: usize,
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    PBKDF2_SHA512 {
        cost: usize,
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    SSHA512 {
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    NT_MD4 {
        hash: Base64UrlSafeData,
    },
}

impl fmt::Debug for DbPasswordV1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbPasswordV1::PBKDF2(_, _, _) => write!(f, "PBKDF2"),
            DbPasswordV1::PBKDF2_SHA1(_, _, _) => write!(f, "PBKDF2_SHA1"),
            DbPasswordV1::PBKDF2_SHA512(_, _, _) => write!(f, "PBKDF2_SHA512"),
            DbPasswordV1::SSHA512(_, _) => write!(f, "SSHA512"),
            DbPasswordV1::NT_MD4(_) => write!(f, "NT_MD4"),
        }
    }
}

#[derive(Debug)]
pub struct CryptoPolicy {
    pub(crate) pbkdf2_cost: usize,
}

impl CryptoPolicy {
    pub fn minimum() -> Self {
        CryptoPolicy {
            pbkdf2_cost: PBKDF2_MIN_NIST_COST,
        }
    }

    pub fn time_target(t: Duration) -> Self {
        let r = match Password::bench_pbkdf2(PBKDF2_MIN_NIST_COST * 10) {
            Some(bt) => {
                let ubt = bt.as_nanos() as usize;

                // Get the cost per thousand rounds
                let per_thou = (PBKDF2_MIN_NIST_COST * 10) / 1000;
                let t_per_thou = ubt / per_thou;
                // eprintln!("{} / {}", ubt, per_thou);

                // Now we need the attacker work in nanos
                let attack_time = t.as_nanos() as usize;
                let r = (attack_time / t_per_thou) * 1000;

                // eprintln!("({} / {} ) * 1000", attack_time, t_per_thou);
                // eprintln!("Maybe rounds -> {}", r);

                if r < PBKDF2_MIN_NIST_COST {
                    PBKDF2_MIN_NIST_COST
                } else {
                    r
                }
            }
            None => PBKDF2_MIN_NIST_COST,
        };

        CryptoPolicy { pbkdf2_cost: r }
    }
}

// Why PBKDF2? Rust's bcrypt has a number of hardcodings like max pw len of 72
// I don't really feel like adding in so many restrictions, so I'll use
// pbkdf2 in openssl because it doesn't have the same limits.
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
enum Kdf {
    //     cost, salt,   hash
    PBKDF2(usize, Vec<u8>, Vec<u8>),

    // Imported types, will upgrade to the above.
    //         cost,   salt,    hash
    PBKDF2_SHA1(usize, Vec<u8>, Vec<u8>),
    //           cost,   salt,    hash
    PBKDF2_SHA512(usize, Vec<u8>, Vec<u8>),
    //      salt     hash
    SSHA512(Vec<u8>, Vec<u8>),
    //     hash
    NT_MD4(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Password {
    material: Kdf,
}

impl TryFrom<DbPasswordV1> for Password {
    type Error = ();

    fn try_from(value: DbPasswordV1) -> Result<Self, Self::Error> {
        match value {
            DbPasswordV1::PBKDF2(c, s, h) => Ok(Password {
                material: Kdf::PBKDF2(c, s, h),
            }),
            DbPasswordV1::PBKDF2_SHA1(c, s, h) => Ok(Password {
                material: Kdf::PBKDF2_SHA1(c, s, h),
            }),
            DbPasswordV1::PBKDF2_SHA512(c, s, h) => Ok(Password {
                material: Kdf::PBKDF2_SHA512(c, s, h),
            }),
            DbPasswordV1::SSHA512(s, h) => Ok(Password {
                material: Kdf::SSHA512(s, h),
            }),
            DbPasswordV1::NT_MD4(h) => Ok(Password {
                material: Kdf::NT_MD4(h),
            }),
        }
    }
}

impl TryFrom<&ReplPasswordV1> for Password {
    type Error = ();

    fn try_from(value: &ReplPasswordV1) -> Result<Self, Self::Error> {
        match value {
            ReplPasswordV1::PBKDF2 { cost, salt, hash } => Ok(Password {
                material: Kdf::PBKDF2(*cost, salt.0.clone(), hash.0.clone()),
            }),
            ReplPasswordV1::PBKDF2_SHA1 { cost, salt, hash } => Ok(Password {
                material: Kdf::PBKDF2_SHA1(*cost, salt.0.clone(), hash.0.clone()),
            }),
            ReplPasswordV1::PBKDF2_SHA512 { cost, salt, hash } => Ok(Password {
                material: Kdf::PBKDF2_SHA512(*cost, salt.0.clone(), hash.0.clone()),
            }),
            ReplPasswordV1::SSHA512 { salt, hash } => Ok(Password {
                material: Kdf::SSHA512(salt.0.clone(), hash.0.clone()),
            }),
            ReplPasswordV1::NT_MD4 { hash } => Ok(Password {
                material: Kdf::NT_MD4(hash.0.clone()),
            }),
        }
    }
}

// OpenLDAP based their PBKDF2 implementation on passlib from python, that uses a
// non-standard base64 altchar set and padding that is not supported by
// anything else in the world. To manage this, we only ever encode to base64 with
// no pad but we have to remap ab64 to b64. This function allows b64 standard with
// padding to pass, and remaps ab64 to b64 standard with padding.
macro_rules! ab64_to_b64 {
    ($ab64:expr) => {{
        let mut s = $ab64.replace(".", "+");
        match s.len() & 3 {
            0 => {
                // Do nothing
            }
            1 => {
                // One is invalid, do nothing, we'll error in base64
            }
            2 => s.push_str("=="),
            3 => s.push_str("="),
            _ => unreachable!(),
        }
        s
    }};
}

impl TryFrom<&str> for Password {
    type Error = ();

    // As we may add more algos, we keep the match algo single for later.
    #[allow(clippy::single_match)]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // There is probably a more efficient way to try this given different types?

        // test django - algo$salt$hash
        let django_pbkdf: Vec<&str> = value.split('$').collect();
        if django_pbkdf.len() == 4 {
            let algo = django_pbkdf[0];
            let cost = django_pbkdf[1];
            let salt = django_pbkdf[2];
            let hash = django_pbkdf[3];
            match algo {
                "pbkdf2_sha256" => {
                    let c = cost.parse::<usize>().map_err(|_| ())?;
                    let s: Vec<_> = salt.as_bytes().to_vec();
                    let h = general_purpose::STANDARD.decode(hash).map_err(|_| ())?;
                    if h.len() < PBKDF2_MIN_NIST_KEY_LEN {
                        return Err(());
                    }
                    return Ok(Password {
                        material: Kdf::PBKDF2(c, s, h),
                    });
                }
                _ => {}
            }
        }

        if value.starts_with("ipaNTHash: ") {
            let nt_md4 = match value.split_once(' ') {
                Some((_, v)) => v,
                None => {
                    unreachable!();
                }
            };

            let h = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(nt_md4)
                .map_err(|_| ())?;

            return Ok(Password {
                material: Kdf::NT_MD4(h),
            });
        }

        if value.starts_with("sambaNTPassword: ") {
            let nt_md4 = match value.split_once(' ') {
                Some((_, v)) => v,
                None => {
                    unreachable!();
                }
            };

            let h = hex::decode(nt_md4).map_err(|_| ())?;
            return Ok(Password {
                material: Kdf::NT_MD4(h),
            });
        }

        // Test 389ds formats
        if let Some(ds_ssha512) = value.strip_prefix("{SSHA512}") {
            let sh = general_purpose::STANDARD
                .decode(ds_ssha512)
                .map_err(|_| ())?;
            let (h, s) = sh.split_at(DS_SSHA512_HASH_LEN);
            if s.len() != DS_SSHA512_SALT_LEN {
                return Err(());
            }
            return Ok(Password {
                material: Kdf::SSHA512(s.to_vec(), h.to_vec()),
            });
        }

        // Test for OpenLDAP formats
        if value.starts_with("{PBKDF2}")
            || value.starts_with("{PBKDF2-SHA1}")
            || value.starts_with("{PBKDF2-SHA256}")
            || value.starts_with("{PBKDF2-SHA512}")
        {
            let ol_pbkdf2 = match value.split_once('}') {
                Some((_, v)) => v,
                None => {
                    unreachable!();
                }
            };

            let ol_pbkdf: Vec<&str> = ol_pbkdf2.split('$').collect();
            if ol_pbkdf.len() == 3 {
                let cost = ol_pbkdf[0];
                let salt = ol_pbkdf[1];
                let hash = ol_pbkdf[2];

                let c = cost.parse::<usize>().map_err(|_| ())?;

                let s = ab64_to_b64!(salt);
                let base64_decoder_config = general_purpose::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true);
                let base64_decoder =
                    GeneralPurpose::new(&alphabet::STANDARD, base64_decoder_config);
                let s = base64_decoder.decode(s).map_err(|e| {
                    error!(?e, "Invalid base64 in oldap pbkdf2-sha1");
                })?;

                let h = ab64_to_b64!(hash);
                let h = base64_decoder.decode(h).map_err(|e| {
                    error!(?e, "Invalid base64 in oldap pbkdf2-sha1");
                })?;

                // This is just sha1 in a trenchcoat.
                if value.strip_prefix("{PBKDF2}").is_some()
                    || value.strip_prefix("{PBKDF2-SHA1}").is_some()
                {
                    if h.len() < PBKDF2_SHA1_MIN_KEY_LEN {
                        return Err(());
                    }
                    return Ok(Password {
                        material: Kdf::PBKDF2_SHA1(c, s, h),
                    });
                }

                if value.strip_prefix("{PBKDF2-SHA256}").is_some() {
                    if h.len() < PBKDF2_MIN_NIST_KEY_LEN {
                        return Err(());
                    }
                    return Ok(Password {
                        material: Kdf::PBKDF2(c, s, h),
                    });
                }

                if value.strip_prefix("{PBKDF2-SHA512}").is_some() {
                    if h.len() < PBKDF2_MIN_NIST_KEY_LEN {
                        return Err(());
                    }
                    return Ok(Password {
                        material: Kdf::PBKDF2_SHA512(c, s, h),
                    });
                }

                // Should be no way to get here!
                unreachable!();
            } else {
                warn!("oldap pbkdf2 found but invalid number of elements?");
            }
        }

        // Nothing matched to this point.
        Err(())
    }
}

impl Password {
    fn bench_pbkdf2(pbkdf2_cost: usize) -> Option<Duration> {
        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.gen()).collect();
        let input: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.gen()).collect();
        // This is 512 bits of output
        let mut key: Vec<u8> = (0..PBKDF2_KEY_LEN).map(|_| 0).collect();

        let start = Instant::now();
        pbkdf2_hmac(
            input.as_slice(),
            salt.as_slice(),
            pbkdf2_cost,
            MessageDigest::sha256(),
            key.as_mut_slice(),
        )
        .ok()?;
        let end = Instant::now();

        end.checked_duration_since(start)
    }

    fn new_pbkdf2(pbkdf2_cost: usize, cleartext: &str) -> Result<Kdf, OperationError> {
        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.gen()).collect();
        // This is 512 bits of output
        let mut key: Vec<u8> = (0..PBKDF2_KEY_LEN).map(|_| 0).collect();

        pbkdf2_hmac(
            cleartext.as_bytes(),
            salt.as_slice(),
            pbkdf2_cost,
            MessageDigest::sha256(),
            key.as_mut_slice(),
        )
        .map(|()| {
            // Turn key to a vec.
            Kdf::PBKDF2(pbkdf2_cost, salt, key)
        })
        .map_err(|_| OperationError::CryptographyError)
    }

    pub fn new(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, OperationError> {
        Self::new_pbkdf2(policy.pbkdf2_cost, cleartext).map(|material| Password { material })
    }

    pub fn verify(&self, cleartext: &str) -> Result<bool, OperationError> {
        match &self.material {
            Kdf::PBKDF2(cost, salt, key) => {
                // We have to get the number of bits to derive from our stored hash
                // as some imported hash types may have variable lengths
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_MIN_NIST_KEY_LEN);
                let mut chal_key: Vec<u8> = (0..key_len).map(|_| 0).collect();
                pbkdf2_hmac(
                    cleartext.as_bytes(),
                    salt.as_slice(),
                    *cost,
                    MessageDigest::sha256(),
                    chal_key.as_mut_slice(),
                )
                .map_err(|_| OperationError::CryptographyError)
                .map(|()| {
                    // Actually compare the outputs.
                    &chal_key == key
                })
            }
            Kdf::PBKDF2_SHA1(cost, salt, key) => {
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_SHA1_MIN_KEY_LEN);
                let mut chal_key: Vec<u8> = (0..key_len).map(|_| 0).collect();
                pbkdf2_hmac(
                    cleartext.as_bytes(),
                    salt.as_slice(),
                    *cost,
                    MessageDigest::sha1(),
                    chal_key.as_mut_slice(),
                )
                .map_err(|_| OperationError::CryptographyError)
                .map(|()| {
                    // Actually compare the outputs.
                    &chal_key == key
                })
            }
            Kdf::PBKDF2_SHA512(cost, salt, key) => {
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_MIN_NIST_KEY_LEN);
                let mut chal_key: Vec<u8> = (0..key_len).map(|_| 0).collect();
                pbkdf2_hmac(
                    cleartext.as_bytes(),
                    salt.as_slice(),
                    *cost,
                    MessageDigest::sha512(),
                    chal_key.as_mut_slice(),
                )
                .map_err(|_| OperationError::CryptographyError)
                .map(|()| {
                    // Actually compare the outputs.
                    &chal_key == key
                })
            }
            Kdf::SSHA512(salt, key) => {
                let mut hasher = Sha512::new();
                hasher.update(cleartext.as_bytes());
                hasher.update(salt);
                let r = hasher.finish();
                Ok(key == &(r.to_vec()))
            }
            Kdf::NT_MD4(key) => {
                // We need to get the cleartext to utf16le for reasons.
                let clear_utf16le: Vec<u8> = cleartext
                    .encode_utf16()
                    .map(|c| c.to_le_bytes())
                    .flat_map(|i| i.into_iter())
                    .collect();

                let dgst = MessageDigest::from_nid(Nid::MD4).ok_or_else(|| {
                    error!("Unable to access MD4 - fips mode may be enabled, or you may need to activate the legacy provider.");
                    error!("For more details, see https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers");
                    OperationError::CryptographyError
                })?;

                hash::hash(dgst, &clear_utf16le)
                    .map_err(|e| {
                        debug!(?e);
                        error!("Unable to digest MD4 - fips mode may be enabled, or you may need to activate the legacy provider.");
                        error!("For more details, see https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers");
                        OperationError::CryptographyError
                    })
                    .map(|chal_key| chal_key.as_ref() == key)
            }
        }
    }

    pub fn to_dbpasswordv1(&self) -> DbPasswordV1 {
        match &self.material {
            Kdf::PBKDF2(cost, salt, hash) => {
                DbPasswordV1::PBKDF2(*cost, salt.clone(), hash.clone())
            }
            Kdf::PBKDF2_SHA1(cost, salt, hash) => {
                DbPasswordV1::PBKDF2_SHA1(*cost, salt.clone(), hash.clone())
            }
            Kdf::PBKDF2_SHA512(cost, salt, hash) => {
                DbPasswordV1::PBKDF2_SHA512(*cost, salt.clone(), hash.clone())
            }
            Kdf::SSHA512(salt, hash) => DbPasswordV1::SSHA512(salt.clone(), hash.clone()),
            Kdf::NT_MD4(hash) => DbPasswordV1::NT_MD4(hash.clone()),
        }
    }

    pub fn to_repl_v1(&self) -> ReplPasswordV1 {
        match &self.material {
            Kdf::PBKDF2(cost, salt, hash) => ReplPasswordV1::PBKDF2 {
                cost: *cost,
                salt: salt.clone().into(),
                hash: hash.clone().into(),
            },
            Kdf::PBKDF2_SHA1(cost, salt, hash) => ReplPasswordV1::PBKDF2_SHA1 {
                cost: *cost,
                salt: salt.clone().into(),
                hash: hash.clone().into(),
            },
            Kdf::PBKDF2_SHA512(cost, salt, hash) => ReplPasswordV1::PBKDF2_SHA512 {
                cost: *cost,
                salt: salt.clone().into(),
                hash: hash.clone().into(),
            },
            Kdf::SSHA512(salt, hash) => ReplPasswordV1::SSHA512 {
                salt: salt.clone().into(),
                hash: hash.clone().into(),
            },
            Kdf::NT_MD4(hash) => ReplPasswordV1::NT_MD4 {
                hash: hash.clone().into(),
            },
        }
    }

    pub fn requires_upgrade(&self) -> bool {
        match &self.material {
            Kdf::PBKDF2_SHA512(cost, salt, hash) | Kdf::PBKDF2(cost, salt, hash) => {
                *cost < PBKDF2_MIN_NIST_COST
                    || salt.len() < PBKDF2_MIN_NIST_SALT_LEN
                    || hash.len() < PBKDF2_MIN_NIST_KEY_LEN
            }
            Kdf::PBKDF2_SHA1(_, _, _) | Kdf::SSHA512(_, _) | Kdf::NT_MD4(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::*;

    #[test]
    fn test_credential_simple() {
        let p = CryptoPolicy::minimum();
        let c = Password::new(&p, "password").unwrap();
        assert!(c.verify("password").unwrap());
        assert!(!c.verify("password1").unwrap());
        assert!(!c.verify("Password1").unwrap());
        assert!(!c.verify("It Works!").unwrap());
        assert!(!c.verify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap());
    }

    #[test]
    fn test_password_from_invalid() {
        assert!(Password::try_from("password").is_err())
    }

    #[test]
    fn test_password_from_django_pbkdf2_sha256() {
        let im_pw = "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";
        let password = "eicieY7ahchaoCh0eeTa";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_ds_ssha512() {
        let im_pw = "{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        // Known weak, require upgrade.
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    // Can be generated with:
    // slappasswd -s password -o module-load=/usr/lib64/openldap/pw-argon2.so -h {ARGON2}

    #[test]
    fn test_password_from_openldap_pkbdf2() {
        let im_pw = "{PBKDF2}10000$IlfapjA351LuDSwYC0IQ8Q$saHqQTuYnjJN/tmAndT.8mJt.6w";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha1() {
        let im_pw = "{PBKDF2-SHA1}10000$ZBEH6B07rgQpJSikyvMU2w$TAA03a5IYkz1QlPsbJKvUsTqNV";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha256() {
        let im_pw = "{PBKDF2-SHA256}10000$henZGfPWw79Cs8ORDeVNrQ$1dTJy73v6n3bnTmTZFghxHXHLsAzKaAy8SksDfZBPIw";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(!r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha512() {
        let im_pw = "{PBKDF2-SHA512}10000$Je1Uw19Bfv5lArzZ6V3EPw$g4T/1sqBUYWl9o93MVnyQ/8zKGSkPbKaXXsT8WmysXQJhWy8MRP2JFudSL.N9RklQYgDPxPjnfum/F2f/TrppA";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(!r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    /*
    // Not supported in openssl, may need an external crate.
    #[test]
    fn test_password_from_openldap_argon2() {
        let im_pw = "{ARGON2}$argon2id$v=19$m=65536,t=2,p=1$IyTQMsvzB2JHDiWx8fq7Ew$VhYOA7AL0kbRXI5g2kOyyp8St1epkNj7WZyUY4pAIQQ"
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }
    */

    /*
     * wbrown - 20221104 - I tried to programmatically enable the legacy provider, but
     * it consistently "did nothing at all", meaning we have to rely on users to enable
     * this for this test.
     */

    /*
    #[cfg(openssl3)]
    fn setup_openssl_legacy_provider() -> openssl::lib_ctx::LibCtx {
        let ctx = openssl::lib_ctx::LibCtx::new()
            .expect("Failed to create new library context");

        openssl::provider::Provider::load(Some(&ctx), "legacy")
            .expect("Failed to setup provider.");

        eprintln!("setup legacy provider maybe??");

        ctx
    }
    */

    #[test]
    fn test_password_from_ipa_nt_hash() {
        sketching::test_init();
        // Base64 no pad
        let im_pw = "ipaNTHash: iEb36u6PsRetBr3YMLdYbA";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());

        match r.verify(password) {
            Ok(r) => assert!(r),
            Err(_) => {
                if cfg!(openssl3) {
                    warn!("To run this test, enable the legacy provider.");
                } else {
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_password_from_samba_nt_hash() {
        sketching::test_init();
        // Base64 no pad
        let im_pw = "sambaNTPassword: 8846F7EAEE8FB117AD06BDD830B7586C";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        match r.verify(password) {
            Ok(r) => assert!(r),
            Err(_) => {
                if cfg!(openssl3) {
                    warn!("To run this test, enable the legacy provider.");
                } else {
                    assert!(false);
                }
            }
        }
    }
}

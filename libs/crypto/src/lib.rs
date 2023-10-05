#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::unreachable)]

use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use base64::engine::GeneralPurpose;
use base64::{alphabet, Engine};
use tracing::{debug, error, info, trace, warn};

use base64::engine::general_purpose;
use base64urlsafedata::Base64UrlSafeData;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

use kanidm_proto::v1::OperationError;
use openssl::error::ErrorStack as OpenSSLErrorStack;
use openssl::hash::{self, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::sha::Sha512;

pub mod mtls;
pub mod prelude;
pub mod serialise;

#[cfg(feature = "tpm")]
pub use tss_esapi::{handles::ObjectHandle as TpmHandle, Context as TpmContext, Error as TpmError};
#[cfg(not(feature = "tpm"))]
pub struct TpmContext {}
#[cfg(not(feature = "tpm"))]
pub struct TpmHandle {}

// NIST 800-63.b salt should be 112 bits -> 14  8u8.
const PBKDF2_SALT_LEN: usize = 24;

pub const PBKDF2_MIN_NIST_SALT_LEN: usize = 14;

// Min number of rounds for a pbkdf2
pub const PBKDF2_MIN_NIST_COST: usize = 10000;

// 64 * u8 -> 512 bits of out.
const PBKDF2_KEY_LEN: usize = 64;
const PBKDF2_MIN_NIST_KEY_LEN: usize = 32;
const PBKDF2_SHA1_MIN_KEY_LEN: usize = 19;

const DS_SSHA512_SALT_LEN: usize = 8;
const DS_SSHA512_HASH_LEN: usize = 64;

// Taken from the argon2 library and rfc 9106
const ARGON2_VERSION: u32 = 19;
const ARGON2_SALT_LEN: usize = 16;
const ARGON2_KEY_LEN: usize = 32;
const ARGON2_MIN_RAM_KIB: u32 = 8 * 1024;
const ARGON2_MAX_RAM_KIB: u32 = 32 * 1024;
const ARGON2_MIN_T_COST: u32 = 2;
const ARGON2_MAX_T_COST: u32 = 4;
const ARGON2_MAX_P_COST: u32 = 1;

#[derive(Clone, Debug)]
pub enum CryptoError {
    Tpm2,
    Tpm2PublicBuilder,
    Tpm2FeatureMissing,
    Tpm2InputExceeded,
    Tpm2ContextMissing,
    OpenSSL(u64),
    Md4Disabled,
    Argon2,
    Argon2Version,
    Argon2Parameters,
}

impl From<OpenSSLErrorStack> for CryptoError {
    fn from(ossl_err: OpenSSLErrorStack) -> Self {
        error!(?ossl_err);
        let code = ossl_err.errors().get(0).map(|e| e.code()).unwrap_or(0);
        CryptoError::OpenSSL(code)
    }
}

#[allow(clippy::from_over_into)]
impl Into<OperationError> for CryptoError {
    fn into(self) -> OperationError {
        OperationError::CryptographyError
    }
}

#[cfg(feature = "tpm")]
impl From<TpmError> for CryptoError {
    fn from(_e: TpmError) -> Self {
        CryptoError::Tpm2
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum DbPasswordV1 {
    TPM_ARGON2ID {
        m: u32,
        t: u32,
        p: u32,
        v: u32,
        s: Base64UrlSafeData,
        k: Base64UrlSafeData,
    },
    ARGON2ID {
        m: u32,
        t: u32,
        p: u32,
        v: u32,
        s: Base64UrlSafeData,
        k: Base64UrlSafeData,
    },
    PBKDF2(usize, Vec<u8>, Vec<u8>),
    PBKDF2_SHA1(usize, Vec<u8>, Vec<u8>),
    PBKDF2_SHA512(usize, Vec<u8>, Vec<u8>),
    SSHA512(Vec<u8>, Vec<u8>),
    NT_MD4(Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ReplPasswordV1 {
    TPM_ARGON2ID {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: u32,
        salt: Base64UrlSafeData,
        key: Base64UrlSafeData,
    },
    ARGON2ID {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: u32,
        salt: Base64UrlSafeData,
        key: Base64UrlSafeData,
    },
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
            DbPasswordV1::TPM_ARGON2ID { .. } => write!(f, "TPM_ARGON2ID"),
            DbPasswordV1::ARGON2ID { .. } => write!(f, "ARGON2ID"),
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
    // https://docs.rs/argon2/0.5.0/argon2/struct.Params.html
    // defaults to 19mb memory, 2 iterations and 1 thread, with a 32byte output.
    pub(crate) argon2id_params: Params,
}

impl CryptoPolicy {
    pub fn minimum() -> Self {
        CryptoPolicy {
            pbkdf2_cost: PBKDF2_MIN_NIST_COST,
            argon2id_params: Params::default(),
        }
    }

    pub fn time_target(target_time: Duration) -> Self {
        const PBKDF2_BENCH_FACTOR: usize = 10;

        let pbkdf2_cost = match Password::bench_pbkdf2(PBKDF2_MIN_NIST_COST * PBKDF2_BENCH_FACTOR) {
            Some(bt) => {
                let ubt = bt.as_nanos() as usize;

                // Get the cost per thousand rounds
                let per_thou = (PBKDF2_MIN_NIST_COST * PBKDF2_BENCH_FACTOR) / 1000;
                let t_per_thou = ubt / per_thou;
                trace!("{:010}µs / 1000 rounds", t_per_thou);

                // Now we need the attacker work in nanos
                let target = target_time.as_nanos() as usize;
                let r = (target / t_per_thou) * 1000;

                trace!("{}µs target time", target);
                trace!("Maybe rounds -> {}", r);

                if r < PBKDF2_MIN_NIST_COST {
                    PBKDF2_MIN_NIST_COST
                } else {
                    r
                }
            }
            None => PBKDF2_MIN_NIST_COST,
        };

        // Argon2id has multiple parameters. These all are about *exchanges* that you can
        // request in how the computation is performed.
        //
        // rfc9106 explains that there are two algorithms stacked here. Argon2i has defences
        // against side-channel timing. Argon2d provides defences for time-memory tradeoffs.
        //
        // We can see how this impacts timings from sources like:
        // https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/
        //
        // M =  256 MB, T =    2, d = 8, Time = 0.732 s
        // M =  128 MB, T =    6, d = 8, Time = 0.99 s
        // M =   64 MB, T =   12, d = 8, Time = 0.968 s
        // M =   32 MB, T =   24, d = 8, Time = 0.896 s
        // M =   16 MB, T =   49, d = 8, Time = 0.973 s
        // M =    8 MB, T =   96, d = 8, Time = 0.991 s
        // M =    4 MB, T =  190, d = 8, Time = 0.977 s
        // M =    2 MB, T =  271, d = 8, Time = 0.973 s
        // M =    1 MB, T =  639, d = 8, Time = 0.991 s
        //
        // As we can see, the time taken stays constant, but as ram decreases the amount of
        // CPU work required goes up. In our case, our primary threat is from GPU hashcat
        // cracking. GPU's tend to have many fast cores but very little amounts of fast ram
        // for those cores. So we want to have as much ram as *possible* up to a limit, and
        // then we want to increase iterations.
        //
        // This way a GPU has to expend further GPU time to compensate for the less ram.
        //
        // We also need to balance this against the fact we are a database, and we do have
        // caches. We also don't want to over-use RAM, especially because in the worst case
        // every thread will be operationg in argon2id at the same time. That means
        // thread x ram will be used. If we had 8 threads at 64mb of ram, that would require
        // 512mb of ram alone just for hashing. This becomes worse as core counts scale, with
        // 24 core xeons easily reaching 1.5GB in these cases.
        //
        // To try to balance this we cap max ram at 32MB for now.

        // Default amount of ram we sacrifice per thread is 8MB
        let mut m_cost = ARGON2_MIN_RAM_KIB;
        let mut t_cost = ARGON2_MIN_T_COST;
        let p_cost = ARGON2_MAX_P_COST;

        // Raise memory usage until an acceptable ram amount is reached.
        loop {
            let params = if let Ok(p) = Params::new(m_cost, t_cost, p_cost, None) {
                p
            } else {
                // Unable to proceed.
                error!(
                    ?m_cost,
                    ?t_cost,
                    ?p_cost,
                    "Parameters were not valid for argon2"
                );
                break;
            };

            if let Some(ubt) = Password::bench_argon2id(params) {
                trace!("{}µs - t_cost {} m_cost {}", ubt.as_nanos(), t_cost, m_cost);
                // Parameter adjustment
                if ubt < target_time {
                    if m_cost < ARGON2_MAX_RAM_KIB {
                        // Help narrow in quicker.
                        let m_adjust = if target_time
                            .as_nanos()
                            .checked_div(ubt.as_nanos())
                            .unwrap_or(1)
                            >= 2
                        {
                            // Very far from target, double m_cost.
                            m_cost * 2
                        } else {
                            // Close! Increase in a small step
                            m_cost + (2 * 1024)
                        };

                        m_cost = if m_adjust > ARGON2_MAX_RAM_KIB {
                            ARGON2_MAX_RAM_KIB
                        } else {
                            m_adjust
                        };
                        continue;
                    } else if t_cost < ARGON2_MAX_T_COST {
                        // t=2 with m = 32MB is about the same as t=3 m=20MB, so we want to start with ram
                        // higher on these iterations. About 12MB appears to be one iteration. We use 8MB
                        // here though, just to give a little window under that for adjustment.
                        //
                        // Similar, once we hit t=4 we just need to have max ram.
                        let m_adjust = (t_cost.saturating_sub(ARGON2_MIN_T_COST)
                            * ARGON2_MIN_RAM_KIB)
                            + ARGON2_MAX_RAM_KIB;
                        m_cost = if m_adjust > ARGON2_MAX_RAM_KIB {
                            ARGON2_MAX_RAM_KIB
                        } else {
                            m_adjust
                        };
                        t_cost += 1;
                        continue;
                    } else {
                        // Unable to proceed, parameters are maxed out.
                        warn!("Argon2 parameters have hit their maximums - this may be a bug!");
                        break;
                    }
                } else {
                    // Found the target time.
                    break;
                }
            } else {
                error!("Unable to perform bench of argon2id, stopping benchmark");
                break;
            }
        }

        let argon2id_params = Params::new(m_cost, t_cost, p_cost, None)
            // fallback
            .unwrap_or_default();

        let p = CryptoPolicy {
            pbkdf2_cost,
            argon2id_params,
        };
        info!(pbkdf2_cost = %p.pbkdf2_cost, argon2id_m = %p.argon2id_params.m_cost(), argon2id_p = %p.argon2id_params.p_cost(), argon2id_t = %p.argon2id_params.t_cost(), );
        p
    }
}

// Why PBKDF2? Rust's bcrypt has a number of hardcodings like max pw len of 72
// I don't really feel like adding in so many restrictions, so I'll use
// pbkdf2 in openssl because it doesn't have the same limits.
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
enum Kdf {
    TPM_ARGON2ID {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: u32,
        salt: Vec<u8>,
        key: Vec<u8>,
    },
    //
    ARGON2ID {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: u32,
        salt: Vec<u8>,
        key: Vec<u8>,
    },
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
            DbPasswordV1::TPM_ARGON2ID { m, t, p, v, s, k } => Ok(Password {
                material: Kdf::TPM_ARGON2ID {
                    m_cost: m,
                    t_cost: t,
                    p_cost: p,
                    version: v,
                    salt: s.into(),
                    key: k.into(),
                },
            }),
            DbPasswordV1::ARGON2ID { m, t, p, v, s, k } => Ok(Password {
                material: Kdf::ARGON2ID {
                    m_cost: m,
                    t_cost: t,
                    p_cost: p,
                    version: v,
                    salt: s.into(),
                    key: k.into(),
                },
            }),
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
            ReplPasswordV1::TPM_ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => Ok(Password {
                material: Kdf::TPM_ARGON2ID {
                    m_cost: *m_cost,
                    t_cost: *t_cost,
                    p_cost: *p_cost,
                    version: *version,
                    salt: salt.0.clone(),
                    key: key.0.clone(),
                },
            }),
            ReplPasswordV1::ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => Ok(Password {
                material: Kdf::ARGON2ID {
                    m_cost: *m_cost,
                    t_cost: *t_cost,
                    p_cost: *p_cost,
                    version: *version,
                    salt: salt.0.clone(),
                    key: key.0.clone(),
                },
            }),
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

        if let Some(argon2_phc) = value.strip_prefix("{ARGON2}") {
            match PasswordHash::try_from(argon2_phc) {
                Ok(PasswordHash {
                    algorithm,
                    version,
                    params,
                    salt,
                    hash,
                }) => {
                    if algorithm.as_str() != "argon2id" {
                        error!(alg = %algorithm.as_str(), "Only argon2id is supported");
                        return Err(());
                    }

                    let version = version.unwrap_or(ARGON2_VERSION);
                    let version: Version = version.try_into().map_err(|_| {
                        error!("Failed to convert {} to valid argon2id version", version);
                    })?;

                    let m_cost = params.get_decimal("m").ok_or_else(|| {
                        error!("Failed to access m_cost parameter");
                    })?;

                    let t_cost = params.get_decimal("t").ok_or_else(|| {
                        error!("Failed to access t_cost parameter");
                    })?;

                    let p_cost = params.get_decimal("p").ok_or_else(|| {
                        error!("Failed to access p_cost parameter");
                    })?;

                    let salt = salt
                        .and_then(|s| {
                            let mut salt_arr = [0u8; 64];
                            s.decode_b64(&mut salt_arr)
                                .ok()
                                .map(|salt_bytes| salt_bytes.to_owned())
                        })
                        .ok_or_else(|| {
                            error!("Failed to access salt");
                        })?;

                    error!(?salt);

                    let key = hash.map(|h| h.as_bytes().into()).ok_or_else(|| {
                        error!("Failed to access key");
                    })?;

                    return Ok(Password {
                        material: Kdf::ARGON2ID {
                            m_cost,
                            t_cost,
                            p_cost,
                            version: version as u32,
                            salt,
                            key,
                        },
                    });
                }
                Err(e) => {
                    error!(?e, "Invalid argon2 phc string");
                    return Err(());
                }
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

    fn bench_argon2id(params: Params) -> Option<Duration> {
        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.gen()).collect();
        let input: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.gen()).collect();
        // This is 512 bits of output
        let mut key: Vec<u8> = (0..PBKDF2_KEY_LEN).map(|_| 0).collect();

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let start = Instant::now();
        argon
            .hash_password_into(input.as_slice(), salt.as_slice(), key.as_mut_slice())
            .ok()?;
        let end = Instant::now();

        end.checked_duration_since(start)
    }

    pub fn new_pbkdf2(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, CryptoError> {
        let pbkdf2_cost = policy.pbkdf2_cost;
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
        .map(|material| Password { material })
        .map_err(|e| e.into())
    }

    pub fn new_argon2id(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, CryptoError> {
        let version = Version::V0x13;

        let argon = Argon2::new(Algorithm::Argon2id, version, policy.argon2id_params.clone());

        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..ARGON2_SALT_LEN).map(|_| rng.gen()).collect();
        let mut key: Vec<u8> = (0..ARGON2_KEY_LEN).map(|_| 0).collect();

        argon
            .hash_password_into(cleartext.as_bytes(), salt.as_slice(), key.as_mut_slice())
            .map(|()| Kdf::ARGON2ID {
                m_cost: policy.argon2id_params.m_cost(),
                t_cost: policy.argon2id_params.t_cost(),
                p_cost: policy.argon2id_params.p_cost(),
                version: version as u32,
                salt,
                key,
            })
            .map_err(|_| CryptoError::Argon2)
            .map(|material| Password { material })
    }

    pub fn new_argon2id_tpm(
        policy: &CryptoPolicy,
        cleartext: &str,
        tpm_ctx: &mut TpmContext,
        tpm_key_handle: TpmHandle,
    ) -> Result<Self, CryptoError> {
        let version = Version::V0x13;

        let argon = Argon2::new(Algorithm::Argon2id, version, policy.argon2id_params.clone());

        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..ARGON2_SALT_LEN).map(|_| rng.gen()).collect();
        let mut check_key: Vec<u8> = (0..ARGON2_KEY_LEN).map(|_| 0).collect();

        argon
            .hash_password_into(
                cleartext.as_bytes(),
                salt.as_slice(),
                check_key.as_mut_slice(),
            )
            .map_err(|_| CryptoError::Argon2)
            .and_then(|()| do_tpm_hmac(check_key, tpm_ctx, tpm_key_handle))
            .map(|key| Kdf::TPM_ARGON2ID {
                m_cost: policy.argon2id_params.m_cost(),
                t_cost: policy.argon2id_params.t_cost(),
                p_cost: policy.argon2id_params.p_cost(),
                version: version as u32,
                salt,
                key,
            })
            .map(|material| Password { material })
    }

    #[inline]
    pub fn new(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, CryptoError> {
        Self::new_argon2id(policy, cleartext)
    }

    pub fn verify(&self, cleartext: &str) -> Result<bool, CryptoError> {
        self.verify_ctx(cleartext, None)
    }

    pub fn verify_ctx(
        &self,
        cleartext: &str,
        tpm: Option<(&mut TpmContext, TpmHandle)>,
    ) -> Result<bool, CryptoError> {
        match (&self.material, tpm) {
            (
                Kdf::TPM_ARGON2ID {
                    m_cost,
                    t_cost,
                    p_cost,
                    version,
                    salt,
                    key,
                },
                Some((tpm_ctx, tpm_key_handle)),
            ) => {
                let version: Version = (*version).try_into().map_err(|_| {
                    error!("Failed to convert {} to valid argon2id version", version);
                    CryptoError::Argon2Version
                })?;

                let key_len = key.len();

                let params =
                    Params::new(*m_cost, *t_cost, *p_cost, Some(key_len)).map_err(|e| {
                        error!(err = ?e, "invalid argon2id parameters");
                        CryptoError::Argon2Parameters
                    })?;

                let argon = Argon2::new(Algorithm::Argon2id, version, params);
                let mut check_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                argon
                    .hash_password_into(
                        cleartext.as_bytes(),
                        salt.as_slice(),
                        check_key.as_mut_slice(),
                    )
                    .map_err(|e| {
                        error!(err = ?e, "unable to perform argon2id hash");
                        CryptoError::Argon2
                    })
                    .and_then(|()| do_tpm_hmac(check_key, tpm_ctx, tpm_key_handle))
                    .map(|hmac_key| {
                        // Actually compare the outputs.
                        &hmac_key == key
                    })
            }
            (Kdf::TPM_ARGON2ID { .. }, None) => {
                error!("Unable to validate password - not tpm context available");
                Err(CryptoError::Tpm2ContextMissing)
            }
            (
                Kdf::ARGON2ID {
                    m_cost,
                    t_cost,
                    p_cost,
                    version,
                    salt,
                    key,
                },
                _,
            ) => {
                let version: Version = (*version).try_into().map_err(|_| {
                    error!("Failed to convert {} to valid argon2id version", version);
                    CryptoError::Argon2Version
                })?;

                let key_len = key.len();

                let params =
                    Params::new(*m_cost, *t_cost, *p_cost, Some(key_len)).map_err(|e| {
                        error!(err = ?e, "invalid argon2id parameters");
                        CryptoError::Argon2Parameters
                    })?;

                let argon = Argon2::new(Algorithm::Argon2id, version, params);
                let mut check_key: Vec<u8> = (0..key_len).map(|_| 0).collect();

                argon
                    .hash_password_into(
                        cleartext.as_bytes(),
                        salt.as_slice(),
                        check_key.as_mut_slice(),
                    )
                    .map_err(|e| {
                        error!(err = ?e, "unable to perform argon2id hash");
                        CryptoError::Argon2
                    })
                    .map(|()| {
                        // Actually compare the outputs.
                        &check_key == key
                    })
            }
            (Kdf::PBKDF2(cost, salt, key), _) => {
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
                .map(|()| {
                    // Actually compare the outputs.
                    &chal_key == key
                })
                .map_err(|e| e.into())
            }
            (Kdf::PBKDF2_SHA1(cost, salt, key), _) => {
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
                .map(|()| {
                    // Actually compare the outputs.
                    &chal_key == key
                })
                .map_err(|e| e.into())
            }
            (Kdf::PBKDF2_SHA512(cost, salt, key), _) => {
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
                .map(|()| {
                    // Actually compare the outputs.
                    &chal_key == key
                })
                .map_err(|e| e.into())
            }
            (Kdf::SSHA512(salt, key), _) => {
                let mut hasher = Sha512::new();
                hasher.update(cleartext.as_bytes());
                hasher.update(salt);
                let r = hasher.finish();
                Ok(key == &(r.to_vec()))
            }
            (Kdf::NT_MD4(key), _) => {
                // We need to get the cleartext to utf16le for reasons.
                let clear_utf16le: Vec<u8> = cleartext
                    .encode_utf16()
                    .map(|c| c.to_le_bytes())
                    .flat_map(|i| i.into_iter())
                    .collect();

                let dgst = MessageDigest::from_nid(Nid::MD4).ok_or_else(|| {
                    error!("Unable to access MD4 - fips mode may be enabled, or you may need to activate the legacy provider.");
                    error!("For more details, see https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers");
                    CryptoError::Md4Disabled
                })?;

                hash::hash(dgst, &clear_utf16le)
                    .map_err(|e| {
                        debug!(?e);
                        error!("Unable to digest MD4 - fips mode may be enabled, or you may need to activate the legacy provider.");
                        error!("For more details, see https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers");
                        CryptoError::Md4Disabled
                    })
                    .map(|chal_key| chal_key.as_ref() == key)
            }
        }
    }

    pub fn to_dbpasswordv1(&self) -> DbPasswordV1 {
        match &self.material {
            Kdf::TPM_ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => DbPasswordV1::TPM_ARGON2ID {
                m: *m_cost,
                t: *t_cost,
                p: *p_cost,
                v: *version,
                s: salt.clone().into(),
                k: key.clone().into(),
            },
            Kdf::ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => DbPasswordV1::ARGON2ID {
                m: *m_cost,
                t: *t_cost,
                p: *p_cost,
                v: *version,
                s: salt.clone().into(),
                k: key.clone().into(),
            },
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
            Kdf::TPM_ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => ReplPasswordV1::TPM_ARGON2ID {
                m_cost: *m_cost,
                t_cost: *t_cost,
                p_cost: *p_cost,
                version: *version,
                salt: salt.clone().into(),
                key: key.clone().into(),
            },
            Kdf::ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => ReplPasswordV1::ARGON2ID {
                m_cost: *m_cost,
                t_cost: *t_cost,
                p_cost: *p_cost,
                version: *version,
                salt: salt.clone().into(),
                key: key.clone().into(),
            },
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
            Kdf::ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => {
                *version < ARGON2_VERSION ||
                salt.len() < ARGON2_SALT_LEN ||
                key.len() < ARGON2_KEY_LEN ||
                // Can't multi-thread
                *p_cost > ARGON2_MAX_P_COST ||
                // Likely too long on cpu time.
                *t_cost > ARGON2_MAX_T_COST ||
                // Too much ram
                *m_cost > ARGON2_MAX_RAM_KIB
            }
            // Only used in unixd today
            Kdf::TPM_ARGON2ID { .. } => false,
            // All now upgraded to argon2id
            Kdf::PBKDF2(_, _, _)
            | Kdf::PBKDF2_SHA512(_, _, _)
            | Kdf::PBKDF2_SHA1(_, _, _)
            | Kdf::SSHA512(_, _)
            | Kdf::NT_MD4(_) => true,
        }
    }
}

#[cfg(feature = "tpm")]
fn do_tpm_hmac(
    data: Vec<u8>,
    ctx: &mut TpmContext,
    key_handle: TpmHandle,
) -> Result<Vec<u8>, CryptoError> {
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::structures::MaxBuffer;

    let data: MaxBuffer = data.try_into().map_err(|_| {
        error!("input data exceeds maximum tpm input buffer");
        CryptoError::Tpm2InputExceeded
    })?;

    ctx.hmac(key_handle, data.into(), HashingAlgorithm::Sha256)
        .map(|dgst| dgst.to_vec())
        .map_err(|e| {
            error!(tpm_err = ?e, "unable to proceed, tpm error");
            CryptoError::Tpm2
        })
}

#[cfg(not(feature = "tpm"))]
#[allow(clippy::needless_pass_by_value)]
fn do_tpm_hmac(
    _data: Vec<u8>,
    _ctx: &mut TpmContext,
    _key_handle: TpmHandle,
) -> Result<Vec<u8>, CryptoError> {
    error!("Unable to perform hmac - tpm feature not compiled");
    Err(CryptoError::Tpm2FeatureMissing)
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
    fn test_password_pbkdf2() {
        let p = CryptoPolicy::minimum();
        let c = Password::new_pbkdf2(&p, "password").unwrap();
        assert!(c.verify("password").unwrap());
        assert!(!c.verify("password1").unwrap());
        assert!(!c.verify("Password1").unwrap());
    }

    #[test]
    fn test_password_argon2id() {
        let p = CryptoPolicy::minimum();
        let c = Password::new_argon2id(&p, "password").unwrap();
        assert!(c.verify("password").unwrap());
        assert!(!c.verify("password1").unwrap());
        assert!(!c.verify("Password1").unwrap());
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
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    #[test]
    fn test_password_from_openldap_pkbdf2_sha512() {
        let im_pw = "{PBKDF2-SHA512}10000$Je1Uw19Bfv5lArzZ6V3EPw$g4T/1sqBUYWl9o93MVnyQ/8zKGSkPbKaXXsT8WmysXQJhWy8MRP2JFudSL.N9RklQYgDPxPjnfum/F2f/TrppA";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

    // Not supported in openssl, may need an external crate.
    #[test]
    fn test_password_from_openldap_argon2() {
        sketching::test_init();
        let im_pw = "{ARGON2}$argon2id$v=19$m=65536,t=2,p=1$IyTQMsvzB2JHDiWx8fq7Ew$VhYOA7AL0kbRXI5g2kOyyp8St1epkNj7WZyUY4pAIQQ";
        let password = "password";
        let r = Password::try_from(im_pw).expect("Failed to parse");
        assert!(r.requires_upgrade());
        assert!(r.verify(password).unwrap_or(false));
    }

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

    #[cfg(feature = "tpm")]
    #[test]
    fn test_password_argon2id_tpm_bind() {
        use std::str::FromStr;

        sketching::test_init();

        use tss_esapi::{Context, TctiNameConf};

        let mut context =
            Context::new(TctiNameConf::from_str("device:/dev/tpmrm0").expect("Failed to get TCTI"))
                .expect("Failed to create Context");

        let key = context
            .execute_with_nullauth_session(|ctx| prepare_tpm_key(ctx))
            .unwrap();

        let p = CryptoPolicy::minimum();
        let c = context
            .execute_with_nullauth_session(|ctx| {
                Password::new_argon2id_tpm(&p, "password", ctx, key)
            })
            .unwrap();

        assert!(matches!(
            c.verify("password"),
            Err(CryptoError::Tpm2ContextMissing)
        ));

        // Assert it fails without the hmac
        let dup = match &c.material {
            Kdf::TPM_ARGON2ID {
                m_cost,
                t_cost,
                p_cost,
                version,
                salt,
                key,
            } => Password {
                material: Kdf::ARGON2ID {
                    m_cost: *m_cost,
                    t_cost: *t_cost,
                    p_cost: *p_cost,
                    version: *version,
                    salt: salt.clone(),
                    key: key.clone(),
                },
            },
            _ => unreachable!(),
        };

        assert!(!dup.verify("password").unwrap());

        context
            .execute_with_nullauth_session(|ctx| {
                assert!(c.verify_ctx("password", Some((ctx, key))).unwrap());
                assert!(!c.verify_ctx("password1", Some((ctx, key))).unwrap());
                assert!(!c.verify_ctx("Password1", Some((ctx, key))).unwrap());

                ctx.flush_context(key).expect("Failed to unload hmac key");

                // Should fail, no key!
                assert!(matches!(
                    c.verify_ctx("password", Some((ctx, key))),
                    Err(CryptoError::Tpm2)
                ));

                Ok::<(), CryptoError>(())
            })
            .unwrap();
    }

    #[cfg(feature = "tpm")]
    pub fn prepare_tpm_key(tpm_ctx: &mut TpmContext) -> Result<TpmHandle, CryptoError> {
        use tss_esapi::{
            attributes::ObjectAttributesBuilder,
            interface_types::{
                algorithm::{HashingAlgorithm, PublicAlgorithm},
                resource_handles::Hierarchy,
            },
            structures::{Digest, KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters},
        };

        // We generate a digest, which is really some unique small amount of data that
        // we save into the key context that we are going to save/load. This allows us
        // to have unique hmac keys compared to other users of the same tpm.

        let digest = tpm_ctx
            .get_random(16)
            .map_err(|e| {
                error!(tpm_err = ?e, "unable to proceed, tpm error");
                CryptoError::Tpm2
            })
            .and_then(|rand| {
                Digest::try_from(rand).map_err(|e| {
                    error!(tpm_err = ?e, "unable to proceed, tpm error");
                    CryptoError::Tpm2
                })
            })?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| {
                error!(tpm_err = ?e, "unable to proceed, tpm error");
                CryptoError::Tpm2
            })?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(digest)
            .build()
            .map_err(|e| {
                error!(tpm_err = ?e, "unable to proceed, tpm error");
                CryptoError::Tpm2
            })?;

        tpm_ctx
            .create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
            .map(|key| key.key_handle.into())
            .map_err(|e| {
                error!(tpm_err = ?e, "unable to proceed, tpm error");
                CryptoError::Tpm2
            })
    }
}

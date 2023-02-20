use std::convert::TryFrom;
use std::time::{Duration, Instant};

use hashbrown::{HashMap as Map, HashSet};
use kanidm_proto::v1::{BackupCodesView, CredentialDetail, CredentialDetailType, OperationError};
use openssl::hash::{self, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::sha::Sha512;
use rand::prelude::*;
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey, SecurityKey};
use webauthn_rs_core::proto::{Credential as WebauthnCredential, CredentialV3};

use crate::be::dbvalue::{DbBackupCodeV1, DbCred, DbPasswordV1};
use crate::repl::proto::{
    ReplBackupCodeV1, ReplCredV1, ReplPasskeyV4V1, ReplPasswordV1, ReplSecurityKeyV4V1,
};

pub mod policy;
pub mod softlock;
pub mod totp;

use self::totp::TOTP_DEFAULT_STEP;

use crate::credential::policy::CryptoPolicy;
use crate::credential::softlock::CredSoftLockPolicy;
use crate::credential::totp::Totp;

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

// These are in order of "relative" strength.
/*
#[derive(Clone, Debug)]
pub enum Policy {
    PasswordOnly,
    WebauthnOnly,
    GeneratedPassword,
    PasswordAndWebauthn,
}
*/

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
                    let h = base64::decode(hash).map_err(|_| ())?;
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

            let h = base64::decode_config(nt_md4, base64::STANDARD_NO_PAD).map_err(|_| ())?;
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
            let sh = base64::decode(ds_ssha512).map_err(|_| ())?;
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
                let s = base64::decode_config(s, base64::STANDARD.decode_allow_trailing_bits(true))
                    .map_err(|e| {
                        error!(?e, "Invalid base64 in oldap pbkdf2-sha1");
                    })?;

                let h = ab64_to_b64!(hash);
                let h = base64::decode_config(h, base64::STANDARD.decode_allow_trailing_bits(true))
                    .map_err(|e| {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupCodes {
    code_set: HashSet<String>,
}

impl TryFrom<DbBackupCodeV1> for BackupCodes {
    type Error = ();

    fn try_from(value: DbBackupCodeV1) -> Result<Self, Self::Error> {
        Ok(BackupCodes {
            code_set: value.code_set,
        })
    }
}

impl TryFrom<&ReplBackupCodeV1> for BackupCodes {
    type Error = ();

    fn try_from(value: &ReplBackupCodeV1) -> Result<Self, Self::Error> {
        Ok(BackupCodes {
            code_set: value.codes.iter().cloned().collect(),
        })
    }
}

impl BackupCodes {
    pub fn new(code_set: HashSet<String>) -> Self {
        BackupCodes { code_set }
    }

    pub fn verify(&self, code_chal: &str) -> bool {
        self.code_set.contains(code_chal)
    }

    pub fn remove(&mut self, code_chal: &str) -> bool {
        self.code_set.remove(code_chal)
    }

    pub fn to_dbbackupcodev1(&self) -> DbBackupCodeV1 {
        DbBackupCodeV1 {
            code_set: self.code_set.clone(),
        }
    }

    pub fn to_repl_v1(&self) -> ReplBackupCodeV1 {
        ReplBackupCodeV1 {
            codes: self.code_set.iter().cloned().collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
/// This is how we store credentials in the server. An account can have many credentials, and
/// a credential can have many factors. Only successful auth to a credential as a whole unit
/// will succeed. For example:
/// A: Credential { password: aaa }
/// B: Credential { password: bbb, otp: ... }
/// In this case, if we selected credential B, and then provided password "aaa" we would deny
/// the auth as the password of B was incorrect. Additionally, while A only needs the "password",
/// B requires both the password and otp to be valid.
///
/// In this way, each Credential provides it's own password requirements and policy, and requires
/// some metadata to support this such as it's source and strength etc.
pub struct Credential {
    // policy: Policy,
    pub(crate) type_: CredentialType,
    // Uuid of Credential, used by auth session to lock this specific credential
    // if required.
    pub(crate) uuid: Uuid,
    // TODO #59: Add auth policy IE validUntil, lock state ...
    // locked: bool
}

#[derive(Clone, Debug, PartialEq)]
/// The type of credential that is stored. Each of these represents a full set of 'what is required'
/// to complete an authentication session. The reason to have these typed like this is so we can
/// apply policy later to what classes or levels of credentials can be used. We use these types
/// to also know what type of auth session handler to initiate.
pub enum CredentialType {
    // Anonymous,
    Password(Password),
    GeneratedPassword(Password),
    PasswordMfa(
        Password,
        Map<String, Totp>,
        Map<String, SecurityKey>,
        Option<BackupCodes>,
    ),
    Webauthn(Map<String, Passkey>),
}

impl From<&Credential> for CredentialDetail {
    fn from(value: &Credential) -> Self {
        CredentialDetail {
            uuid: value.uuid,
            type_: match &value.type_ {
                CredentialType::Password(_) => CredentialDetailType::Password,
                CredentialType::GeneratedPassword(_) => CredentialDetailType::GeneratedPassword,
                CredentialType::Webauthn(wan) => {
                    let labels: Vec<_> = wan.keys().cloned().collect();
                    CredentialDetailType::Passkey(labels)
                }
                CredentialType::PasswordMfa(_, totp, wan, backup_code) => {
                    // Don't sort - we need these in order to match to what the user
                    // sees so they can remove by index.
                    let wan_labels: Vec<_> = wan.keys().cloned().collect();
                    let totp_labels: Vec<_> = totp.keys().cloned().collect();

                    CredentialDetailType::PasswordMfa(
                        totp_labels,
                        wan_labels,
                        backup_code.as_ref().map(|c| c.code_set.len()).unwrap_or(0),
                    )
                }
            },
        }
    }
}

impl TryFrom<DbCred> for Credential {
    type Error = ();

    fn try_from(value: DbCred) -> Result<Self, Self::Error> {
        // Work out what the policy is?
        match value {
            DbCred::V2Password {
                password: db_password,
                uuid,
            }
            | DbCred::Pw {
                password: Some(db_password),
                webauthn: _,
                totp: _,
                backup_code: _,
                claims: _,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;
                let type_ = CredentialType::Password(v_password);
                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            DbCred::V2GenPassword {
                password: db_password,
                uuid,
            }
            | DbCred::GPw {
                password: Some(db_password),
                webauthn: _,
                totp: _,
                backup_code: _,
                claims: _,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;
                let type_ = CredentialType::GeneratedPassword(v_password);
                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            DbCred::PwMfa {
                password: Some(db_password),
                webauthn: maybe_db_webauthn,
                totp,
                backup_code,
                claims: _,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;

                let v_totp = match totp {
                    Some(dbt) => {
                        let l = "totp".to_string();
                        let t = Totp::try_from(dbt)?;
                        Map::from([(l, t)])
                    }
                    None => Map::default(),
                };

                let v_webauthn = match maybe_db_webauthn {
                    Some(db_webauthn) => db_webauthn
                        .into_iter()
                        .map(|wc| {
                            (
                                wc.label,
                                SecurityKey::from(WebauthnCredential::from(CredentialV3 {
                                    cred_id: wc.id,
                                    cred: wc.cred,
                                    counter: wc.counter,
                                    verified: wc.verified,
                                    registration_policy: wc.registration_policy,
                                })),
                            )
                        })
                        .collect(),
                    None => Default::default(),
                };

                let v_backup_code = match backup_code {
                    Some(dbb) => Some(BackupCodes::try_from(dbb)?),
                    None => None,
                };

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            DbCred::Wn {
                password: _,
                webauthn: Some(db_webauthn),
                totp: _,
                backup_code: _,
                claims: _,
                uuid,
            } => {
                let v_webauthn = db_webauthn
                    .into_iter()
                    .map(|wc| {
                        (
                            wc.label,
                            Passkey::from(WebauthnCredential::from(CredentialV3 {
                                cred_id: wc.id,
                                cred: wc.cred,
                                counter: wc.counter,
                                verified: wc.verified,
                                registration_policy: wc.registration_policy,
                            })),
                        )
                    })
                    .collect();

                let type_ = CredentialType::Webauthn(v_webauthn);

                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            DbCred::TmpWn {
                webauthn: db_webauthn,
                uuid,
            } => {
                let v_webauthn = db_webauthn.into_iter().collect();
                let type_ = CredentialType::Webauthn(v_webauthn);

                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            DbCred::V2PasswordMfa {
                password: db_password,
                totp: maybe_db_totp,
                backup_code,
                webauthn: db_webauthn,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;

                let v_totp = match maybe_db_totp {
                    Some(dbt) => {
                        let l = "totp".to_string();
                        let t = Totp::try_from(dbt)?;
                        Map::from([(l, t)])
                    }
                    None => Map::default(),
                };

                let v_backup_code = match backup_code {
                    Some(dbb) => Some(BackupCodes::try_from(dbb)?),
                    None => None,
                };

                let v_webauthn = db_webauthn.into_iter().collect();

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            DbCred::V3PasswordMfa {
                password: db_password,
                totp: db_totp,
                backup_code,
                webauthn: db_webauthn,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;

                let v_totp = db_totp
                    .into_iter()
                    .map(|(l, dbt)| Totp::try_from(dbt).map(|t| (l, t)))
                    .collect::<Result<Map<_, _>, _>>()?;

                let v_backup_code = match backup_code {
                    Some(dbb) => Some(BackupCodes::try_from(dbb)?),
                    None => None,
                };

                let v_webauthn = db_webauthn.into_iter().collect();

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok(Credential { type_, uuid })
                } else {
                    Err(())
                }
            }
            credential => {
                error!("Database content may be corrupt - invalid credential state");
                debug!(%credential);
                debug!(?credential);
                Err(())
            }
        }
    }
}

impl Credential {
    pub fn try_from_repl_v1(rc: &ReplCredV1) -> Result<(String, Self), ()> {
        match rc {
            ReplCredV1::TmpWn { tag, set } => {
                let m_uuid: Option<Uuid> = set.get(0).map(|v| v.uuid);

                let v_webauthn = set
                    .iter()
                    .map(|passkey| (passkey.tag.clone(), passkey.key.clone()))
                    .collect();
                let type_ = CredentialType::Webauthn(v_webauthn);

                match (m_uuid, type_.is_valid()) {
                    (Some(uuid), true) => Ok((tag.clone(), Credential { type_, uuid })),
                    _ => Err(()),
                }
            }
            ReplCredV1::Password {
                tag,
                password,
                uuid,
            } => {
                let v_password = Password::try_from(password)?;
                let type_ = CredentialType::Password(v_password);
                if type_.is_valid() {
                    Ok((tag.clone(), Credential { type_, uuid: *uuid }))
                } else {
                    Err(())
                }
            }
            ReplCredV1::GenPassword {
                tag,
                password,
                uuid,
            } => {
                let v_password = Password::try_from(password)?;
                let type_ = CredentialType::GeneratedPassword(v_password);
                if type_.is_valid() {
                    Ok((tag.clone(), Credential { type_, uuid: *uuid }))
                } else {
                    Err(())
                }
            }
            ReplCredV1::PasswordMfa {
                tag,
                password,
                totp,
                backup_code,
                webauthn,
                uuid,
            } => {
                let v_password = Password::try_from(password)?;

                let v_totp = totp
                    .iter()
                    .map(|(l, dbt)| Totp::try_from(dbt).map(|t| (l.clone(), t)))
                    .collect::<Result<Map<_, _>, _>>()?;

                let v_backup_code = match backup_code {
                    Some(rbc) => Some(BackupCodes::try_from(rbc)?),
                    None => None,
                };

                let v_webauthn = webauthn
                    .iter()
                    .map(|sk| (sk.tag.clone(), sk.key.clone()))
                    .collect();

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok((tag.clone(), Credential { type_, uuid: *uuid }))
                } else {
                    Err(())
                }
            }
        }
    }

    /// Create a new credential that contains a CredentialType::Password
    pub fn new_password_only(
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext).map(Self::new_from_password)
    }

    /// Create a new credential that contains a CredentialType::GeneratedPassword
    pub fn new_generatedpassword_only(
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext).map(Self::new_from_generatedpassword)
    }

    /// Update the state of the Password on this credential, if a password is present. If possible
    /// this will convert the credential to a PasswordMFA in some cases, or fail in others.
    pub fn set_password(
        &self,
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext).map(|pw| self.update_password(pw))
    }

    /// Extend this credential with another alternate webauthn credential. This is especially
    /// useful for `PasswordMfa` where you can have many webauthn credentials and a password
    /// generally so that one is a backup.
    pub fn append_securitykey(
        &self,
        label: String,
        cred: SecurityKey,
    ) -> Result<Self, OperationError> {
        let type_ = match &self.type_ {
            CredentialType::Password(pw) | CredentialType::GeneratedPassword(pw) => {
                let mut wan = Map::new();
                wan.insert(label, cred);
                CredentialType::PasswordMfa(pw.clone(), Map::default(), wan, None)
            }
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => {
                let mut nmap = map.clone();
                if nmap.insert(label.clone(), cred).is_some() {
                    return Err(OperationError::InvalidAttribute(format!(
                        "Webauthn label '{label:?}' already exists"
                    )));
                }
                CredentialType::PasswordMfa(pw.clone(), totp.clone(), nmap, backup_code.clone())
            }
            // Ignore
            CredentialType::Webauthn(map) => CredentialType::Webauthn(map.clone()),
        };

        // Check stuff
        Ok(Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
        })
    }

    /// Remove a webauthn token identified by `label` from this Credential.
    pub fn remove_securitykey(&self, label: &str) -> Result<Self, OperationError> {
        let type_ = match &self.type_ {
            CredentialType::Password(_)
            | CredentialType::GeneratedPassword(_)
            | CredentialType::Webauthn(_) => {
                return Err(OperationError::InvalidAttribute(
                    "SecurityKey is not present on this credential".to_string(),
                ));
            }
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => {
                let mut nmap = map.clone();
                if nmap.remove(label).is_none() {
                    return Err(OperationError::InvalidAttribute(format!(
                        "Removing Webauthn token with label '{label:?}': does not exist"
                    )));
                }
                if nmap.is_empty() {
                    if !totp.is_empty() {
                        CredentialType::PasswordMfa(
                            pw.clone(),
                            totp.clone(),
                            nmap,
                            backup_code.clone(),
                        )
                    } else {
                        // Note: No need to keep backup code if it is no longer MFA
                        CredentialType::Password(pw.clone())
                    }
                } else {
                    CredentialType::PasswordMfa(pw.clone(), totp.clone(), nmap, backup_code.clone())
                }
            }
        };

        // Check stuff
        Ok(Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
        })
    }

    #[allow(clippy::ptr_arg)]
    /// After a successful authentication with Webauthn, we need to advance the credentials
    /// counter value to prevent certain classes of replay attacks.
    pub fn update_webauthn_properties(
        &self,
        auth_result: &AuthenticationResult,
    ) -> Result<Option<Self>, OperationError> {
        let type_ = match &self.type_ {
            CredentialType::Password(_pw) | CredentialType::GeneratedPassword(_pw) => {
                // Should not be possible!
                // -- this does occur when we have mixed pw/passkey
                // and we need to do an update, so we just mask this no Ok(None).
                // return Err(OperationError::InvalidState);
                return Ok(None);
            }
            CredentialType::Webauthn(map) => {
                let mut nmap = map.clone();
                nmap.values_mut().for_each(|pk| {
                    pk.update_credential(auth_result);
                });
                CredentialType::Webauthn(nmap)
            }
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => {
                let mut nmap = map.clone();
                nmap.values_mut().for_each(|sk| {
                    sk.update_credential(auth_result);
                });
                CredentialType::PasswordMfa(pw.clone(), totp.clone(), nmap, backup_code.clone())
            }
        };

        Ok(Some(Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
        }))
    }

    /// Get a reference to the contained webuthn credentials, if any.
    pub fn securitykey_ref(&self) -> Result<&Map<String, SecurityKey>, OperationError> {
        match &self.type_ {
            CredentialType::Webauthn(_)
            | CredentialType::Password(_)
            | CredentialType::GeneratedPassword(_) => Err(OperationError::InvalidAccountState(
                "non-webauthn cred type?".to_string(),
            )),
            CredentialType::PasswordMfa(_, _, map, _) => Ok(map),
        }
    }

    pub fn passkey_ref(&self) -> Result<&Map<String, Passkey>, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(_, _, _, _)
            | CredentialType::Password(_)
            | CredentialType::GeneratedPassword(_) => Err(OperationError::InvalidAccountState(
                "non-webauthn cred type?".to_string(),
            )),
            CredentialType::Webauthn(map) => Ok(map),
        }
    }

    /// Get a reference to the contained password, if any.
    pub fn password_ref(&self) -> Result<&Password, OperationError> {
        match &self.type_ {
            CredentialType::Password(pw)
            | CredentialType::GeneratedPassword(pw)
            | CredentialType::PasswordMfa(pw, _, _, _) => Ok(pw),
            CredentialType::Webauthn(_) => Err(OperationError::InvalidAccountState(
                "non-password cred type?".to_string(),
            )),
        }
    }

    #[cfg(test)]
    pub fn verify_password(&self, cleartext: &str) -> Result<bool, OperationError> {
        self.password_ref().and_then(|pw| pw.verify(cleartext))
    }

    /// Extract this credential into it's Serialisable Database form, ready for persistence.
    pub fn to_db_valuev1(&self) -> DbCred {
        let uuid = self.uuid;
        match &self.type_ {
            CredentialType::Password(pw) => DbCred::V2Password {
                password: pw.to_dbpasswordv1(),
                uuid,
            },
            CredentialType::GeneratedPassword(pw) => DbCred::V2GenPassword {
                password: pw.to_dbpasswordv1(),
                uuid,
            },
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => DbCred::V3PasswordMfa {
                password: pw.to_dbpasswordv1(),
                totp: totp
                    .iter()
                    .map(|(l, t)| (l.clone(), t.to_dbtotpv1()))
                    .collect(),
                backup_code: backup_code.as_ref().map(|b| b.to_dbbackupcodev1()),
                webauthn: map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                uuid,
            },
            CredentialType::Webauthn(map) => DbCred::TmpWn {
                webauthn: map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                uuid,
            },
        }
    }

    /// Extract this credential into it's Serialisable Replication form
    pub fn to_repl_v1(&self, tag: String) -> ReplCredV1 {
        let uuid = self.uuid;
        match &self.type_ {
            CredentialType::Password(pw) => ReplCredV1::Password {
                tag,
                password: pw.to_repl_v1(),
                uuid,
            },
            CredentialType::GeneratedPassword(pw) => ReplCredV1::GenPassword {
                tag,
                password: pw.to_repl_v1(),
                uuid,
            },
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => ReplCredV1::PasswordMfa {
                tag,
                password: pw.to_repl_v1(),
                totp: totp
                    .iter()
                    .map(|(l, t)| (l.clone(), t.to_repl_v1()))
                    .collect(),
                backup_code: backup_code.as_ref().map(|b| b.to_repl_v1()),
                webauthn: map
                    .iter()
                    .map(|(k, v)| ReplSecurityKeyV4V1 {
                        tag: k.clone(),
                        key: v.clone(),
                    })
                    .collect(),
                uuid,
            },
            CredentialType::Webauthn(map) => ReplCredV1::TmpWn {
                tag,
                set: map
                    .iter()
                    .map(|(k, v)| ReplPasskeyV4V1 {
                        uuid,
                        tag: k.clone(),
                        key: v.clone(),
                    })
                    .collect(),
            },
        }
    }

    pub(crate) fn update_password(&self, pw: Password) -> Self {
        let type_ = match &self.type_ {
            CredentialType::Password(_) | CredentialType::GeneratedPassword(_) => {
                CredentialType::Password(pw)
            }
            CredentialType::PasswordMfa(_, totp, wan, backup_code) => {
                CredentialType::PasswordMfa(pw, totp.clone(), wan.clone(), backup_code.clone())
            }
            // Ignore
            CredentialType::Webauthn(wan) => CredentialType::Webauthn(wan.clone()),
        };
        Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
        }
    }

    // We don't make totp accessible from outside the crate for now.
    pub(crate) fn append_totp(&self, label: String, totp: Totp) -> Self {
        let type_ = match &self.type_ {
            CredentialType::Password(pw) | CredentialType::GeneratedPassword(pw) => {
                CredentialType::PasswordMfa(
                    pw.clone(),
                    Map::from([(label, totp)]),
                    Map::new(),
                    None,
                )
            }
            CredentialType::PasswordMfa(pw, totps, wan, backup_code) => {
                let mut totps = totps.clone();
                let replaced = totps.insert(label, totp).is_none();
                debug_assert!(replaced);

                CredentialType::PasswordMfa(pw.clone(), totps, wan.clone(), backup_code.clone())
            }
            CredentialType::Webauthn(wan) => {
                debug_assert!(false);
                CredentialType::Webauthn(wan.clone())
            }
        };
        Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
        }
    }

    pub(crate) fn remove_totp(&self, label: &str) -> Self {
        let type_ = match &self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, backup_code) => {
                let mut totp = totp.clone();
                let removed = totp.remove(label).is_some();
                debug_assert!(removed);

                if wan.is_empty() && totp.is_empty() {
                    // Note: No need to keep backup code if it is no longer MFA
                    CredentialType::Password(pw.clone())
                } else {
                    CredentialType::PasswordMfa(pw.clone(), totp, wan.clone(), backup_code.clone())
                }
            }
            _ => self.type_.clone(),
        };
        Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
        }
    }

    pub(crate) fn new_from_generatedpassword(pw: Password) -> Self {
        Credential {
            type_: CredentialType::GeneratedPassword(pw),
            uuid: Uuid::new_v4(),
        }
    }

    pub(crate) fn new_from_password(pw: Password) -> Self {
        Credential {
            type_: CredentialType::Password(pw),
            uuid: Uuid::new_v4(),
        }
    }

    pub(crate) fn softlock_policy(&self) -> CredSoftLockPolicy {
        match &self.type_ {
            CredentialType::Password(_pw) | CredentialType::GeneratedPassword(_pw) => {
                CredSoftLockPolicy::Password
            }
            CredentialType::PasswordMfa(_pw, totp, wan, _) => {
                // For backup code, use totp/wan policy (whatever is available)
                if !totp.is_empty() {
                    // What's the min step?
                    let min_step = totp
                        .iter()
                        .map(|(_, t)| t.step)
                        .min()
                        .unwrap_or(TOTP_DEFAULT_STEP);
                    CredSoftLockPolicy::Totp(min_step)
                } else if !wan.is_empty() {
                    CredSoftLockPolicy::Webauthn
                } else {
                    CredSoftLockPolicy::Password
                }
            }
            CredentialType::Webauthn(_wan) => CredSoftLockPolicy::Webauthn,
        }
    }

    pub(crate) fn update_backup_code(
        &self,
        backup_codes: BackupCodes,
    ) -> Result<Self, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, _) => Ok(Credential {
                type_: CredentialType::PasswordMfa(
                    pw.clone(),
                    totp.clone(),
                    wan.clone(),
                    Some(backup_codes),
                ),
                // Rotate the credential id on any change to invalidate sessions.
                uuid: Uuid::new_v4(),
            }),
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }

    pub(crate) fn invalidate_backup_code(
        self,
        code_to_remove: &str,
    ) -> Result<Self, OperationError> {
        match self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, opt_backup_codes) => {
                match opt_backup_codes {
                    Some(mut backup_codes) => {
                        backup_codes.remove(code_to_remove);
                        Ok(Credential {
                            type_: CredentialType::PasswordMfa(pw, totp, wan, Some(backup_codes)),
                            // Don't rotate uuid here since this is a consumption of a backup
                            // code.
                            uuid: self.uuid,
                        })
                    }
                    _ => Err(OperationError::InvalidAccountState(
                        "backup code does not exist".to_string(),
                    )),
                }
            }
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }

    pub(crate) fn remove_backup_code(&self) -> Result<Self, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, _) => Ok(Credential {
                type_: CredentialType::PasswordMfa(pw.clone(), totp.clone(), wan.clone(), None),
                // Rotate the credential id on any change to invalidate sessions.
                uuid: Uuid::new_v4(),
            }),
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }

    pub(crate) fn get_backup_code_view(&self) -> Result<BackupCodesView, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(_, _, _, opt_bc) => opt_bc
                .as_ref()
                .ok_or_else(|| {
                    OperationError::InvalidAccountState(
                        "No backup codes are available for this account".to_string(),
                    )
                })
                .map(|bc| BackupCodesView {
                    backup_codes: bc.code_set.clone().into_iter().collect(),
                }),
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }
}

impl CredentialType {
    fn is_valid(&self) -> bool {
        match self {
            CredentialType::Password(_) | CredentialType::GeneratedPassword(_) => true,
            CredentialType::PasswordMfa(_, m_totp, webauthn, _) => {
                !m_totp.is_empty() || !webauthn.is_empty() // ignore backup code (it should only be a complement for totp/webauth)
            }
            CredentialType::Webauthn(webauthn) => !webauthn.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::credential::policy::CryptoPolicy;
    use crate::credential::*;

    #[test]
    fn test_credential_simple() {
        let p = CryptoPolicy::minimum();
        let c = Credential::new_password_only(&p, "password").unwrap();
        assert!(c.verify_password("password").unwrap());
        assert!(!c.verify_password("password1").unwrap());
        assert!(!c.verify_password("Password1").unwrap());
        assert!(!c.verify_password("It Works!").unwrap());
        assert!(!c.verify_password("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap());
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

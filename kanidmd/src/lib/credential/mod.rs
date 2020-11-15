use crate::be::dbvalue::{DbCredV1, DbPasswordV1, DbWebauthnV1};
use hashbrown::HashMap as Map;
use kanidm_proto::v1::OperationError;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::sha::Sha512;
use rand::prelude::*;
use std::convert::TryFrom;
use std::time::{Duration, Instant};
use uuid::Uuid;
use webauthn_rs::proto::Credential as WebauthnCredential;

pub mod policy;
pub mod softlock;
pub mod totp;
pub mod webauthn;

use crate::credential::policy::CryptoPolicy;
use crate::credential::softlock::CredSoftLockPolicy;
use crate::credential::totp::TOTP;

// NIST 800-63.b salt should be 112 bits -> 14  8u8.
// I choose tinfoil hat though ...
const PBKDF2_SALT_LEN: usize = 24;
// 64 * u8 -> 512 bits of out.
const PBKDF2_KEY_LEN: usize = 64;
const PBKDF2_IMPORT_MIN_LEN: usize = 32;

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
#[derive(Clone, Debug)]
enum KDF {
    //     cost, salt,   hash
    PBKDF2(usize, Vec<u8>, Vec<u8>),
    //      salt     hash
    SSHA512(Vec<u8>, Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct Password {
    material: KDF,
}

impl TryFrom<DbPasswordV1> for Password {
    type Error = ();

    fn try_from(value: DbPasswordV1) -> Result<Self, Self::Error> {
        match value {
            DbPasswordV1::PBKDF2(c, s, h) => Ok(Password {
                material: KDF::PBKDF2(c, s, h),
            }),
            DbPasswordV1::SSHA512(s, h) => Ok(Password {
                material: KDF::SSHA512(s, h),
            }),
        }
    }
}

impl TryFrom<&str> for Password {
    type Error = ();

    // As we may add more algos, we keep the match algo single for later.
    #[allow(clippy::single_match)]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // There is probably a more efficent way to try this given different types?

        // test django - algo$salt$hash
        let django_pbkdf: Vec<&str> = value.split('$').collect();
        if django_pbkdf.len() == 4 {
            let algo = django_pbkdf[0];
            let cost = django_pbkdf[1];
            let salt = django_pbkdf[2];
            let hash = django_pbkdf[3];
            match algo {
                "pbkdf2_sha256" => {
                    let c = usize::from_str_radix(cost, 10).map_err(|_| ())?;
                    let s: Vec<_> = salt.as_bytes().to_vec();
                    let h = base64::decode(hash).map_err(|_| ())?;
                    if h.len() < PBKDF2_IMPORT_MIN_LEN {
                        return Err(());
                    }
                    return Ok(Password {
                        material: KDF::PBKDF2(c, s, h),
                    });
                }
                _ => {}
            }
        }

        // Test 389ds formats
        if let Some(ds_ssha512) = value.strip_prefix("{SSHA512}") {
            let sh = base64::decode(ds_ssha512).map_err(|_| ())?;
            let (h, s) = sh.split_at(DS_SSHA512_HASH_LEN);
            if s.len() != DS_SSHA512_SALT_LEN {
                return Err(());
            }
            return Ok(Password {
                material: KDF::SSHA512(s.to_vec(), h.to_vec()),
            });
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
        let _ = pbkdf2_hmac(
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

    fn new_pbkdf2(pbkdf2_cost: usize, cleartext: &str) -> Result<KDF, OperationError> {
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
            KDF::PBKDF2(pbkdf2_cost, salt, key)
        })
        .map_err(|_| OperationError::CryptographyError)
    }

    pub fn new(policy: &CryptoPolicy, cleartext: &str) -> Result<Self, OperationError> {
        Self::new_pbkdf2(policy.pbkdf2_cost, cleartext).map(|material| Password { material })
    }

    pub fn verify(&self, cleartext: &str) -> Result<bool, OperationError> {
        match &self.material {
            KDF::PBKDF2(cost, salt, key) => {
                // We have to get the number of bits to derive from our stored hash
                // as some imported hash types may have variable lengths
                let key_len = key.len();
                debug_assert!(key_len >= PBKDF2_IMPORT_MIN_LEN);
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
            KDF::SSHA512(salt, key) => {
                let mut hasher = Sha512::new();
                hasher.update(cleartext.as_bytes());
                hasher.update(&salt);
                let r = hasher.finish();
                Ok(key == &(r.to_vec()))
            }
        }
    }

    pub fn to_dbpasswordv1(&self) -> DbPasswordV1 {
        match &self.material {
            KDF::PBKDF2(cost, salt, hash) => {
                DbPasswordV1::PBKDF2(*cost, salt.clone(), hash.clone())
            }
            KDF::SSHA512(salt, hash) => DbPasswordV1::SSHA512(salt.clone(), hash.clone()),
        }
    }

    pub fn requires_upgrade(&self) -> bool {
        match &self.material {
            KDF::PBKDF2(_, _, _) => false,
            _ => true,
        }
    }
}

#[derive(Clone, Debug)]
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
/// some metadata to support this such as it's source and strength etc. Some of these details are
/// to be resolved ...
pub struct Credential {
    // Source (machine, user, ....). Strength?
    // policy: Policy,
    pub(crate) password: Option<Password>,
    pub(crate) webauthn: Option<Map<String, WebauthnCredential>>,
    // totp: Option<NonEmptyVec<TOTP>>
    pub(crate) totp: Option<TOTP>,
    pub(crate) claims: Vec<String>,
    // Uuid of Credential, used by auth session to lock this specific credential
    // if required.
    pub(crate) uuid: Uuid,
    // TODO #59: Add auth policy IE validUntil, lock state ...
    // locked: bool
}

impl TryFrom<DbCredV1> for Credential {
    type Error = ();

    fn try_from(value: DbCredV1) -> Result<Self, Self::Error> {
        // Work out what the policy is?
        let DbCredV1 {
            password,
            webauthn,
            totp,
            claims,
            uuid,
        } = value;

        let v_password = match password {
            Some(dbp) => Some(Password::try_from(dbp)?),
            None => None,
        };

        let v_totp = match totp {
            Some(dbt) => Some(TOTP::try_from(dbt)?),
            None => None,
        };

        let v_webauthn = match webauthn {
            Some(dbw) => Some(
                dbw.into_iter()
                    .map(|wc| {
                        (
                            wc.l,
                            WebauthnCredential {
                                cred_id: wc.i,
                                cred: wc.c,
                                counter: wc.t,
                                verified: wc.v,
                            },
                        )
                    })
                    .collect(),
            ),
            None => None,
        };

        Ok(Credential {
            password: v_password,
            webauthn: v_webauthn,
            totp: v_totp,
            claims,
            uuid,
        })
    }
}

impl Credential {
    pub fn new_password_only(
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext).map(|pw| Self::new_from_password(pw))
    }

    pub fn new_webauthn_only(label: String, cred: WebauthnCredential) -> Self {
        let mut webauthn_map = Map::new();
        webauthn_map.insert(label, cred);
        Credential {
            password: None,
            webauthn: Some(webauthn_map),
            totp: None,
            claims: Vec::new(),
            uuid: Uuid::new_v4(),
        }
    }

    pub fn set_password(
        &self,
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext).map(|pw| Credential {
            password: Some(pw),
            webauthn: self.webauthn.clone(),
            totp: self.totp.clone(),
            claims: self.claims.clone(),
            uuid: self.uuid,
        })
    }

    pub fn append_webauthn(
        &self,
        label: String,
        cred: WebauthnCredential,
    ) -> Result<Self, OperationError> {
        let webauthn_map = match &self.webauthn {
            Some(map) => {
                let mut nmap = map.clone();
                match nmap.insert(label.clone(), cred) {
                    Some(_) => {
                        return Err(OperationError::InvalidAttribute(format!(
                            "Webauthn label '{:?}' already exists",
                            label
                        )));
                    }
                    None => nmap,
                }
            }
            None => {
                let mut map = Map::new();
                map.insert(label, cred);
                map
            }
        };
        // Check stuff
        Ok(Credential {
            password: self.password.clone(),
            webauthn: Some(webauthn_map),
            totp: self.totp.clone(),
            claims: self.claims.clone(),
            uuid: self.uuid,
        })
    }

    #[cfg(test)]
    pub fn verify_password(&self, cleartext: &str) -> bool {
        match &self.password {
            Some(pw) => pw.verify(cleartext).unwrap_or(false),
            None => false,
        }
    }

    pub fn to_db_valuev1(&self) -> DbCredV1 {
        DbCredV1 {
            password: self.password.as_ref().map(|pw| pw.to_dbpasswordv1()),
            webauthn: self.webauthn.as_ref().map(|map| {
                map.iter()
                    .map(|(k, v)| DbWebauthnV1 {
                        l: k.clone(),
                        i: v.cred_id.clone(),
                        c: v.cred.clone(),
                        t: v.counter,
                        v: v.verified,
                    })
                    .collect()
            }),
            totp: self.totp.as_ref().map(|t| t.to_dbtotpv1()),
            claims: self.claims.clone(),
            uuid: self.uuid,
        }
    }

    pub(crate) fn update_password(&self, pw: Password) -> Self {
        Credential {
            password: Some(pw),
            webauthn: self.webauthn.clone(),
            totp: self.totp.clone(),
            claims: self.claims.clone(),
            uuid: self.uuid,
        }
    }

    // We don't make totp accessible from outside the crate for now.
    pub(crate) fn update_totp(&self, totp: TOTP) -> Self {
        Credential {
            password: self.password.clone(),
            webauthn: self.webauthn.clone(),
            totp: Some(totp),
            claims: self.claims.clone(),
            uuid: self.uuid,
        }
    }

    pub(crate) fn new_from_password(pw: Password) -> Self {
        Credential {
            password: Some(pw),
            webauthn: None,
            totp: None,
            claims: Vec::new(),
            uuid: Uuid::new_v4(),
        }
    }

    pub(crate) fn softlock_policy(&self) -> Option<CredSoftLockPolicy> {
        match (&self.webauthn, &self.totp, &self.password) {
            // Has any kind of Webauthn ....
            (Some(_webauthn), _, _) => Some(CredSoftLockPolicy::Webauthn),
            // Has any kind of totp.
            (None, Some(totp), _) => Some(CredSoftLockPolicy::TOTP(totp.step)),
            // No totp, pw
            (None, None, Some(_)) => Some(CredSoftLockPolicy::Password),
            // Indeterminate
            _ => None,
        }
    }

    /*
    pub fn add_claim(&mut self) {
    }

    pub fn remove_claim(&mut self) {
    }
    */

    /*
    pub fn modify_password(&mut self) {
        // Change the password
    }

    pub fn add_webauthn_token() {
    }

    pub fn remove_webauthn_token() {
    }
    */
}

#[cfg(test)]
mod tests {
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::*;
    use std::convert::TryFrom;

    #[test]
    fn test_credential_simple() {
        let p = CryptoPolicy::minimum();
        let c = Credential::new_password_only(&p, "password").unwrap();
        assert!(c.verify_password("password"));
        assert!(!c.verify_password("password1"));
        assert!(!c.verify_password("Password1"));
        assert!(!c.verify_password("It Works!"));
        assert!(!c.verify_password("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
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
}

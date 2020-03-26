use crate::be::dbvalue::{DbCredV1, DbPasswordV1};
use base64;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use rand::prelude::*;
use std::convert::TryFrom;
use uuid::Uuid;

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

// TODO: Determine this at startup based on a time factor
const PBKDF2_COST: usize = 10000;
// NIST 800-63.b salt should be 112 bits -> 14  8u8.
// I choose tinfoil hat though ...
const PBKDF2_SALT_LEN: usize = 24;
// 64 * u8 -> 512 bits of out.
const PBKDF2_KEY_LEN: usize = 64;

const PBKDF2_IMPORT_MIN_LEN: usize = 32;

// Why PBKDF2? Rust's bcrypt has a number of hardcodings like max pw len of 72
// I don't really feel like adding in so many restrictions, so I'll use
// pbkdf2 in openssl because it doesn't have the same limits.
#[derive(Clone, Debug)]
enum KDF {
    //     cost, salt,   hash
    PBKDF2(usize, Vec<u8>, Vec<u8>),
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
        }
    }
}

impl TryFrom<&str> for Password {
    type Error = ();

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
                    let s: Vec<_> = salt.as_bytes().iter().map(|b| *b).collect();
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

        // Nothing matched to this point.
        Err(())
    }
}

impl Password {
    fn new_pbkdf2(cleartext: &str) -> KDF {
        let mut rng = rand::thread_rng();
        let salt: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| rng.gen()).collect();
        // This is 512 bits of output
        let mut key: Vec<u8> = (0..PBKDF2_KEY_LEN).map(|_| 0).collect();

        pbkdf2_hmac(
            cleartext.as_bytes(),
            salt.as_slice(),
            PBKDF2_COST,
            MessageDigest::sha256(),
            key.as_mut_slice(),
        )
        .expect("PBKDF2 failure");
        // Turn key to a vec.
        KDF::PBKDF2(PBKDF2_COST, salt, key)
    }

    pub fn new(cleartext: &str) -> Self {
        Password {
            material: Self::new_pbkdf2(cleartext),
        }
    }

    pub fn verify(&self, cleartext: &str) -> bool {
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
                .expect("PBKDF2 failure");
                // Actually compare the outputs.
                &chal_key == key
            }
        }
    }

    pub fn to_dbpasswordv1(&self) -> DbPasswordV1 {
        match &self.material {
            KDF::PBKDF2(cost, salt, hash) => {
                DbPasswordV1::PBKDF2(*cost, salt.clone(), hash.clone())
            }
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
    // webauthn: Option<NonEmptyVec<Webauthn>>
    // totp: Option<NonEmptyVec<TOTP>>
    pub(crate) claims: Vec<String>,
    // Uuid of Credential, used by auth session to lock this specific credential
    // if required.
    pub(crate) uuid: Uuid,
    // TODO: Add auth policy IE validUntil, lock state ...
    // locked: bool
}

impl TryFrom<DbCredV1> for Credential {
    type Error = ();

    fn try_from(value: DbCredV1) -> Result<Self, Self::Error> {
        // Work out what the policy is?
        let DbCredV1 {
            password,
            claims,
            uuid,
        } = value;

        let v_password = match password {
            Some(dbp) => Some(Password::try_from(dbp)?),
            None => None,
        };

        Ok(Credential {
            password: v_password,
            claims,
            uuid,
        })
    }
}

impl Credential {
    pub fn new_password_only(cleartext: &str) -> Self {
        Credential {
            password: Some(Password::new(cleartext)),
            claims: Vec::new(),
            uuid: Uuid::new_v4(),
        }
    }

    pub fn set_password(&self, cleartext: &str) -> Self {
        Credential {
            password: Some(Password::new(cleartext)),
            claims: self.claims.clone(),
            uuid: self.uuid,
        }
    }

    #[cfg(test)]
    pub fn verify_password(&self, cleartext: &str) -> bool {
        match &self.password {
            Some(pw) => pw.verify(cleartext),
            None => panic!(),
        }
    }

    pub fn to_db_valuev1(&self) -> DbCredV1 {
        DbCredV1 {
            password: match &self.password {
                Some(pw) => Some(pw.to_dbpasswordv1()),
                None => None,
            },
            claims: self.claims.clone(),
            uuid: self.uuid,
        }
    }

    pub(crate) fn update_password(&self, pw: Password) -> Self {
        Credential {
            password: Some(pw),
            claims: self.claims.clone(),
            uuid: self.uuid.clone(),
        }
    }

    pub(crate) fn new_from_password(pw: Password) -> Self {
        Credential {
            password: Some(pw),
            claims: Vec::new(),
            uuid: Uuid::new_v4(),
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
    use crate::credential::*;
    use std::convert::TryFrom;

    #[test]
    fn test_credential_simple() {
        let c = Credential::new_password_only("password");
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
        assert!(r.verify(password));
    }
}

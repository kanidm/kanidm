#[cfg(test)]
use openssl::hash::MessageDigest;
#[cfg(test)]
use openssl::pkcs5::pbkdf2_hmac;
#[cfg(test)]
use rand::prelude::*;
use uuid::Uuid;
use crate::be::dbvalue::{DbCredV1, DbPasswordV1};

// These are in order of "relative" strength.
#[derive(Clone, Debug)]
pub enum Policy {
    PasswordOnly,
    WebauthnOnly,
    GeneratedPassword,
    PasswordAndWebauthn,
}

// TODO: Determine this at startup based on a time factor
#[cfg(test)]
const PBKDF2_COST: usize = 10000;
// NIST 800-63.b salt should be 112 bits -> 14  8u8.
// I choose tinfoil hat though ...
#[cfg(test)]
const PBKDF2_SALT_LEN: usize = 24;
// 64 * u8 -> 512 bits of out.
#[cfg(test)]
const PBKDF2_KEY_LEN: usize = 64;

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

impl Password {
    #[cfg(test)]
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

    #[cfg(test)]
    pub fn new(cleartext: &str) -> Self {
        Password {
            material: Self::new_pbkdf2(cleartext),
        }
    }

    #[cfg(test)]
    pub fn verify(&self, cleartext: &str) -> bool {
        match &self.material {
            KDF::PBKDF2(cost, salt, key) => {
                let mut chal_key: Vec<u8> = (0..PBKDF2_KEY_LEN).map(|_| 0).collect();
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
    policy: Policy,
    password: Option<Password>,
    // webauthn: Option<NonEmptyVec<Webauthn>>
    // totp: Option<NonEmptyVec<TOTP>>
    claims: Vec<String>,
    // Uuid of Credential, used by auth session to lock this specific credential
    // if required.
    uuid: Uuid,
    // TODO: Add auth policy IE validUntil, lock state ...
    // locked: bool
}

impl Credential {
    #[cfg(test)]
    pub fn new_password_only(cleartext: &str) -> Self {
        Credential {
            policy: Policy::PasswordOnly,
            password: Some(Password::new(cleartext)),
            claims: Vec::new(),
            uuid: Uuid::new_v4(),
        }
    }

    #[cfg(test)]
    pub fn verify_password(&self, cleartext: &str) -> bool {
        match &self.password {
            Some(pw) => pw.verify(cleartext),
            None => unimplemented!(),
        }
    }

    pub fn to_db_valuev1(&self) -> DbCredV1 {
        DbCredV1 {
            password: match &self.password {
                Some(pw) => {
                    match &pw.material {
                        KDF::PBKDF2(cost, salt, hash) => {
                            Some(DbPasswordV1::PBKDF2(*cost, salt.clone(), hash.clone()))
                        }
                    }
                }
                None => None,
            },
            claims: self.claims.clone(),
            uuid: self.uuid.clone(),

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

    #[test]
    fn test_credential_simple() {
        let c = Credential::new_password_only("password");
        assert!(c.verify_password("password"));
        assert!(!c.verify_password("password1"));
        assert!(!c.verify_password("Password1"));
        assert!(!c.verify_password("It Works!"));
        assert!(!c.verify_password("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }
}

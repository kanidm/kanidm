use crate::be::dbvalue::{DbTotpAlgoV1, DbTotpV1};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use rand::prelude::*;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::time::{Duration, SystemTime};

use kanidm_proto::v1::TotpAlgo as ProtoTotpAlgo;
use kanidm_proto::v1::TotpSecret as ProtoTotp;

// This is 64 bits of entropy, as the examples in https://tools.ietf.org/html/rfc6238 show.
const SECRET_SIZE_BYTES: usize = 8;
pub const TOTP_DEFAULT_STEP: u64 = 30;

#[derive(Debug, PartialEq)]
pub enum TotpError {
    OpenSSLError,
    HmacError,
    TimeError,
}

#[derive(Debug, Clone)]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgo {
    pub(crate) fn digest(&self, key: &[u8], counter: u64) -> Result<Vec<u8>, TotpError> {
        let key = PKey::hmac(key).map_err(|_e| TotpError::OpenSSLError)?;
        let mut signer =
            match self {
                TotpAlgo::Sha1 => Signer::new(MessageDigest::sha1(), &key)
                    .map_err(|_e| TotpError::OpenSSLError)?,
                TotpAlgo::Sha256 => Signer::new(MessageDigest::sha256(), &key)
                    .map_err(|_e| TotpError::OpenSSLError)?,
                TotpAlgo::Sha512 => Signer::new(MessageDigest::sha512(), &key)
                    .map_err(|_e| TotpError::OpenSSLError)?,
            };
        signer
            .update(&counter.to_be_bytes())
            .map_err(|_e| TotpError::OpenSSLError)?;
        let hmac = signer.sign_to_vec().map_err(|_e| TotpError::OpenSSLError)?;

        let expect = match self {
            TotpAlgo::Sha1 => 20,
            TotpAlgo::Sha256 => 32,
            TotpAlgo::Sha512 => 64,
        };
        if hmac.len() != expect {
            return Err(TotpError::HmacError);
        }
        Ok(hmac)
    }
}

/// https://tools.ietf.org/html/rfc6238 which relies on https://tools.ietf.org/html/rfc4226
#[derive(Debug, Clone)]
pub struct Totp {
    secret: Vec<u8>,
    pub(crate) step: u64,
    algo: TotpAlgo,
}

impl TryFrom<DbTotpV1> for Totp {
    type Error = ();

    fn try_from(value: DbTotpV1) -> Result<Self, Self::Error> {
        let algo = match value.algo {
            DbTotpAlgoV1::S1 => TotpAlgo::Sha1,
            DbTotpAlgoV1::S256 => TotpAlgo::Sha256,
            DbTotpAlgoV1::S512 => TotpAlgo::Sha512,
        };
        Ok(Totp {
            secret: value.key,
            step: value.step,
            algo,
        })
    }
}

impl From<ProtoTotp> for Totp {
    fn from(value: ProtoTotp) -> Self {
        Totp {
            secret: value.secret,
            algo: match value.algo {
                ProtoTotpAlgo::Sha1 => TotpAlgo::Sha1,
                ProtoTotpAlgo::Sha256 => TotpAlgo::Sha256,
                ProtoTotpAlgo::Sha512 => TotpAlgo::Sha512,
            },
            step: value.step,
        }
    }
}

impl Totp {
    pub fn new(secret: Vec<u8>, step: u64, algo: TotpAlgo) -> Self {
        Totp { secret, step, algo }
    }

    // Create a new token with secure key and algo.
    pub fn generate_secure(step: u64) -> Self {
        let mut rng = rand::thread_rng();
        let secret: Vec<u8> = (0..SECRET_SIZE_BYTES).map(|_| rng.gen()).collect();
        let algo = TotpAlgo::Sha512;
        Totp { secret, step, algo }
    }

    pub(crate) fn to_dbtotpv1(&self) -> DbTotpV1 {
        DbTotpV1 {
            label: "totp".to_string(),
            key: self.secret.clone(),
            step: self.step,
            algo: match self.algo {
                TotpAlgo::Sha1 => DbTotpAlgoV1::S1,
                TotpAlgo::Sha256 => DbTotpAlgoV1::S256,
                TotpAlgo::Sha512 => DbTotpAlgoV1::S512,
            },
        }
    }

    fn digest(&self, counter: u64) -> Result<u32, TotpError> {
        let hmac = self.algo.digest(&self.secret, counter)?;
        // Now take the hmac and encode it as hotp expects.
        // https://tools.ietf.org/html/rfc4226#page-7
        let offset = hmac
            .last()
            .map(|v| (v & 0xf) as usize)
            .ok_or(TotpError::HmacError)?;
        let bytes: [u8; 4] = hmac[offset..offset + 4]
            .try_into()
            .map_err(|_| TotpError::HmacError)?;

        let otp = u32::from_be_bytes(bytes);
        Ok((otp & 0x7fff_ffff) % 1_000_000)
    }

    pub fn do_totp_duration_from_epoch(&self, time: &Duration) -> Result<u32, TotpError> {
        let secs = time.as_secs();
        // do the window calculation
        let counter = secs / self.step;
        self.digest(counter)
    }

    pub fn do_totp(&self, time: &SystemTime) -> Result<u32, TotpError> {
        let dur = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TotpError::TimeError)?;
        self.do_totp_duration_from_epoch(&dur)
    }

    pub fn verify(&self, chal: u32, time: &Duration) -> bool {
        let secs = time.as_secs();
        let counter = secs / self.step;
        // Any error becomes a failure.
        self.digest(counter).map(|v1| v1 == chal).unwrap_or(false)
            || self
                .digest(counter - 1)
                .map(|v2| v2 == chal)
                .unwrap_or(false)
    }

    pub fn to_proto(&self, accountname: &str, issuer: &str) -> ProtoTotp {
        ProtoTotp {
            accountname: accountname
                .replace(":", "")
                .replace("%3A", "")
                .replace(" ", "%20"),
            issuer: issuer
                .replace(":", "")
                .replace("%3A", "")
                .replace(" ", "%20"),
            secret: self.secret.clone(),
            step: self.step,
            algo: match self.algo {
                TotpAlgo::Sha1 => ProtoTotpAlgo::Sha1,
                TotpAlgo::Sha256 => ProtoTotpAlgo::Sha256,
                TotpAlgo::Sha512 => ProtoTotpAlgo::Sha512,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::totp::{Totp, TotpAlgo, TotpError, TOTP_DEFAULT_STEP};
    use std::time::Duration;

    #[test]
    fn hotp_basic() {
        let otp_sha1 = Totp::new(vec![0], 30, TotpAlgo::Sha1);
        assert!(otp_sha1.digest(0) == Ok(328482));
        let otp_sha256 = Totp::new(vec![0], 30, TotpAlgo::Sha256);
        assert!(otp_sha256.digest(0) == Ok(356306));
        let otp_sha512 = Totp::new(vec![0], 30, TotpAlgo::Sha512);
        assert!(otp_sha512.digest(0) == Ok(674061));
    }

    fn do_test(key: Vec<u8>, algo: TotpAlgo, secs: u64, step: u64, expect: Result<u32, TotpError>) {
        let otp = Totp::new(key.clone(), step, algo.clone());
        let d = Duration::from_secs(secs);
        let r = otp.do_totp_duration_from_epoch(&d);
        debug!(
            "key: {:?}, algo: {:?}, time: {:?}, step: {:?}, expect: {:?} == {:?}",
            key, algo, secs, step, expect, r
        );
        assert!(r == expect);
    }

    #[test]
    fn totp_sha1_vectors() {
        do_test(
            vec![0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha1,
            1585368920,
            TOTP_DEFAULT_STEP,
            Ok(728926),
        );
        do_test(
            vec![0x00, 0xaa, 0xbb, 0xcc],
            TotpAlgo::Sha1,
            1585369498,
            TOTP_DEFAULT_STEP,
            Ok(985074),
        );
    }

    #[test]
    fn totp_sha256_vectors() {
        do_test(
            vec![0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha256,
            1585369682,
            TOTP_DEFAULT_STEP,
            Ok(795483),
        );
        do_test(
            vec![0x00, 0xaa, 0xbb, 0xcc],
            TotpAlgo::Sha256,
            1585369689,
            TOTP_DEFAULT_STEP,
            Ok(728402),
        );
    }

    #[test]
    fn totp_sha512_vectors() {
        do_test(
            vec![0x00, 0x00, 0x00, 0x00],
            TotpAlgo::Sha512,
            1585369775,
            TOTP_DEFAULT_STEP,
            Ok(587735),
        );
        do_test(
            vec![0x00, 0xaa, 0xbb, 0xcc],
            TotpAlgo::Sha512,
            1585369780,
            TOTP_DEFAULT_STEP,
            Ok(952181),
        );
    }

    #[test]
    fn totp_allow_one_previous() {
        let key = vec![0x00, 0xaa, 0xbb, 0xcc];
        let secs = 1585369780;
        let otp = Totp::new(key.clone(), TOTP_DEFAULT_STEP, TotpAlgo::Sha512);
        let d = Duration::from_secs(secs);
        // Step
        assert!(otp.verify(952181, &d));
        // Step - 1
        assert!(otp.verify(685469, &d));
        // This is step - 2
        assert!(!otp.verify(217213, &d));
        // This is step + 1
        assert!(!otp.verify(972806, &d));
    }
}

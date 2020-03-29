use crate::be::dbvalue::DbTotpV1;
use base32;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use rand::prelude::*;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::time::{Duration, SystemTime};

// This is 64 bits of entropy, as the examples in https://tools.ietf.org/html/rfc6238 show.
const SECRET_SIZE_BYTES: usize = 8;
pub const TOTP_DEFAULT_STEP: u64 = 60;

#[derive(Debug, PartialEq)]
pub enum TOTPError {
    OpenSSLError,
    HmacError,
    TimeError,
}

#[derive(Debug, Clone)]
pub enum TOTPAlgo {
    Sha1,
    Sha256,
    Sha512,
}

impl TOTPAlgo {
    pub(crate) fn digest(&self, key: &[u8], counter: u64) -> Result<Vec<u8>, TOTPError> {
        let key = PKey::hmac(key).map_err(|_e| TOTPError::OpenSSLError)?;
        let mut signer =
            match self {
                TOTPAlgo::Sha1 => Signer::new(MessageDigest::sha1(), &key)
                    .map_err(|_e| TOTPError::OpenSSLError)?,
                TOTPAlgo::Sha256 => Signer::new(MessageDigest::sha256(), &key)
                    .map_err(|_e| TOTPError::OpenSSLError)?,
                TOTPAlgo::Sha512 => Signer::new(MessageDigest::sha512(), &key)
                    .map_err(|_e| TOTPError::OpenSSLError)?,
            };
        signer
            .update(&counter.to_be_bytes())
            .map_err(|_e| TOTPError::OpenSSLError)?;
        let hmac = signer.sign_to_vec().map_err(|_e| TOTPError::OpenSSLError)?;

        let expect = match self {
            TOTPAlgo::Sha1 => 20,
            TOTPAlgo::Sha256 => 32,
            TOTPAlgo::Sha512 => 64,
        };
        if hmac.len() != expect {
            return Err(TOTPError::HmacError);
        }
        Ok(hmac)
    }

    pub(crate) fn to_string(&self) -> String {
        match self {
            TOTPAlgo::Sha1 => "SHA1",
            TOTPAlgo::Sha256 => "SHA256",
            TOTPAlgo::Sha512 => "SHA512",
        }
        .to_string()
    }
}

/// https://tools.ietf.org/html/rfc6238 which relies on https://tools.ietf.org/html/rfc4226
#[derive(Debug, Clone)]
pub struct TOTP {
    label: String,
    secret: Vec<u8>,
    step: u64,
    algo: TOTPAlgo,
}

impl TryFrom<DbTotpV1> for TOTP {
    type Error = ();

    fn try_from(_value: DbTotpV1) -> Result<Self, Self::Error> {
        unimplemented!();
    }
}

impl TOTP {
    pub fn new(label: String, secret: Vec<u8>, step: u64, algo: TOTPAlgo) -> Self {
        TOTP {
            label,
            secret,
            step,
            algo,
        }
    }

    // Create a new token with secure key and algo.
    pub fn generate_secure(label: String, step: u64) -> Self {
        let mut rng = rand::thread_rng();
        let secret: Vec<u8> = (0..SECRET_SIZE_BYTES).map(|_| rng.gen()).collect();
        let algo = TOTPAlgo::Sha512;
        TOTP {
            label,
            secret,
            step,
            algo,
        }
    }

    pub(crate) fn to_dbtotpv1(&self) -> DbTotpV1 {
        unimplemented!();
    }

    fn digest(&self, counter: u64) -> Result<u32, TOTPError> {
        let hmac = self.algo.digest(&self.secret, counter)?;
        // Now take the hmac and encode it as hotp expects.
        // https://tools.ietf.org/html/rfc4226#page-7
        let offset = hmac
            .last()
            .map(|v| (v & 0xf) as usize)
            .ok_or(TOTPError::HmacError)?;
        let bytes: [u8; 4] = hmac[offset..offset + 4]
            .try_into()
            .map_err(|_| TOTPError::HmacError)?;

        let otp = u32::from_be_bytes(bytes);
        Ok((otp & 0x7fffffff) % 1_000_000)
    }

    pub fn do_totp_duration_from_epoch(&self, time: &Duration) -> Result<u32, TOTPError> {
        let secs = time.as_secs();
        // do the window calculation
        let counter = secs / self.step;
        self.digest(counter)
    }

    pub fn do_totp(&self, time: &SystemTime) -> Result<u32, TOTPError> {
        let dur = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TOTPError::TimeError)?;
        self.do_totp_duration_from_epoch(&dur)
    }

    pub fn verify(&self, chal: u32, time: &Duration) -> bool {
        // Any error becomes a failure.
        match self.do_totp_duration_from_epoch(time) {
            Ok(v) => v == chal,
            Err(_) => false,
        }
    }

    /// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    pub fn to_string(&self, accountname: &str, issuer: &str) -> String {
        // label = accountname / issuer (“:” / “%3A”) *”%20” accountname
        let accountname = accountname
            .replace(":", "")
            .replace("%3A", "")
            .replace(" ", "%20");
        let issuer = issuer
            .replace(":", "")
            .replace("%3A", "")
            .replace(" ", "%20");
        let label = format!("{}:{}", issuer, accountname);
        let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.secret);
        let algo = self.algo.to_string();
        let period = self.step;
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits=6&period={}",
            label, secret, issuer, algo, period
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::totp::{TOTPAlgo, TOTPError, TOTP};
    use std::time::Duration;

    #[test]
    fn hotp_basic() {
        let otp_sha1 = TOTP::new("".to_string(), vec![0], 30, TOTPAlgo::Sha1);
        assert!(otp_sha1.digest(0) == Ok(328482));
        let otp_sha256 = TOTP::new("".to_string(), vec![0], 30, TOTPAlgo::Sha256);
        assert!(otp_sha256.digest(0) == Ok(356306));
        let otp_sha512 = TOTP::new("".to_string(), vec![0], 30, TOTPAlgo::Sha512);
        assert!(otp_sha512.digest(0) == Ok(674061));
    }

    fn do_test(key: Vec<u8>, algo: TOTPAlgo, secs: u64, step: u64, expect: Result<u32, TOTPError>) {
        let otp = TOTP::new("".to_string(), key.clone(), step, algo.clone());
        let d = Duration::from_secs(secs);
        let r = otp.do_totp_duration_from_epoch(&d);
        println!(
            "key: {:?}, algo: {:?}, time: {:?}, step: {:?}, expect: {:?} == {:?}",
            key, algo, secs, step, expect, r
        );
        assert!(r == expect);
    }

    #[test]
    fn totp_sha1_vectors() {
        do_test(
            vec![0x00, 0x00, 0x00, 0x00],
            TOTPAlgo::Sha1,
            1585368920,
            30,
            Ok(728926),
        );
        do_test(
            vec![0x00, 0xaa, 0xbb, 0xcc],
            TOTPAlgo::Sha1,
            1585369498,
            30,
            Ok(985074),
        );
    }

    #[test]
    fn totp_sha256_vectors() {
        do_test(
            vec![0x00, 0x00, 0x00, 0x00],
            TOTPAlgo::Sha256,
            1585369682,
            30,
            Ok(795483),
        );
        do_test(
            vec![0x00, 0xaa, 0xbb, 0xcc],
            TOTPAlgo::Sha256,
            1585369689,
            30,
            Ok(728402),
        );
    }

    #[test]
    fn totp_sha512_vectors() {
        do_test(
            vec![0x00, 0x00, 0x00, 0x00],
            TOTPAlgo::Sha512,
            1585369775,
            30,
            Ok(587735),
        );
        do_test(
            vec![0x00, 0xaa, 0xbb, 0xcc],
            TOTPAlgo::Sha512,
            1585369780,
            30,
            Ok(952181),
        );
    }

    #[test]
    fn totp_to_string() {
        let totp = TOTP::new(
            "".to_string(),
            vec![0xaa, 0xbb, 0xcc, 0xdd],
            30,
            TOTPAlgo::Sha256,
        );
        let s = totp.to_string("william", "blackhats");
        assert!(s == "otpauth://totp/blackhats:william?secret=VK54ZXI&issuer=blackhats&algorithm=SHA256&digits=6&period=30");

        // check that invalid issuer/accounts are cleaned up.
        let totp = TOTP::new(
            "".to_string(),
            vec![0xaa, 0xbb, 0xcc, 0xdd],
            30,
            TOTPAlgo::Sha256,
        );
        let s = totp.to_string("william:%3A", "blackhats australia");
        assert!(s == "otpauth://totp/blackhats%20australia:william?secret=VK54ZXI&issuer=blackhats%20australia&algorithm=SHA256&digits=6&period=30");
    }
}

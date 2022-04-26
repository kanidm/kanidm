use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs::proto::{COSEKey, UserVerificationPolicy};

#[derive(Serialize, Deserialize, Debug)]
pub struct DbCidV1 {
    #[serde(rename = "d")]
    pub domain_id: Uuid,
    #[serde(rename = "s")]
    pub server_id: Uuid,
    #[serde(rename = "t")]
    pub timestamp: Duration,
}

#[derive(Serialize, Deserialize)]
pub enum DbPasswordV1 {
    PBKDF2(usize, Vec<u8>, Vec<u8>),
    SSHA512(Vec<u8>, Vec<u8>),
}

impl std::fmt::Debug for DbPasswordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DbPasswordV1::PBKDF2(_, _, _) => write!(f, "PBKDF2"),
            DbPasswordV1::SSHA512(_, _) => write!(f, "SSHA512"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbValueIntentTokenStateV1 {
    V,
    P(Uuid, Duration),
    C,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbTotpAlgoV1 {
    S1,
    S256,
    S512,
}

#[derive(Serialize, Deserialize)]
pub struct DbTotpV1 {
    #[serde(rename = "l")]
    pub label: String,
    #[serde(rename = "k")]
    pub key: Vec<u8>,
    #[serde(rename = "s")]
    pub step: u64,
    #[serde(rename = "a")]
    pub algo: DbTotpAlgoV1,
}

impl std::fmt::Debug for DbTotpV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("DbTotpV1")
            .field("label", &self.label)
            .field("step", &self.step)
            .field("algo", &self.algo)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbWebauthnV1 {
    #[serde(rename = "l")]
    pub label: String,
    #[serde(rename = "i")]
    pub id: Vec<u8>,
    #[serde(rename = "c")]
    pub cred: COSEKey,
    #[serde(rename = "t")]
    pub counter: u32,
    #[serde(rename = "v")]
    pub verified: bool,
    #[serde(rename = "p", default)]
    pub registration_policy: UserVerificationPolicy,
}

#[derive(Serialize, Deserialize)]
pub struct DbBackupCodeV1 {
    pub code_set: HashSet<String>, // has to use std::HashSet for serde
}

impl std::fmt::Debug for DbBackupCodeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "codes remaining: {}", self.code_set.len())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbCredTypeV1 {
    Pw,
    GPw,
    PwMfa,
    // PwWn,
    Wn,
    // WnVer,
    // PwWnVer,
}

// We have to allow this as serde expects &T for the fn sig.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !b
}

fn dbcred_type_default_pw() -> DbCredTypeV1 {
    DbCredTypeV1::Pw
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbCredV1 {
    #[serde(default = "dbcred_type_default_pw")]
    pub type_: DbCredTypeV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<DbPasswordV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<Vec<DbWebauthnV1>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<DbTotpV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_code: Option<DbBackupCodeV1>,
    pub claims: Vec<String>,
    pub uuid: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueCredV1 {
    #[serde(rename = "t")]
    pub tag: String,
    #[serde(rename = "d")]
    pub data: DbCredV1,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueTaggedStringV1 {
    #[serde(rename = "t")]
    pub tag: String,
    #[serde(rename = "d")]
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueEmailAddressV1 {
    pub d: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub p: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValuePhoneNumberV1 {
    pub d: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub p: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueAddressV1 {
    #[serde(rename = "f")]
    pub formatted: String,
    #[serde(rename = "s")]
    pub street_address: String,
    #[serde(rename = "l")]
    pub locality: String,
    #[serde(rename = "r")]
    pub region: String,
    #[serde(rename = "p")]
    pub postal_code: String,
    #[serde(rename = "c")]
    pub country: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueOauthScopeMapV1 {
    #[serde(rename = "u")]
    pub refer: Uuid,
    #[serde(rename = "m")]
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbValueV1 {
    #[serde(rename = "U8")]
    Utf8(String),
    #[serde(rename = "I8")]
    Iutf8(String),
    #[serde(rename = "N8")]
    Iname(String),
    #[serde(rename = "UU")]
    Uuid(Uuid),
    #[serde(rename = "BO")]
    Bool(bool),
    #[serde(rename = "SY")]
    SyntaxType(usize),
    #[serde(rename = "IN")]
    IndexType(usize),
    #[serde(rename = "RF")]
    Reference(Uuid),
    #[serde(rename = "JF")]
    JsonFilter(String),
    #[serde(rename = "CR")]
    Credential(DbValueCredV1),
    #[serde(rename = "RU")]
    SecretValue(String),
    #[serde(rename = "SK")]
    SshKey(DbValueTaggedStringV1),
    #[serde(rename = "SP")]
    Spn(String, String),
    #[serde(rename = "UI")]
    Uint32(u32),
    #[serde(rename = "CI")]
    Cid(DbCidV1),
    #[serde(rename = "NU")]
    NsUniqueId(String),
    #[serde(rename = "DT")]
    DateTime(String),
    #[serde(rename = "EM")]
    EmailAddress(DbValueEmailAddressV1),
    #[serde(rename = "PN")]
    PhoneNumber(DbValuePhoneNumberV1),
    #[serde(rename = "AD")]
    Address(DbValueAddressV1),
    #[serde(rename = "UR")]
    Url(Url),
    #[serde(rename = "OS")]
    OauthScope(String),
    #[serde(rename = "OM")]
    OauthScopeMap(DbValueOauthScopeMapV1),
    #[serde(rename = "E2")]
    PrivateBinary(Vec<u8>),
    #[serde(rename = "PB")]
    PublicBinary(String, Vec<u8>),
    #[serde(rename = "RS")]
    RestrictedString(String),
    #[serde(rename = "IT")]
    IntentToken {
        u: Uuid,
        s: DbValueIntentTokenStateV1,
    },
    #[serde(rename = "TE")]
    TrustedDeviceEnrollment { u: Uuid },
    #[serde(rename = "AS")]
    AuthSession { u: Uuid },
}

#[cfg(test)]
mod tests {
    use crate::be::dbvalue::DbCredV1;

    #[test]
    fn test_dbcred_pre_totp_decode() {
        // This test exists to prove that the previous dbcredv1 format (without totp)
        // can still decode into the updated dbcredv1 that does have a TOTP field.
        /*
        let dbcred = DbCredV1 {
            password: Some(DbPasswordV1::PBKDF2(0, vec![0], vec![0])),
            claims: vec![],
            uuid: Uuid::new_v4(),
        };
        let data = serde_cbor::to_vec(&dbcred).unwrap();
        let s = base64::encode(data);
        */
        let s = "o2hwYXNzd29yZKFmUEJLREYygwCBAIEAZmNsYWltc4BkdXVpZFAjkHFm4q5M86UcNRi4hBjN";
        let data = base64::decode(s).unwrap();
        let _dbcred: DbCredV1 = serde_cbor::from_slice(data.as_slice()).unwrap();
    }
}

use std::time::Duration;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct DbCidV1 {
    pub d: Uuid,
    pub s: Uuid,
    pub t: Duration,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbPasswordV1 {
    PBKDF2(usize, Vec<u8>, Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbTotpAlgoV1 {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbTotpV1 {
    pub l: String,
    pub k: Vec<u8>,
    pub s: u64,
    pub a: DbTotpAlgoV1,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbCredV1 {
    pub password: Option<DbPasswordV1>,
    pub totp: Option<DbTotpV1>,
    pub claims: Vec<String>,
    pub uuid: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueCredV1 {
    pub t: String,
    pub d: DbCredV1,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueTaggedStringV1 {
    pub t: String,
    pub d: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbValueV1 {
    U8(String),
    I8(String),
    UU(Uuid),
    BO(bool),
    SY(usize),
    IN(usize),
    RF(Uuid),
    JF(String),
    CR(DbValueCredV1),
    RU(String),
    SK(DbValueTaggedStringV1),
    SP(String, String),
    UI(u32),
    CI(DbCidV1),
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

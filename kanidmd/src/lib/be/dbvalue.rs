use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub enum DbPasswordV1 {
    PBKDF2(usize, Vec<u8>, Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbCredV1 {
    pub password: Option<DbPasswordV1>,
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
}

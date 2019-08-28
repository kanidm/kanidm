use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct DbValueCredV1 {}

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
}

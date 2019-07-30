use crate::be::dbvalue::DbValueV1;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct DbEntryV1 {
    pub attrs: BTreeMap<String, Vec<DbValueV1>>,
}

// REMEMBER: If you add a new version here, you MUST
// update entry.rs into_dbentry to export to the latest
// type always!!
#[derive(Serialize, Deserialize, Debug)]
pub enum DbEntryVers {
    V1(DbEntryV1),
}

// This is actually what we store into the DB.
#[derive(Serialize, Deserialize, Debug)]
pub struct DbEntry {
    pub ent: DbEntryVers,
}

use crate::be::dbvalue::DbValueV1;
use serde::{Deserialize, Serialize};
use smartstring::alias::String as AttrString;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct DbEntryV1 {
    pub attrs: BTreeMap<AttrString, Vec<DbValueV1>>,
}

// REMEMBER: If you add a new version here, you MUST
// update entry.rs into_dbentry to export to the latest
// type always!!
#[derive(Serialize, Deserialize, Debug)]
pub enum DbEntryVers {
    V1(DbEntryV1),
}

// This is actually what we store into the DB.
#[derive(Serialize, Deserialize)]
pub struct DbEntry {
    pub ent: DbEntryVers,
}

impl std::fmt::Debug for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V1(dbe_v1) => {
                write!(f, "v1 - {{ ")?;
                for (k, vs) in dbe_v1.attrs.iter() {
                    write!(f, "{} - [", k)?;
                    for v in vs {
                        write!(f, "{:?}, ", v)?;
                    }
                    write!(f, "], ")?;
                }
                write!(f, "}}")
            }
        }
    }
}

impl std::fmt::Display for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V1(dbe_v1) => {
                write!(f, "v1 - {{ ")?;
                match dbe_v1.attrs.get("uuid") {
                    Some(uuids) => {
                        for uuid in uuids {
                            write!(f, "{:?}, ", uuid)?;
                        }
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };
                if let Some(names) = dbe_v1.attrs.get("name") {
                    for name in names {
                        write!(f, "{:?}, ", name)?;
                    }
                }
                if let Some(names) = dbe_v1.attrs.get("attributename") {
                    for name in names {
                        write!(f, "{:?}, ", name)?;
                    }
                }
                if let Some(names) = dbe_v1.attrs.get("classname") {
                    for name in names {
                        write!(f, "{:?}, ", name)?;
                    }
                }
                write!(f, "}}")
            }
        }
    }
}

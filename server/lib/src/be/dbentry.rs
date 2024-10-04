use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::dbrepl::{DbEntryChangeState, DbReplMeta};
use super::dbvalue::DbValueSetV2;
use super::keystorage::{KeyHandle, KeyHandleId};
use crate::prelude::entries::Attribute;

// REMEMBER: If you add a new version here, you MUST
// update entry.rs to_dbentry to export to the latest
// type always!!
#[derive(Serialize, Deserialize, Debug)]
pub enum DbEntryVers {
    V3 {
        changestate: DbEntryChangeState,
        attrs: BTreeMap<Attribute, DbValueSetV2>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
// This doesn't need a version since uuid2spn is reindexed - remember if you change this
// though, to change the index version!
pub enum DbIdentSpn {
    #[serde(rename = "SP")]
    Spn(String, String),
    #[serde(rename = "N8")]
    Iname(String),
    #[serde(rename = "UU")]
    Uuid(Uuid),
}

// This is actually what we store into the DB.
#[derive(Serialize, Deserialize)]
pub struct DbEntry {
    pub ent: DbEntryVers,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DbBackup {
    // Because of untagged, this has to be in order of newest
    // to oldest as untagged does a first-match when deserialising.
    V5 {
        version: String,
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
        repl_meta: DbReplMeta,
        entries: Vec<DbEntry>,
    },
    V4 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
        repl_meta: DbReplMeta,
        entries: Vec<DbEntry>,
    },
    V3 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
        entries: Vec<DbEntry>,
    },
    V2 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        entries: Vec<DbEntry>,
    },
    V1(Vec<DbEntry>),
}

impl std::fmt::Debug for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                write!(f, "v3 - {{ ")?;
                match changestate {
                    DbEntryChangeState::V1Live { at, changes } => {
                        writeln!(f, "\nlive {at:>32}")?;
                        for (attr, cid) in changes {
                            write!(f, "\n{attr:>32} - {cid} ")?;
                            if let Some(vs) = attrs.get(attr) {
                                write!(f, "{vs:?}")?;
                            } else {
                                write!(f, "-")?;
                            }
                        }
                    }
                    DbEntryChangeState::V1Tombstone { at } => {
                        writeln!(f, "\ntombstone {at:>32?}")?;
                    }
                }
                write!(f, "\n        }}")
            }
        }
    }
}

impl std::fmt::Display for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                write!(f, "v3 - {{ ")?;
                match attrs.get(&Attribute::Uuid) {
                    Some(uuids) => {
                        write!(f, "{uuids:?}, ")?;
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };

                match changestate {
                    DbEntryChangeState::V1Live { at, changes: _ } => {
                        write!(f, "created: {at}, ")?;
                        if let Some(names) = attrs.get(&Attribute::Name) {
                            write!(f, "{names:?}, ")?;
                        }
                        if let Some(names) = attrs.get(&Attribute::AttributeName) {
                            write!(f, "{names:?}, ")?;
                        }
                        if let Some(names) = attrs.get(&Attribute::ClassName) {
                            write!(f, "{names:?}, ")?;
                        }
                    }
                    DbEntryChangeState::V1Tombstone { at } => {
                        write!(f, "tombstoned: {at}, ")?;
                    }
                }
                write!(f, "}}")
            }
        }
    }
}

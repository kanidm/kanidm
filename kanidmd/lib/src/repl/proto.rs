use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplCidV1 {}

// From / Into CID

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplAttrV1 {

}

// From / Into ValueSet

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplAttrStateV1 {
    cid: ReplCidV1,
    attr: Option<ReplAttrV1>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplStateV1 {
    Live {
        attrs: BTreeMap<String, ReplAttrStateV1>,
    },
    Tombstone {
        at: ReplCidV1,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
// This can be a partial entry too
pub struct ReplEntryV1 {
    uuid: Uuid,
    // Change State
    st: ReplStateV1,
}

impl From<&EntrySealedCommitted> for ReplEntryV1 {
    fn from(entry: &EntrySealedCommitted) -> ReplEntryV1 {
        let cs = entry.get_changestate();

        if cs.is_live() {
            let attrs = entry.get_ava_iter();
            todo!();
        } else {
            todo!();
        }
    }
}

impl Into<EntryInvalidNew> for &ReplEntryV1 {
    fn into(self) -> EntryInvalidNew {
        todo!();
    }
}

// From / Into Entry

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReplRefreshContext {
    V1 {
        domain_version: DomainVersion,
        domain_uuid: Uuid,
        schema_entries: Vec<ReplEntryV1>,
        meta_entries: Vec<ReplEntryV1>,
        entries: Vec<ReplEntryV1>,
    },
}

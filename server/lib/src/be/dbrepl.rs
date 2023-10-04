use super::dbvalue::DbCidV1;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum DbEntryChangeState {
    V1Live {
        at: DbCidV1,
        changes: BTreeMap<String, DbCidV1>,
    },
    V1Tombstone {
        at: DbCidV1,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbReplMeta {
    V1 { ruv: BTreeSet<DbCidV1> },
}

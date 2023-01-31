use super::cid::Cid;
use crate::entry::Eattrs;
use crate::prelude::*;
use crate::schema::SchemaTransaction;
// use crate::valueset;

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum State {
    Live { changes: BTreeMap<AttrString, Cid> },
    Tombstone { at: Cid },
}

#[derive(Debug, Clone)]
pub struct EntryChangeState {
    st: State,
}

impl EntryChangeState {
    pub fn new(cid: &Cid, attrs: &Eattrs, _schema: &dyn SchemaTransaction) -> Self {
        let changes = attrs
            .keys()
            .cloned()
            .map(|attr| (attr, cid.clone()))
            .collect();

        let st = State::Live { changes };

        EntryChangeState { st }
    }

    pub fn new_without_schema(cid: &Cid, attrs: &Eattrs) -> Self {
        let class = attrs.get("class");
        let st = if class
            .as_ref()
            .map(|c| c.contains(&PVCLASS_TOMBSTONE as &PartialValue))
            .unwrap_or(false)
        {
            State::Tombstone { at: cid.clone() }
        } else {
            let changes = attrs
                .keys()
                .cloned()
                .map(|attr| (attr, cid.clone()))
                .collect();

            State::Live { changes }
        };

        EntryChangeState { st }
    }

    pub fn change_ava(&mut self, cid: &Cid, attr: &str) {
        match &mut self.st {
            State::Live { ref mut changes } => {
                if let Some(change) = changes.get_mut(attr) {
                    // Update the cid.
                    if change != cid {
                        *change = cid.clone()
                    }
                } else {
                    changes.insert(attr.into(), cid.clone());
                }
            }
            State::Tombstone { .. } => {
                assert!(false)
            }
        }
    }

    pub fn tombstone(&mut self, cid: &Cid) {
        match &mut self.st {
            State::Live { changes: _ } => self.st = State::Tombstone { at: cid.clone() },
            State::Tombstone { .. } => {} // no-op
        };
    }

    pub fn can_delete(&self, cid: &Cid) -> bool {
        match &self.st {
            State::Live { .. } => false,
            State::Tombstone { at } => at < cid,
        }
    }

    pub fn is_live(&self) -> bool {
        match &self.st {
            State::Live { .. } => true,
            State::Tombstone { .. } => false,
        }
    }

    pub fn contains_tail_cid(&self, cid: &Cid) -> bool {
        // This is slow? Is it needed?
        match &self.st {
            State::Live { changes } => changes.values().any(|change| change == cid),
            State::Tombstone { at } => at == cid,
        }
    }

    pub fn cid_iter(&self) -> Vec<&Cid> {
        // Not deduped, not ordered!
        match &self.st {
            State::Live { changes } => {
                let mut v: Vec<_> = changes.values().collect();
                v.sort_unstable();
                v.dedup();
                v
            }
            State::Tombstone { at } => vec![&at],
        }
    }

    #[instrument(level = "trace", name = "verify", skip_all)]
    pub fn verify(
        &self,
        _schema: &dyn SchemaTransaction,
        _expected_attrs: &Eattrs,
        _entry_id: u64,
        _results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        todo!();
    }
}

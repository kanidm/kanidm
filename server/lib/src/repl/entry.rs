use super::cid::Cid;
use crate::entry::Eattrs;
use crate::prelude::*;
use crate::schema::SchemaTransaction;
// use crate::valueset;

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum State {
    Live { changes: BTreeMap<AttrString, Cid> },
    Tombstone { at: Cid },
}

#[derive(Debug, Clone)]
pub struct EntryChangeState {
    pub(super) st: State,
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

    pub fn current(&self) -> &State {
        &self.st
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
                unreachable!();
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
        match &self.st {
            State::Live { changes } => {
                let mut v: Vec<_> = changes.values().collect();
                v.sort_unstable();
                v.dedup();
                v
            }
            State::Tombstone { at } => vec![at],
        }
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&AttrString, &mut Cid) -> bool,
    {
        match &mut self.st {
            State::Live { changes } => changes.retain(f),
            State::Tombstone { .. } => {}
        }
    }

    #[instrument(level = "trace", name = "verify", skip_all)]
    pub fn verify(
        &self,
        schema: &dyn SchemaTransaction,
        expected_attrs: &Eattrs,
        entry_id: u64,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        let class = expected_attrs.get("class");
        let is_ts = class
            .as_ref()
            .map(|c| c.contains(&PVCLASS_TOMBSTONE as &PartialValue))
            .unwrap_or(false);

        match (&self.st, is_ts) {
            (State::Live { changes }, false) => {
                // Check that all attrs from expected, have a value in our changes.
                let inconsistent: Vec<_> = expected_attrs
                    .keys()
                    .filter(|attr| {
                        /*
                         * If the attribute is a replicated attribute, and it is NOT present
                         * in the change state then we are in a desync state.
                         *
                         * However, we don't check the inverse - if an entry is in the change state
                         * but is NOT replicated by schema. This is because there is is a way to
                         * delete an attribute in schema which will then prevent future replications
                         * of that value. However the value, while not being updated, will retain
                         * a state entry in the change state.
                         *
                         * For the entry to then be replicated once more, it would require it's schema
                         * attributes to be re-added and then the replication will resume from whatever
                         * receives the changes first. Generally there are lots of desync and edge
                         * cases here, which is why we pretty much don't allow schema to be deleted
                         * but we have to handle it here due to a test case that simulates this.
                         */
                        let desync = schema.is_replicated(attr) && !changes.contains_key(*attr);
                        if desync {
                            debug!(%entry_id, %attr, %desync);
                        }
                        desync
                    })
                    .collect();

                if inconsistent.is_empty() {
                    trace!("changestate is synchronised");
                } else {
                    warn!("changestate has desynchronised! Missing state attrs {inconsistent:?}");
                    results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
                }
            }
            (State::Tombstone { .. }, true) => {
                trace!("changestate is synchronised");
            }
            (State::Live { .. }, true) => {
                warn!("changestate has desynchronised! State Live when tombstone is true");
                results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
            }
            (State::Tombstone { .. }, false) => {
                warn!("changestate has desynchronised! State Tombstone when tombstone is false");
                results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
            }
        }
    }
}

impl PartialEq for EntryChangeState {
    fn eq(&self, rhs: &Self) -> bool {
        match (&self.st, &rhs.st) {
            (
                State::Live {
                    changes: changes_left,
                },
                State::Live {
                    changes: changes_right,
                },
            ) => changes_left.eq(changes_right),
            (State::Tombstone { at: at_left }, State::Tombstone { at: at_right }) => {
                at_left.eq(at_right)
            }
            (_, _) => false,
        }
    }
}

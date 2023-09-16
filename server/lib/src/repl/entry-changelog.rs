use std::collections::btree_map::Keys;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::ops::Bound::*;

use kanidm_proto::v1::ConsistencyError;

use super::cid::Cid;
use crate::entry::{compare_attrs, Eattrs};
use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::valueset;

#[derive(Debug, Clone)]
pub struct EntryChangelog {
    /// The set of "entries as they existed at a point in time". This allows us to rewind
    /// to a point-in-time, and then to start to "replay" applying all changes again.
    ///
    /// A subtle and important piece of information is that an anchor can be considered
    /// as the "state as existing between two Cid's". This means for Cid X, this state is
    /// the "moment before X". This is important, as for a create we define the initial anchor
    /// as "nothing". It's means for the anchor at time X, that changes that occurred at time
    /// X have NOT been replayed and applied!
    anchors: BTreeMap<Cid, State>,
    changes: BTreeMap<Cid, Change>,
}

/*
impl fmt::Display for EntryChangelog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f
    }
}
*/

/// A change defines the transitions that occurred within this Cid (transaction). A change is applied
/// as a whole, or rejected during the replay process.
#[derive(Debug, Clone)]
pub struct Change {
    s: Vec<Transition>,
}

#[derive(Debug, Clone)]
enum State {
    NonExistent,
    Live(Eattrs),
    Recycled(Eattrs),
    Tombstone(Eattrs),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            State::NonExistent => write!(f, "NonExistent"),
            State::Live(_) => write!(f, "Live"),
            State::Recycled(_) => write!(f, "Recycled"),
            State::Tombstone(_) => write!(f, "Tombstone"),
        }
    }
}

#[derive(Debug, Clone)]
enum Transition {
    Create(Eattrs),
    ModifyPurge(AttrString),
    ModifyPresent(AttrString, Box<Value>),
    ModifyRemoved(AttrString, Box<PartialValue>),
    ModifyAssert(AttrString, Box<PartialValue>),
    Recycle,
    Revive,
    Tombstone(Eattrs),
}

impl fmt::Display for Transition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Transition::Create(_) => write!(f, "Create"),
            Transition::ModifyPurge(a) => write!(f, "ModifyPurge({})", a),
            Transition::ModifyPresent(a, _) => write!(f, "ModifyPresent({})", a),
            Transition::ModifyRemoved(a, _) => write!(f, "ModifyRemoved({})", a),
            Transition::ModifyAssert(a, _) => write!(f, "ModifyAssert({})", a),
            Transition::Recycle => write!(f, "Recycle"),
            Transition::Revive => write!(f, "Revive"),
            Transition::Tombstone(_) => write!(f, "Tombstone"),
        }
    }
}

impl State {
    fn apply_change(self, change: &Change) -> Result<Self, Self> {
        let mut state = self;
        for transition in change.s.iter() {
            match (&mut state, transition) {
                (State::NonExistent, Transition::Create(attrs)) => {
                    trace!("NonExistent + Create -> Live");
                    state = State::Live(attrs.clone());
                }
                (State::Live(ref mut attrs), Transition::ModifyPurge(attr)) => {
                    trace!("Live + ModifyPurge({}) -> Live", attr);
                    attrs.remove(attr);
                }
                (State::Live(ref mut attrs), Transition::ModifyPresent(attr, value)) => {
                    trace!("Live + ModifyPresent({}) -> Live", attr);
                    if let Some(vs) = attrs.get_mut(attr) {
                        let r = vs.insert_checked(value.as_ref().clone());
                        assert!(r.is_ok());
                        // Reject if it fails?
                    } else {
                        #[allow(clippy::expect_used)]
                        let vs = valueset::from_value_iter(std::iter::once(value.as_ref().clone()))
                            .expect("Unable to fail - always single value, and only one type!");
                        attrs.insert(attr.clone(), vs);
                    }
                }
                (State::Live(ref mut attrs), Transition::ModifyRemoved(attr, value)) => {
                    trace!("Live + ModifyRemoved({}) -> Live", attr);
                    let rm = if let Some(vs) = attrs.get_mut(attr) {
                        vs.remove(value);
                        vs.is_empty()
                    } else {
                        false
                    };
                    if rm {
                        attrs.remove(attr);
                    };
                }
                (State::Live(ref mut attrs), Transition::ModifyAssert(attr, value)) => {
                    trace!("Live + ModifyAssert({}) -> Live", attr);

                    if attrs
                        .get(attr)
                        .map(|vs| vs.contains(value))
                        .unwrap_or(false)
                    {
                        // Valid
                    } else {
                        warn!("{} + {:?} -> Assertion not met - REJECTING", attr, value);
                        return Err(state);
                    }
                }
                (State::Live(attrs), Transition::Recycle) => {
                    trace!("Live + Recycle -> Recycled");
                    state = State::Recycled(attrs.clone());
                }
                (State::Live(_), Transition::Tombstone(attrs)) => {
                    trace!("Live + Tombstone -> Tombstone");
                    state = State::Tombstone(attrs.clone());
                }
                (State::Recycled(attrs), Transition::Revive) => {
                    trace!("Recycled + Revive -> Live");
                    state = State::Live(attrs.clone());
                }
                (State::Recycled(ref mut attrs), Transition::ModifyPurge(attr)) => {
                    trace!("Recycled + ModifyPurge({}) -> Recycled", attr);
                    attrs.remove(attr);
                }
                (State::Recycled(attrs), Transition::ModifyRemoved(attr, value)) => {
                    trace!("Recycled + ModifyRemoved({}) -> Recycled", attr);
                    let rm = if let Some(vs) = attrs.get_mut(attr) {
                        vs.remove(value);
                        vs.is_empty()
                    } else {
                        false
                    };
                    if rm {
                        attrs.remove(attr);
                    };
                }
                (State::Recycled(_), Transition::Tombstone(attrs)) => {
                    trace!("Recycled + Tombstone -> Tombstone");
                    state = State::Tombstone(attrs.clone());
                }

                // ==============================
                // Invalid States
                /*
                (State::NonExistent, Transition::ModifyPurge(_))
                | (State::NonExistent, Transition::ModifyPresent(_, _))
                | (State::NonExistent, Transition::ModifyRemoved(_, _))
                | (State::NonExistent, Transition::Recycle)
                | (State::NonExistent, Transition::Revive)
                | (State::NonExistent, Transition::Tombstone(_))
                | (State::Live(_), Transition::Create(_))
                | (State::Live(_), Transition::Revive)
                | (State::Recycled(_), Transition::Create(_))
                | (State::Recycled(_), Transition::Recycle)
                | (State::Recycled(_), Transition::ModifyPresent(_, _))
                | (State::Tombstone(_), _)
                */
                (s, t) => {
                    warn!("{} + {} -> REJECTING", s, t);
                    return Err(state);
                }
            };
        }
        // Everything must have applied, all good then.
        trace!(?state, "applied changes");
        Ok(state)
    }
}

impl EntryChangelog {
    pub fn new(cid: Cid, attrs: Eattrs, _schema: &dyn SchemaTransaction) -> Self {
        // I think we need to reduce the attrs based on what is / is not replicated.?

        let anchors = btreemap![(cid.clone(), State::NonExistent)];
        let changes = btreemap![(
            cid,
            Change {
                s: vec![Transition::Create(attrs)]
            }
        )];

        EntryChangelog { anchors, changes }
    }

    // TODO: work out if the below comment about uncommenting is still valid
    // Uncomment this once we have a real on-disk storage of the changelog
    pub fn new_without_schema(cid: Cid, attrs: Eattrs) -> Self {
        // I think we need to reduce the attrs based on what is / is not replicated.?

        // We need to pick a state that reflects the current state WRT to tombstone
        // or recycled!
        let class = attrs.get(Attribute::Class.as_ref());

        let (anchors, changes) = if class
            .as_ref()
            .map(|c| c.contains(&EntryClass::Tombstone.to_partialvalue()))
            .unwrap_or(false)
        {
            (btreemap![(cid, State::Tombstone(attrs))], BTreeMap::new())
        } else if class
            .as_ref()
            .map(|c| c.contains(&EntryClass::Recycled.to_partialvalue()))
            .unwrap_or(false)
        {
            (btreemap![(cid, State::Recycled(attrs))], BTreeMap::new())
        } else {
            (
                btreemap![(cid.clone(), State::NonExistent)],
                btreemap![(
                    cid,
                    Change {
                        s: vec![Transition::Create(attrs)]
                    }
                )],
            )
        };

        EntryChangelog { anchors, changes }
    }

    // fn add_ava_iter<T>(&mut self, cid: &Cid, attr: Attribute, viter: T)
    // where
    //     T: IntoIterator<Item = Value>,
    // {
    //     if !self.changes.contains_key(cid) {
    //         self.changes.insert(cid.clone(), Change { s: Vec::new() });
    //     }

    //     #[allow(clippy::expect_used)]
    //     let change = self
    //         .changes
    //         .get_mut(cid)
    //         .expect("Memory corruption, change must exist");

    //     viter
    //         .into_iter()
    //         .map(|v| Transition::ModifyPresent(attr.into(), Box::new(v)))
    //         .for_each(|t| change.s.push(t));
    // }

    pub fn remove_ava_iter<T>(&mut self, cid: &Cid, attr: &str, viter: T)
    where
        T: IntoIterator<Item = PartialValue>,
    {
        if !self.changes.contains_key(cid) {
            self.changes.insert(cid.clone(), Change { s: Vec::new() });
        }

        #[allow(clippy::expect_used)]
        let change = self
            .changes
            .get_mut(cid)
            .expect("Memory corruption, change must exist");

        viter
            .into_iter()
            .map(|v| Transition::ModifyRemoved(AttrString::from(attr), Box::new(v)))
            .for_each(|t| change.s.push(t));
    }

    pub fn assert_ava(&mut self, cid: &Cid, attr: Attribute, value: PartialValue) {
        if !self.changes.contains_key(cid) {
            self.changes.insert(cid.clone(), Change { s: Vec::new() });
        }

        #[allow(clippy::expect_used)]
        let change = self
            .changes
            .get_mut(cid)
            .expect("Memory corruption, change must exist");

        change
            .s
            .push(Transition::ModifyAssert(attr.into(), Box::new(value)))
    }

    pub fn purge_ava(&mut self, cid: &Cid, attr: Attribute) {
        if !self.changes.contains_key(cid) {
            self.changes.insert(cid.clone(), Change { s: Vec::new() });
        }

        #[allow(clippy::expect_used)]
        let change = self
            .changes
            .get_mut(cid)
            .expect("Memory corruption, change must exist");
        change.s.push(Transition::ModifyPurge(attr.info()));
    }

    pub fn recycled(&mut self, cid: &Cid) {
        if !self.changes.contains_key(cid) {
            self.changes.insert(cid.clone(), Change { s: Vec::new() });
        }

        #[allow(clippy::expect_used)]
        let change = self
            .changes
            .get_mut(cid)
            .expect("Memory corruption, change must exist");
        change.s.push(Transition::Recycle);
    }

    pub fn revive(&mut self, cid: &Cid) {
        if !self.changes.contains_key(cid) {
            self.changes.insert(cid.clone(), Change { s: Vec::new() });
        }

        #[allow(clippy::expect_used)]
        let change = self
            .changes
            .get_mut(cid)
            .expect("Memory corruption, change must exist");
        change.s.push(Transition::Revive);
    }

    pub fn tombstone(&mut self, cid: &Cid, attrs: Eattrs) {
        if !self.changes.contains_key(cid) {
            self.changes.insert(cid.clone(), Change { s: Vec::new() });
        }

        #[allow(clippy::expect_used)]
        let change = self
            .changes
            .get_mut(cid)
            .expect("Memory corruption, change must exist");
        change.s.push(Transition::Tombstone(attrs));
    }

    /// Replay our changes from and including the replay Cid, up to the latest point
    /// in time. We also return a vector of *rejected* Cid's showing what is in the
    /// change log that is considered invalid.
    fn replay(
        &self,
        from_cid: Bound<&Cid>,
        to_cid: Bound<&Cid>,
    ) -> Result<(State, Vec<Cid>), OperationError> {
        // Select the anchor_cid that is *earlier* or *equals* to the replay_cid.

        // if not found, we are *unable to* perform this replay which indicates a problem!
        let (anchor_cid, anchor) = if matches!(from_cid, Unbounded) {
            // If the from is unbounded, and to is unbounded, we want
            // the earliest anchor possible.

            // If from is unbounded and to is bounded, we want the earliest
            // possible.
            self.anchors.iter().next()
        } else {
            // If from has a bound, we want an anchor "earlier than" from, regardless
            // of the to bound state.
            self.anchors.range((Unbounded, from_cid)).next_back()
        }
        .ok_or_else(|| {
            admin_error!(
                ?from_cid,
                ?to_cid,
                "Failed to locate anchor in replay range"
            );
            OperationError::ReplReplayFailure
        })?;

        trace!(?anchor_cid, ?anchor);

        // Load the entry attribute state at that time.
        let mut replay_state = anchor.clone();
        let mut rejected_cid = Vec::new();

        // For each change
        for (change_cid, change) in self.changes.range((Included(anchor_cid), to_cid)) {
            // Apply the change.
            trace!(?change_cid, ?change);

            replay_state = match replay_state.apply_change(change) {
                Ok(mut new_state) => {
                    // Indicate that this was the highest CID so far.
                    match &mut new_state {
                        State::NonExistent => {
                            trace!("pass");
                        }
                        State::Live(ref mut attrs)
                        | State::Recycled(ref mut attrs)
                        | State::Tombstone(ref mut attrs) => {
                            let cv = vs_cid![change_cid.clone()];
                            let _ = attrs.insert(Attribute::LastModifiedCid.into(), cv);
                        }
                    };
                    new_state
                }
                Err(previous_state) => {
                    warn!("rejecting invalid change {:?}", change_cid);
                    rejected_cid.push(change_cid.clone());
                    previous_state
                }
            };
        }

        // Return the eattrs state.
        Ok((replay_state, rejected_cid))
    }

    #[instrument(
        level = "trace",
        name = "verify",
        skip(self, _schema, expected_attrs, results)
    )]
    pub fn verify(
        &self,
        _schema: &dyn SchemaTransaction,
        expected_attrs: &Eattrs,
        entry_id: u64,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        // We need to be able to take any anchor entry, and replay that when all changes
        // are applied we get the *same entry* as the current state.
        debug_assert!(results.is_empty());

        // For each anchor (we only needs it's change id.)
        for cid in self.anchors.keys() {
            match self.replay(Included(cid), Unbounded) {
                Ok((entry_state, rejected)) => {
                    trace!(?rejected);

                    match entry_state {
                        State::Live(attrs) | State::Recycled(attrs) | State::Tombstone(attrs) => {
                            if compare_attrs(&attrs, expected_attrs) {
                                // valid
                                trace!("changelog is synchronised");
                            } else {
                                // ruh-roh.
                                warn!("changelog has desynchronised!");
                                debug!(?attrs);
                                debug!(?expected_attrs);
                                debug_assert!(false);
                                results
                                    .push(Err(ConsistencyError::ChangelogDesynchronised(entry_id)));
                            }
                        }
                        State::NonExistent => {
                            warn!("entry does not exist - changelog is corrupted?!");
                            results.push(Err(ConsistencyError::ChangelogDesynchronised(entry_id)))
                        }
                    }
                }
                Err(e) => {
                    error!(?e);
                }
            }
        }

        debug_assert!(results.is_empty());
    }

    pub fn contains_tail_cid(&self, cid: &Cid) -> bool {
        if let Some(tail_cid) = self.changes.keys().next_back() {
            if tail_cid == cid {
                return true;
            }
        };
        false
    }

    pub fn can_delete(&self) -> bool {
        // Changelog should be empty.
        // should have a current anchor state of tombstone.
        self.changes.is_empty()
            && matches!(self.anchors.values().next_back(), Some(State::Tombstone(_)))
    }

    pub fn is_live(&self) -> bool {
        !matches!(self.anchors.values().next_back(), Some(State::Tombstone(_)))
    }

    pub fn cid_iter(&self) -> Keys<Cid, Change> {
        self.changes.keys()
    }

    /*
    fn insert_anchor(&mut self, cid: Cid, entry_state: State) {
        // When we insert an anchor, we have to remove all subsequent anchors (but not
        // the preceding ones.)
        let _ = self.anchors.split_off(&cid);
        self.anchors.insert(cid.clone(), entry_state);
    }
    */

    pub fn trim_up_to(&mut self, cid: &Cid) -> Result<(), OperationError> {
        // Build a new anchor that is equal or less than this cid.
        // In other words, the cid we are trimming to, should be remaining
        // in the CL, and we should have an anchor that precedes it.
        let (entry_state, rejected) = self.replay(Unbounded, Excluded(cid)).map_err(|e| {
            error!(?e);
            e
        })?;
        trace!(?rejected);
        // Add the entry_state as an anchor. Use the CID we just
        // trimmed to.

        // insert_anchor will remove anything to the right, we also need to
        // remove everything to the left, so just clear.
        self.anchors.clear();
        self.anchors.insert(cid.clone(), entry_state);

        // And now split the CL.
        let mut right = self.changes.split_off(cid);
        std::mem::swap(&mut right, &mut self.changes);
        // We can trace what we drop later?
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::entry::Eattrs;
    // use crate::prelude::*;
    use crate::repl::cid::Cid;
    use crate::repl::entry::{Change, EntryChangelog, State, Transition};
    use crate::schema::{Schema, SchemaTransaction};

    #[cfg(test)]
    macro_rules! run_entrychangelog_test {
        ($test_fn:expr) => {{
            let _ = sketching::test_init();
            let schema_outer = Schema::new().expect("Failed to init schema");

            let schema_txn = schema_outer.read();

            $test_fn(&schema_txn)
        }};
    }

    #[test]
    fn test_entrychangelog_basic() {
        run_entrychangelog_test!(|schema: &dyn SchemaTransaction| {
            let cid = Cid::new_random_s_d(Duration::from_secs(1));
            let eattrs = Eattrs::new();
            let eclog = EntryChangelog::new(cid, eattrs, schema);
            trace!(?eclog);
        })
    }

    #[test]
    fn test_entrychangelog_state_transitions() {
        // Test that all our transitions are defined and work as
        // expected.
        assert!(State::NonExistent
            .apply_change(&Change { s: vec![] })
            .is_ok());
        assert!(State::NonExistent
            .apply_change(&Change {
                s: vec![Transition::Create(Eattrs::new())]
            })
            .is_ok());

        assert!(State::Live(Eattrs::new())
            .apply_change(&Change { s: vec![] })
            .is_ok());
        assert!(State::Live(Eattrs::new())
            .apply_change(&Change {
                s: vec![Transition::Create(Eattrs::new())]
            })
            .is_err());
    }
}

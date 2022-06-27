use super::cid::Cid;

use crate::entry::Eattrs;
use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone)]
pub struct EntryChangelog {
    /// The set of "entries as they existed at a point in time". This allows us to rewind
    /// to a point-in-time, and then to start to "rewind" and begin to apply changes again.
    ///
    /// A subtle and important piece of information is that an anchor can be considered
    /// as the "state as existing between two Cid's". This means for Cid X, this state is
    /// the "moment before X". This is important, as for a create we define the initial anchor
    /// as "nothing".
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

/// A change defines the transitions that occured within this Cid (transaction). A change is applied
/// as a whole, or rejected during the replay process.
#[derive(Debug, Clone)]
struct Change {
    s: Vec<Transition>,
}

#[derive(Debug, Clone)]
enum State {
    NonExistant,
    Live(Eattrs),
}

#[derive(Debug, Clone)]
enum Transition {
    Create(Eattrs),
}

impl EntryChangelog {
    pub fn new(cid: Cid, attrs: Eattrs, _schema: &dyn SchemaTransaction) -> Self {
        // I think we need to reduce the attrs based on what is / is not replicated.?

        let anchors = btreemap![(cid.clone(), State::NonExistant)];
        let changes = btreemap![(
            cid,
            Change {
                s: vec![Transition::Create(attrs)]
            }
        )];

        EntryChangelog { anchors, changes }
    }

    // Uncomment this once we have a real on-disk storage of the changelog
    // #[cfg(test)]
    pub fn new_without_schema(cid: Cid, attrs: Eattrs) -> Self {
        // I think we need to reduce the attrs based on what is / is not replicated.?

        let anchors = btreemap![(cid.clone(), State::NonExistant)];
        let changes = btreemap![(
            cid,
            Change {
                s: vec![Transition::Create(attrs)]
            }
        )];

        EntryChangelog { anchors, changes }
    }

    /// Replay our changes from and including the replay Cid, up to the latest point
    /// in time. We also return a vector of *rejected* Cid's showing what is in the
    /// change log that is considered invalid.
    pub fn replay(&self, replay_cid: Cid) -> Result<(Eattrs, Vec<Cid>), OperationError> {
        // Select the anchor_cid that is *earlier* or *equals* to the replay_cid.

        // Load the entry attribute state at that time.

        // For each change
        //  apply it!
        // Did it apply cleanly?

        // Return the eattrs state.
    }

    pub fn verify(
        &self,
        entry: &Entry<EntrySealed, EntryCommitted>,
        results: &mut Vec<Result<(), ConsistencyError>>
    ) {
        trace!("verifying changelog of -> {}", self.state.id);

        // We need to be able to take any anchor entry, and replay that when all changes
        // are applied we get the *same entry* as the current state.

        // For each anchor
        // replay
        // compare.
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::Eattrs;
    use crate::prelude::*;
    use crate::repl::cid::Cid;
    use crate::repl::entry::EntryChangelog;
    use crate::schema::{Schema, SchemaTransaction};
    use std::time::Duration;

    #[test]
    fn test_entrychangelog_basic() {
        run_entrychangelog_test!(|schema: &dyn SchemaTransaction| {
            let cid = Cid::new_random_s_d(Duration::from_secs(1));
            let eattrs = Eattrs::new();
            let eclog = EntryChangelog::new(cid, eattrs, schema);
            trace!(?eclog);
        })
    }
}

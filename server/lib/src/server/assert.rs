use crate::prelude::*;
use std::collections::{BTreeSet, BTreeMap};
// use crate::server::{ChangeFlag, Plugins};

pub enum AttributeAssertion {
    // The ValueSet must look exactly like this.
    Set ( ValueSet ),
    // The ValueSet must not be present.
    Absent,
    // TODO: We could in future add a "merge" style statement to this.
}

pub enum EntryAssertion {
    // Could do an assert variant to make an entry look *exactly* like this, but that
    // has a lot of potential risks with internal attributes.
    Present {
        target: Uuid,
        // Option ValueSet represents a removal.
        attrs: BTreeMap<Attribute, AttributeAssertion>,
    },
    Absent {
        target: Uuid,
    }
}

pub struct AssertEvent {
    pub ident: Identity,
    pub asserts: Vec<EntryAssertion>,
}

/*
enum Action {
}
*/

impl QueryServerWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    /// Document me please senpai.
    pub fn assert(&mut self, ae: &AssertEvent) -> Result<(), OperationError> {
        // Get all the UUID's from assert statements.
        let present_uuids: BTreeSet<Uuid> =
            ae.asserts.iter()
                .filter_map(|a| {
                    match a {
                        EntryAssertion::Present { target, .. } => Some(*target),
                        _ => None,
                    }
                })
                .collect();

        let absent_uuids: BTreeSet<Uuid> =
            ae.asserts.iter()
                .filter_map(|a| {
                    match a {
                        EntryAssertion::Absent { target } => Some(*target),
                        _ => None,
                    }
                })
                .collect();

        // Assert that there is no overlap.
        let duplicates: Vec<_> = present_uuids.intersection(&absent_uuids)
            .collect();

        if !duplicates.is_empty() {
            // error
            error!(?duplicates, "entry uuids in SCIM Assertion must be unique.");
            return Err(OperationError::SC0033AssertionContainsDuplicateUuids);
        }

        // Determine which exist.
        // TODO: Make an optimised uuid search in the BE to just get an IDL.
        let filter = filter!(
            f_or(present_uuids
                .iter()
                .copied()
                .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                .collect()
            )
        );

        let existing_uuids = self.internal_search(filter)?;

        let existing_uuids: BTreeMap

        // Break up the asserts then into sets of creates, mods and deletes.

        // Loop and apply.

        // Complete!


        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    // use std::sync::Arc;

    #[qs_test]
    async fn test_entry_asserts(server: &QueryServer) {
        let mut _server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        


    }
}

use crate::prelude::*;
// use std::collections::VecDeque;
use crate::server::batch_modify::ModSetValid;
use std::collections::{BTreeMap, BTreeSet};
// use crate::server::{ChangeFlag, Plugins};

pub enum AttributeAssertion {
    // The ValueSet must look exactly like this.
    Set(ValueSet),
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
    },
}

pub struct AssertEvent {
    pub ident: Identity,
    pub asserts: Vec<EntryAssertion>,
}

struct Assertion {
    target: Uuid,
    attrs: BTreeMap<Attribute, AttributeAssertion>,
}

enum AssertionInner {
    None,
    Create { asserts: Vec<Assertion> },
    Modify { asserts: Vec<Assertion> },
    Remove { targets: Vec<Uuid> },
}

impl QueryServerWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    /// Document me please senpai.
    pub fn assert(&mut self, ae: AssertEvent) -> Result<(), OperationError> {
        let AssertEvent { ident, asserts } = ae;

        // Optimise => If there is nothing to do, bail.
        if asserts.is_empty() {
            todo!();
        }

        // Get all the UUID's from assert statements.
        let present_uuids: BTreeSet<Uuid> = asserts
            .iter()
            .filter_map(|a| match a {
                EntryAssertion::Present { target, .. } => Some(*target),
                _ => None,
            })
            .collect();

        let absent_uuids: BTreeSet<Uuid> = asserts
            .iter()
            .filter_map(|a| match a {
                EntryAssertion::Absent { target } => Some(*target),
                _ => None,
            })
            .collect();

        // Assert that there is no overlap.
        let duplicates: Vec<_> = present_uuids.intersection(&absent_uuids).collect();

        if !duplicates.is_empty() {
            // error
            error!(?duplicates, "entry uuids in SCIM Assertion must be unique.");
            return Err(OperationError::SC0033AssertionContainsDuplicateUuids);
        }

        // Determine which exist.
        // TODO: Make an optimised uuid search in the BE to just get an IDL.
        let filter = filter!(f_or(
            present_uuids
                .iter()
                .copied()
                .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                .collect()
        ));

        // While we do load then discard these, it doesn't really matter as it means
        // all the entries we are about to modify are now "cache hot".
        let existing_entries = self.internal_search(filter)?;

        // Which uuids need to be created vs modified?
        let modify_uuids: BTreeSet<Uuid> = existing_entries
            .iter()
            .map(|entry| entry.get_uuid())
            .collect();

        let create_uuids: BTreeSet<Uuid> =
            present_uuids.difference(&modify_uuids).copied().collect();

        // Break up the asserts then into sets of creates, mods and deletes. We can
        // do this because all three sets of uuids now exist.
        //
        // We apply the assertions *in order* from this point.
        //
        // We also want to ensure as much *batching* as possible to optimise our write paths.
        // To do this effectively we need to use a vecDeque to allow front poping, else we would
        // need to reverse the list.

        let mut working_assert = AssertionInner::None;

        let mut assert_batches = Vec::with_capacity(asserts.len());

        for entry_assert in asserts.into_iter() {
            match entry_assert {
                EntryAssertion::Absent { target } => {
                    if let AssertionInner::Remove { targets } = &mut working_assert {
                        // Push the next remove.
                        targets.push(target)
                    } else {
                        let mut new_assert = AssertionInner::Remove {
                            targets: vec![target],
                        };

                        std::mem::swap(&mut new_assert, &mut working_assert);

                        assert_batches.push(new_assert);
                    }
                }

                EntryAssertion::Present { target, attrs } if create_uuids.contains(&target) => {
                    if let AssertionInner::Create { asserts } = &mut working_assert {
                        // Push the next create
                        asserts.push(Assertion { target, attrs })
                    } else {
                        let mut new_assert = AssertionInner::Create {
                            asserts: vec![Assertion { target, attrs }],
                        };

                        std::mem::swap(&mut new_assert, &mut working_assert);

                        assert_batches.push(new_assert);
                    }
                }

                EntryAssertion::Present { target, attrs } => {
                    if let AssertionInner::Modify { asserts } = &mut working_assert {
                        // Push the next modify
                        asserts.push(Assertion { target, attrs })
                    } else {
                        let mut new_assert = AssertionInner::Modify {
                            asserts: vec![Assertion { target, attrs }],
                        };

                        std::mem::swap(&mut new_assert, &mut working_assert);

                        assert_batches.push(new_assert);
                    }
                }
            }
        }

        // Finally push the last working assert
        assert_batches.push(working_assert);

        // Now we can finally actually do the work.
        // Loop and apply!
        for assertion in assert_batches.into_iter() {
            match assertion {
                AssertionInner::Create { asserts } => {
                    let entries = asserts
                        .into_iter()
                        .map(|Assertion { target, attrs }| {
                            // Convert the attributes so that EntryInitNew understands them.
                            let mut attrs: crate::entry::Eattrs = attrs
                                .into_iter()
                                .filter_map(|(attr, assert_valueset)| match assert_valueset {
                                    AttributeAssertion::Set(vs) => Some((attr, vs)),
                                    AttributeAssertion::Absent => None,
                                })
                                .collect();

                            attrs.insert(Attribute::Uuid, ValueSetUuid::new(target));

                            EntryInitNew::from_iter(attrs.into_iter())
                        })
                        .collect();

                    let create_event = CreateEvent {
                        ident: ident.clone(),
                        entries,
                        return_created_uuids: false,
                    };

                    self.create(&create_event)?;
                }
                AssertionInner::Modify { asserts } => {
                    let modset = asserts
                        .into_iter()
                        .map(|Assertion { target, attrs }| {
                            let ml = attrs
                                .into_iter()
                                .map(|(attr, assert)| match assert {
                                    AttributeAssertion::Set(vs) => Modify::Set(attr, vs),
                                    AttributeAssertion::Absent => Modify::Purged(attr),
                                })
                                .collect();

                            let ml = ModifyList::new_list(ml);

                            (target, ml)
                        })
                        .map(|(target, ml)| {
                            ml.validate(self.get_schema())
                                .map(|modlist| (target, modlist))
                                .map_err(OperationError::SchemaViolation)
                        })
                        .collect::<Result<ModSetValid, _>>()?;

                    let batch_modify_event = BatchModifyEvent {
                        ident: ident.clone(),
                        modset,
                    };

                    self.batch_modify(&batch_modify_event)?;
                }
                AssertionInner::Remove { targets } => {
                    let filter = Filter::new(f_or(
                        targets
                            .into_iter()
                            .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                            .collect(),
                    ));

                    let filter_orig = filter
                        .validate(self.get_schema())
                        .map_err(OperationError::SchemaViolation)?;
                    let filter = filter_orig.clone().into_ignore_hidden();

                    let delete_event = DeleteEvent {
                        ident: ident.clone(),
                        filter,
                        filter_orig,
                    };

                    self.delete(&delete_event)?;
                }
                AssertionInner::None => {}
            }
        }

        // Complete!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AssertEvent, EntryAssertion};
    use crate::prelude::*;
    // use std::sync::Arc;

    #[qs_test]
    async fn test_entry_asserts(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Test duplicate uuids in both delete / assert

        let uuid_a = Uuid::new_v4();

        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Absent { target: uuid_a },
                EntryAssertion::Absent { target: uuid_a },
            ],
        };

        let _err = server_txn.assert(assert_event).expect_err("Should Fail!");

        // Create

        // Modify

        // Remove

        // Now mix and match things.
    }
}

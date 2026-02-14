use crate::prelude::*;
use crate::server::batch_modify::ModSetValid;
use crypto_glue::s256::Sha256Output;
use std::collections::{BTreeMap, BTreeSet};

pub enum AttributeAssertion {
    // The ValueSet must look exactly like this.
    Set(ValueSet),
    // The ValueSet must not be present.
    Absent,
    // TODO: We could in future add a "merge" style statement to this.
}

impl From<ValueSet> for AttributeAssertion {
    fn from(vs: ValueSet) -> Self {
        AttributeAssertion::Set(vs)
    }
}

pub enum EntryAssertion {
    // Could do an assert variant to make an entry look *exactly* like this, but that
    // has a lot of potential risks with internal attributes.
    Present {
        target: Uuid,
        // Option ValueSet represents a removal.
        attrs: BTreeMap<Attribute, Option<ValueSet>>,
    },
    Absent {
        target: Uuid,
    },
}

#[derive(Default)]
pub enum AssertOnce {
    #[default]
    No,
    Yes {
        id: Uuid,
        nonce: Sha256Output,
    },
}

pub struct AssertEvent {
    pub ident: Identity,
    pub asserts: Vec<EntryAssertion>,
    pub once: AssertOnce,
}

struct Assertion {
    target: Uuid,
    attrs: BTreeMap<Attribute, Option<ValueSet>>,
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
        let AssertEvent {
            ident,
            asserts,
            once,
        } = ae;

        if let AssertOnce::Yes { id, nonce } = once {
            // This should only be run once, provided that the valid tag is the same
            // on the existing migration record.

            let filter = filter!(f_and(vec![
                f_eq(Attribute::Uuid, PartialValue::Uuid(id)),
                f_eq(Attribute::Class, EntryClass::AssertionNonce.into())
            ]));

            let search_result = self.internal_search(filter).or_else(|err| {
                if err == OperationError::NoMatchingEntries {
                    Ok(Vec::with_capacity(0))
                } else {
                    Err(err)
                }
            })?;

            if let Some(record) = search_result.first() {
                if record
                    .get_ava_as_s256_set(Attribute::S256)
                    .map(|set| set.contains(&nonce))
                    .unwrap_or_default()
                {
                    // Nonce present - return we are done.
                    info!(?id, "Assertion already applied, skipping.");
                    return Ok(());
                } else {
                    // Need to update the nonce and proceed.
                    let ml = ModifyList::new_list(vec![Modify::Set(
                        Attribute::S256,
                        ValueSetSha256::new(nonce) as ValueSet,
                    )]);

                    self.internal_batch_modify([(id, ml)].into_iter())?;
                }
            } else {
                // No record - create one.

                let entry = EntryInitNew::from_iter([
                    (
                        Attribute::Class,
                        vs_iutf8!(EntryClass::AssertionNonce.into()),
                    ),
                    (Attribute::Uuid, ValueSetUuid::new(id) as ValueSet),
                    (Attribute::S256, ValueSetSha256::new(nonce) as ValueSet),
                ]);

                self.internal_create(vec![entry]).inspect_err(|err| {
                    error!(?err, "Failed to creation assertion nonce.");
                })?;
            }

            // Good to go.
        };

        // Optimise => If there is nothing to do, bail.
        if asserts.is_empty() {
            error!("assert: empty request");
            return Err(OperationError::EmptyRequest);
        }

        // Yes, we could collect() here, but that makes the error/analysis messages
        // worse because it's harder to detect which uuid is duplicate.

        let mut duplicates: BTreeSet<_> = Default::default();
        let mut present_uuids: BTreeSet<Uuid> = Default::default();
        let mut absent_uuids: BTreeSet<Uuid> = Default::default();

        for assert in &asserts {
            match assert {
                EntryAssertion::Present { target, .. } => {
                    // BTreeSet returns true if the value is unique. False if already present
                    if !present_uuids.insert(*target) {
                        duplicates.insert(*target);
                    }
                }
                EntryAssertion::Absent { target } => {
                    if !absent_uuids.insert(*target) {
                        duplicates.insert(*target);
                    }
                }
            }
        }

        // Check the intersection of the sets, and extend duplicates if there are any.
        duplicates.extend(present_uuids.intersection(&absent_uuids));

        // If present_uuids + absent_uuids len is not the same as asserts len, it means a uuid
        // was duplicated in the set.
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
                .chain(absent_uuids.iter().copied())
                .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                .collect()
        ));

        // While we do load then discard these, it doesn't really matter as it means
        // all the entries we are about to modify/delete are now "cache hot".
        let existing_entries = self.internal_search(filter).or_else(|err| {
            if err == OperationError::NoMatchingEntries {
                Ok(Vec::with_capacity(0))
            } else {
                Err(err)
            }
        })?;

        // Which uuids need to be created?
        let existing_uuids: BTreeSet<Uuid> = existing_entries
            .iter()
            .map(|entry| entry.get_uuid())
            .collect();

        let create_uuids: BTreeSet<Uuid> =
            present_uuids.difference(&existing_uuids).copied().collect();

        // Only delete uuids that currently actually exist.
        let delete_uuids: BTreeSet<Uuid> = absent_uuids
            .intersection(&existing_uuids)
            .copied()
            .collect();

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
                    if !delete_uuids.contains(&target) {
                        // The requested uuid to removed already does not exist. We
                        // can skip it as a result.
                        continue;
                    }

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
                                .filter_map(|(attr, assert_valueset)| {
                                    // This removes anything that is set to absent, we don't need it
                                    // during a create since they are none values.
                                    assert_valueset.map(|vs| (attr, vs))
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
                                    Some(vs) => Modify::Set(attr, vs),
                                    None => Modify::Purged(attr),
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
    use super::{AssertEvent, AssertOnce, EntryAssertion};
    use crate::prelude::*;
    use crypto_glue::s256::Sha256;
    use crypto_glue::traits::*;
    use std::collections::BTreeMap;
    // use std::sync::Arc;

    #[qs_test]
    async fn test_entry_asserts_basic(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![],
            once: AssertOnce::No,
        };

        let err = server_txn.assert(assert_event).expect_err("Should Fail!");
        assert_eq!(err, OperationError::EmptyRequest);

        // ======
        // Test duplicate uuids in both delete / assert

        let uuid_a = Uuid::new_v4();

        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Absent { target: uuid_a },
                EntryAssertion::Absent { target: uuid_a },
            ],
            once: AssertOnce::No,
        };

        let err = server_txn.assert(assert_event).expect_err("Should Fail!");
        assert_eq!(err, OperationError::SC0033AssertionContainsDuplicateUuids);

        // ======
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Absent { target: uuid_a },
                EntryAssertion::Present {
                    target: uuid_a,
                    attrs: BTreeMap::default(),
                },
            ],
            once: AssertOnce::No,
        };

        let err = server_txn.assert(assert_event).expect_err("Should Fail!");
        assert_eq!(err, OperationError::SC0033AssertionContainsDuplicateUuids);

        // ======
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Present {
                    target: uuid_a,
                    attrs: BTreeMap::default(),
                },
                EntryAssertion::Present {
                    target: uuid_a,
                    attrs: BTreeMap::default(),
                },
            ],
            once: AssertOnce::No,
        };

        let err = server_txn.assert(assert_event).expect_err("Should Fail!");
        assert_eq!(err, OperationError::SC0033AssertionContainsDuplicateUuids);

        // ======
        // Create
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![EntryAssertion::Present {
                target: uuid_a,
                attrs: BTreeMap::from([
                    (
                        Attribute::Class,
                        vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                    ),
                    (Attribute::Name, vs_iname!("test_entry_a").into()),
                    (
                        Attribute::DisplayName,
                        vs_utf8!("Test Entry A".into()).into(),
                    ),
                ]),
            }],
            once: AssertOnce::No,
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        let entry_a = server_txn
            .internal_search_uuid(uuid_a)
            .expect("Must succeed");
        assert_eq!(
            entry_a.get_ava_single_utf8(Attribute::DisplayName),
            Some("Test Entry A")
        );

        // ======
        // Modify
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![EntryAssertion::Present {
                target: uuid_a,
                attrs: BTreeMap::from([(
                    Attribute::DisplayName,
                    vs_utf8!("Test Entry A Updated".into()).into(),
                )]),
            }],
            once: AssertOnce::No,
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        let entry_a = server_txn
            .internal_search_uuid(uuid_a)
            .expect("Must succeed");
        assert_eq!(
            entry_a.get_ava_single_utf8(Attribute::DisplayName),
            Some("Test Entry A Updated")
        );

        // ======
        // Remove
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![EntryAssertion::Absent { target: uuid_a }],
            once: AssertOnce::No,
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        let err = server_txn
            .internal_search_uuid(uuid_a)
            .expect_err("Must fail");

        // Now absent.
        assert_eq!(err, OperationError::NoMatchingEntries);

        // Now mix and match things. We want to ensure there are at least two operations
        // per assertion, so that they both occur.

        let uuid_b = Uuid::new_v4();
        let uuid_c = Uuid::new_v4();
        let uuid_d = Uuid::new_v4();

        // Create B and D
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Present {
                    target: uuid_b,
                    attrs: BTreeMap::from([
                        (
                            Attribute::Class,
                            vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                        ),
                        (Attribute::Name, vs_iname!("test_entry_b").into()),
                        (
                            Attribute::DisplayName,
                            vs_utf8!("Test Entry B".into()).into(),
                        ),
                    ]),
                },
                EntryAssertion::Present {
                    target: uuid_d,
                    attrs: BTreeMap::from([
                        (
                            Attribute::Class,
                            vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                        ),
                        (Attribute::Name, vs_iname!("test_entry_d").into()),
                        (
                            Attribute::DisplayName,
                            vs_utf8!("Test Entry D".into()).into(),
                        ),
                    ]),
                },
            ],
            once: AssertOnce::No,
        };

        server_txn.assert(assert_event).expect("Must Succeed");
        assert!(server_txn
            .internal_exists_uuid(uuid_b)
            .expect("Failed to check existance"));
        assert!(server_txn
            .internal_exists_uuid(uuid_d)
            .expect("Failed to check existance"));

        // ====
        // Create C in between modifies to B and D
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Present {
                    target: uuid_b,
                    attrs: BTreeMap::from([
                        (
                            Attribute::Class,
                            vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                        ),
                        (Attribute::Name, vs_iname!("test_entry_b").into()),
                        (
                            Attribute::DisplayName,
                            vs_utf8!("Test Entry B".into()).into(),
                        ),
                    ]),
                },
                EntryAssertion::Present {
                    target: uuid_c,
                    attrs: BTreeMap::from([
                        (
                            Attribute::Class,
                            vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                        ),
                        (Attribute::Name, vs_iname!("test_entry_c").into()),
                        (
                            Attribute::DisplayName,
                            vs_utf8!("Test Entry C".into()).into(),
                        ),
                    ]),
                },
                EntryAssertion::Present {
                    target: uuid_d,
                    attrs: BTreeMap::from([
                        (
                            Attribute::Class,
                            vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                        ),
                        (Attribute::Name, vs_iname!("test_entry_d").into()),
                        (
                            Attribute::DisplayName,
                            vs_utf8!("Test Entry D".into()).into(),
                        ),
                    ]),
                },
            ],
            once: AssertOnce::No,
        };

        server_txn.assert(assert_event).expect("Must Succeed");
        assert!(server_txn
            .internal_exists_uuid(uuid_b)
            .expect("Failed to check existance"));
        assert!(server_txn
            .internal_exists_uuid(uuid_c)
            .expect("Failed to check existance"));
        assert!(server_txn
            .internal_exists_uuid(uuid_d)
            .expect("Failed to check existance"));

        // ====
        // Modify C in between deletes of B and D
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![
                EntryAssertion::Absent { target: uuid_b },
                EntryAssertion::Present {
                    target: uuid_c,
                    attrs: BTreeMap::from([
                        (
                            Attribute::Class,
                            vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                        ),
                        (Attribute::Name, vs_iname!("test_entry_c").into()),
                        (
                            Attribute::DisplayName,
                            vs_utf8!("Test Entry C".into()).into(),
                        ),
                    ]),
                },
                EntryAssertion::Absent { target: uuid_d },
            ],
            once: AssertOnce::No,
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        assert!(!server_txn
            .internal_exists_uuid(uuid_b)
            .expect("Failed to check existance"));
        assert!(server_txn
            .internal_exists_uuid(uuid_c)
            .expect("Failed to check existance"));
        assert!(!server_txn
            .internal_exists_uuid(uuid_d)
            .expect("Failed to check existance"));
    }

    #[qs_test]
    async fn test_entry_asserts_nonce(server: &QueryServer) {
        // This will test that assertions run only once. The full breadth of assertion
        // feature testing is done above. The majority of this logic is applying to
        // modifications due to how this is written.

        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let uuid_a = Uuid::new_v4();
        let assert_id = Uuid::new_v4();
        let nonce_1 = {
            let mut hasher = Sha256::new();
            hasher.update([1]);
            hasher.finalize()
        };

        let nonce_2 = {
            let mut hasher = Sha256::new();
            hasher.update([2]);
            hasher.finalize()
        };

        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![EntryAssertion::Present {
                target: uuid_a,
                attrs: BTreeMap::from([
                    (
                        Attribute::Class,
                        vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                    ),
                    (Attribute::Name, vs_iname!("test_entry_a").into()),
                    (
                        Attribute::DisplayName,
                        vs_utf8!("Test Entry A".into()).into(),
                    ),
                ]),
            }],
            once: AssertOnce::Yes {
                id: assert_id,
                nonce: nonce_1,
            },
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        let entry_a = server_txn
            .internal_search_uuid(uuid_a)
            .expect("Must succeed");
        assert_eq!(
            entry_a.get_ava_single_utf8(Attribute::DisplayName),
            Some("Test Entry A")
        );

        // =========================================
        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![EntryAssertion::Present {
                target: uuid_a,
                attrs: BTreeMap::from([
                    (
                        Attribute::Class,
                        vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                    ),
                    (Attribute::Name, vs_iname!("test_entry_a").into()),
                    (
                        Attribute::DisplayName,
                        // =============================
                        // We update the display name
                        vs_utf8!("Test Entry A Updated".into()).into(),
                    ),
                ]),
            }],
            once: AssertOnce::Yes {
                id: assert_id,
                // But we don't update the nonce. This will cause the change to be skipped.
                nonce: nonce_1,
            },
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        let entry_a = server_txn
            .internal_search_uuid(uuid_a)
            .expect("Must succeed");
        assert_eq!(
            entry_a.get_ava_single_utf8(Attribute::DisplayName),
            Some("Test Entry A")
        );

        // ===========================================

        let assert_event = AssertEvent {
            ident: Identity::from_internal(),
            asserts: vec![EntryAssertion::Present {
                target: uuid_a,
                attrs: BTreeMap::from([
                    (
                        Attribute::Class,
                        vs_iutf8!(EntryClass::Person.into(), EntryClass::Account.into()).into(),
                    ),
                    (Attribute::Name, vs_iname!("test_entry_a").into()),
                    (
                        Attribute::DisplayName,
                        // =============================
                        // We update the display name
                        vs_utf8!("Test Entry A Updated".into()).into(),
                    ),
                ]),
            }],
            once: AssertOnce::Yes {
                id: assert_id,
                // But because we update the nonce it now WILL apply.
                nonce: nonce_2,
            },
        };

        server_txn.assert(assert_event).expect("Must Succeed");

        let entry_a = server_txn
            .internal_search_uuid(uuid_a)
            .expect("Must succeed");
        assert_eq!(
            entry_a.get_ava_single_utf8(Attribute::DisplayName),
            Some("Test Entry A Updated")
        );
    }
}

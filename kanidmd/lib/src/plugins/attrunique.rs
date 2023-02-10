// Attribute uniqueness plugin. We read the schema and determine if the
// value should be unique, and how to handle if it is not. This will
// matter a lot when it comes to replication based on first-wins or
// both change approaches.
//
//
use std::collections::BTreeMap;
use std::collections::VecDeque;

use kanidm_proto::v1::{ConsistencyError, PluginError};
use tracing::trace;

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::schema::SchemaTransaction;

pub struct AttrUnique;

fn get_cand_attr_set<VALID, STATE>(
    cand: &[Entry<VALID, STATE>],
    attr: &str,
) -> Result<BTreeMap<PartialValue, Uuid>, OperationError> {
    let mut cand_attr: BTreeMap<PartialValue, Uuid> = BTreeMap::new();

    cand.iter()
        .try_for_each(|e| {
            let uuid = e
                .get_ava_single_uuid("uuid")
                .ok_or(OperationError::InvalidEntryState)?;
            // Get the value and uuid
            //for each value in the ava.
            e.get_ava_set(attr)
                .map(|vs| {
                    vs.to_partialvalue_iter()
                        .try_for_each(|v| match cand_attr.insert(v, uuid) {
                            None => Ok(()),
                            Some(vr) => {
                                admin_error!(
                                    "ava already exists -> {:?}: {:?} on {:?}",
                                    attr,
                                    vr,
                                    uuid
                                );
                                Err(OperationError::Plugin(PluginError::AttrUnique(
                                    "ava already exists".to_string(),
                                )))
                            }
                        })
                })
                .unwrap_or(Ok(()))
        })
        .map(|()| cand_attr)
}

fn enforce_unique<STATE>(
    qs: &mut QueryServerWriteTransaction,
    cand: &[Entry<EntryInvalid, STATE>],
    attr: &str,
) -> Result<(), OperationError> {
    // Build a set of all the value -> uuid for the cands.
    // If already exist, reject due to dup.
    let cand_attr = get_cand_attr_set(cand, attr).map_err(|e| {
        admin_error!(err = ?e, ?attr, "failed to get cand attr set");
        e
    })?;

    // No candidates to check!
    if cand_attr.is_empty() {
        return Ok(());
    }

    // Now do an internal search on name and !uuid for each

    // Or
    let filt_in = filter!(f_or(
        // for each cand_attr
        cand_attr
            .iter()
            .map(|(v, uuid)| {
                // and[ attr eq k, andnot [ uuid eq v ]]
                // Basically this says where name but also not self.
                f_and(vec![
                    FC::Eq(attr, v.clone()),
                    f_andnot(FC::Eq("uuid", PartialValue::Uuid(*uuid))),
                ])
            })
            .collect()
    ));

    trace!(?filt_in);

    // If any results, reject.
    let conflict_cand = qs.internal_exists(filt_in).map_err(|e| {
        admin_error!("internal exists error {:?}", e);
        e
    })?;

    // TODO! Need to make this show what conflicted!
    // We can probably bisect over the filter to work this out?

    if conflict_cand {
        // Some kind of confilct exists. We need to isolate which parts of the filter were suspect.
        // To do this, we bisect over the filter and it's suspect elements.
        //
        // In most cases there is likely only 1 suspect element. But in some there are more. To make
        // this process faster we "bisect" over chunks of the filter remaining until we have only single elements left.
        //
        // We do a bisect rather than a linear one-at-a-time search because we want to try to somewhat minimise calls
        // through internal exists since that has a filter resolve and validate step.

        // First create the vec of filters.
        let mut cand_filters: Vec<_> = cand_attr
            .into_iter()
            .map(|(v, uuid)| {
                // and[ attr eq k, andnot [ uuid eq v ]]
                // Basically this says where name but also not self.
                f_and(vec![
                    FC::Eq(attr, v),
                    f_andnot(FC::Eq("uuid", PartialValue::Uuid(uuid))),
                ])
            })
            .collect();

        // Fast-ish path. There is 0 or 1 element, so we just fast return.
        if cand_filters.len() < 2 {
            error!(
                ?cand_filters,
                "The following filter conditions failed to assert uniqueness"
            );
        } else {
            // First iteration, we already failed and we know that, so we just prime and setup two
            // chunks here.

            let mid = cand_filters.len() / 2;
            let right = cand_filters.split_off(mid);

            let mut queue = VecDeque::new();
            queue.push_back(cand_filters);
            queue.push_back(right);

            // Ok! We are setup to go

            while let Some(mut cand_query) = queue.pop_front() {
                let filt_in = filter!(f_or(cand_query.clone()));
                let conflict_cand = qs.internal_exists(filt_in).map_err(|e| {
                    admin_error!("internal exists error {:?}", e);
                    e
                })?;

                // A conflict was found!
                if conflict_cand {
                    if cand_query.len() >= 2 {
                        // Continue to split to isolate.
                        let mid = cand_query.len() / 2;
                        let right = cand_query.split_off(mid);
                        queue.push_back(cand_query);
                        queue.push_back(right);
                        // Continue!
                    } else {
                        // Report this as a failing query.
                        error!(cand_filters = ?cand_query, "The following filter conditions failed to assert uniqueness");
                    }
                }
            }
            // End logging / warning iterator
        }

        Err(OperationError::Plugin(PluginError::AttrUnique(
            "duplicate value detected".to_string(),
        )))
    } else {
        // If all okay, okay!
        Ok(())
    }
}

impl Plugin for AttrUnique {
    fn id() -> &'static str {
        "plugin_attrunique"
    }

    #[instrument(level = "debug", name = "attrunique_pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let r: Result<(), OperationError> = uniqueattrs
            .iter()
            .try_for_each(|attr| enforce_unique(qs, cand, attr.as_str()));
        r
    }

    #[instrument(level = "debug", name = "attrunique_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let r: Result<(), OperationError> = uniqueattrs
            .iter()
            .try_for_each(|attr| enforce_unique(qs, cand, attr.as_str()));
        r
    }

    #[instrument(level = "debug", name = "attrunique_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let r: Result<(), OperationError> = uniqueattrs
            .iter()
            .try_for_each(|attr| enforce_unique(qs, cand, attr.as_str()));
        r
    }

    #[instrument(level = "debug", name = "attrunique_verify", skip(qs))]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Only check live entries, not recycled.
        let filt_in = filter!(f_pres("class"));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let all_cand: Vec<_> = all_cand.into_iter().map(|e| e.as_ref().clone()).collect();

        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let mut res: Vec<Result<(), ConsistencyError>> = Vec::new();

        for attr in uniqueattrs.iter() {
            // We do a fully in memory check.
            if get_cand_attr_set(&all_cand, attr.as_str()).is_err() {
                res.push(Err(ConsistencyError::DuplicateUniqueAttribute(
                    attr.to_string(),
                )))
            }
        }

        trace!(?res);

        res
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::v1::PluginError;

    use crate::prelude::*;

    // Test entry in db, and same name, reject.
    #[test]
    fn test_pre_create_name_unique() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = vec![e];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "duplicate value detected".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // Test two entries in create that would have same name, reject.
    #[test]
    fn test_pre_create_name_unique_2() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone(), e];
        let preload = Vec::new();

        run_create_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "ava already exists".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // Remember, an entry can't have a duplicate value within itself so we don't need to
    // test this case.

    // A mod to something that exists, reject.
    #[test]
    fn test_pre_modify_name_unique() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "duplicate value detected".to_string()
            ))),
            preload,
            filter!(f_or!([f_eq(
                "name",
                PartialValue::new_iname("testgroup_b")
            ),])),
            ModifyList::new_list(vec![
                Modify::Purged(AttrString::from("name")),
                Modify::Present(AttrString::from("name"), Value::new_iname("testgroup_a"))
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Two items modded to have the same value, reject.
    #[test]
    fn test_pre_modify_name_unique_2() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "ava already exists".to_string()
            ))),
            preload,
            filter!(f_or!([
                f_eq("name", PartialValue::new_iname("testgroup_a")),
                f_eq("name", PartialValue::new_iname("testgroup_b")),
            ])),
            ModifyList::new_list(vec![
                Modify::Purged(AttrString::from("name")),
                Modify::Present(AttrString::from("name"), Value::new_iname("testgroup"))
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_verify_name_unique() {
        // Can we preload two dups and verify to show we detect?
    }
}

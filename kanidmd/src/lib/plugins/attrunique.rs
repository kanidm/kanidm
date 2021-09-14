// Attribute uniqueness plugin. We read the schema and determine if the
// value should be unique, and how to handle if it is not. This will
// matter a lot when it comes to replication based on first-wins or
// both change approaches.
//
//
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::schema::SchemaTransaction;
use kanidm_proto::v1::{ConsistencyError, PluginError};

use std::collections::BTreeMap;

pub struct AttrUnique;

fn get_cand_attr_set<VALID, STATE>(
    au: &mut AuditScope,
    cand: &[Entry<VALID, STATE>],
    attr: &str,
) -> Result<BTreeMap<PartialValue, PartialValue>, OperationError> {
    let mut cand_attr: BTreeMap<PartialValue, PartialValue> = BTreeMap::new();

    cand.iter()
        .try_for_each(|e| {
            let uuid = match e.get_ava_single("uuid") {
                Some(v) => v.to_partialvalue(),
                None => {
                    return Err(OperationError::InvalidEntryState);
                }
            };
            // Get the value and uuid
            //for each value in the ava.
            e.get_ava_set(attr)
                .map(|vs| {
                    vs.to_partialvalue_iter().try_for_each(|v| {
                        match cand_attr.insert(v, uuid.clone()) {
                            None => Ok(()),
                            Some(vr) => {
                                ladmin_error!(
                                    au,
                                    "ava already exists -> {:?}: {:?} on {:?}",
                                    attr,
                                    vr,
                                    uuid
                                );
                                Err(OperationError::Plugin(PluginError::AttrUnique(
                                    "ava already exists".to_string(),
                                )))
                            }
                        }
                    })
                })
                .unwrap_or(Ok(()))
        })
        .map(|()| cand_attr)
}

fn enforce_unique<STATE>(
    au: &mut AuditScope,
    qs: &QueryServerWriteTransaction,
    cand: &[Entry<EntryInvalid, STATE>],
    attr: &str,
) -> Result<(), OperationError> {
    ltrace!(au, "{:?}", attr);

    // Build a set of all the value -> uuid for the cands.
    // If already exist, reject due to dup.
    let cand_attr = get_cand_attr_set(au, cand, attr).map_err(|e| {
        ladmin_error!(au, "failed to get cand attr set {:?}", e);
        e
    })?;

    ltrace!(au, "{:?}", cand_attr);

    // No candidates to check!
    if cand_attr.is_empty() {
        return Ok(());
    }

    // Now do an internal search on name and !uuid for each

    // Or
    let filt_in = filter!(f_or(
        // for each cand_attr
        cand_attr
            .into_iter()
            .map(|(v, uuid)| {
                // and[ attr eq k, andnot [ uuid eq v ]]
                // Basically this says where name but also not self.
                f_and(vec![FC::Eq(attr, v), f_andnot(FC::Eq("uuid", uuid))])
            })
            .collect()
    ));

    ltrace!(au, "{:?}", filt_in);

    // If any results, reject.
    let conflict_cand = qs.internal_exists(au, filt_in).map_err(|e| {
        ladmin_error!(au, "internal exists error {:?}", e);
        e
    })?;

    // If all okay, okay!
    if conflict_cand {
        Err(OperationError::Plugin(PluginError::AttrUnique(
            "duplicate value detected".to_string(),
        )))
    } else {
        Ok(())
    }
}

impl Plugin for AttrUnique {
    fn id() -> &'static str {
        "plugin_attrunique"
    }

    fn pre_create_transform(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Needs to clone to avoid a borrow issue?
        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let r: Result<(), OperationError> = uniqueattrs
            .iter()
            .try_for_each(|attr| enforce_unique(au, qs, cand, attr.as_str()));
        r
    }

    fn pre_modify(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // Needs to clone to avoid a borrow issue?
        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let r: Result<(), OperationError> = uniqueattrs
            .iter()
            .try_for_each(|attr| enforce_unique(au, qs, cand, attr.as_str()));
        r
    }

    fn verify(
        au: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        // Only check live entries, not recycled.
        let filt_in = filter!(f_pres("class"));

        let all_cand = match qs
            .internal_search(au, filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let mut res: Vec<Result<(), ConsistencyError>> = Vec::new();

        for attr in uniqueattrs.iter() {
            // We do a fully in memory check.
            if get_cand_attr_set(au, &all_cand, attr.as_str()).is_err() {
                res.push(Err(ConsistencyError::DuplicateUniqueAttribute(
                    attr.to_string(),
                )))
            }
        }

        ltrace!(au, "{:?}", res);

        res
    }
}

#[cfg(test)]
mod tests {
    use crate::modify::{Modify, ModifyList};
    use crate::prelude::*;
    use kanidm_proto::v1::PluginError;

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
            |_, _| {}
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
            |_, _| {}
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
            |_, _| {}
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
            |_, _| {}
        );
    }

    #[test]
    fn test_verify_name_unique() {
        // Can we preload two dups and verify to show we detect?
    }
}

// Generate and manage spn's for all entries in the domain. Also deals with
// the infrequent - but possible - case where a domain is renamed.
use crate::plugins::Plugin;
use crate::prelude::*;

use crate::constants::UUID_DOMAIN_INFO;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntrySealed};
use crate::event::{CreateEvent, ModifyEvent};
use crate::value::PartialValue;
// use crate::value::{PartialValue, Value};
use kanidm_proto::v1::{ConsistencyError, OperationError};
use std::iter::once;
use std::sync::Arc;

pub struct Spn {}

lazy_static! {
    static ref CLASS_GROUP: PartialValue = PartialValue::new_class("group");
    static ref CLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
    static ref PV_UUID_DOMAIN_INFO: PartialValue = PartialValue::new_uuidr(&UUID_DOMAIN_INFO);
}

impl Plugin for Spn {
    fn id() -> &'static str {
        "plugin_spn"
    }

    // hook on pre-create and modify to generate / validate.
    fn pre_create_transform(
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Always generate the spn and set it. Why? Because the effort
        // needed to validate is the same as generation, so we may as well
        // just generate and set blindly when required.

        // Should we work out what classes dynamically from schema into a filter?
        // No - types that are trust replicated are fixed.
        let domain_name = qs.get_domain_name();

        for e in cand.iter_mut() {
            if e.attribute_equality("class", &CLASS_GROUP)
                || e.attribute_equality("class", &CLASS_ACCOUNT)
            {
                let spn = e
                    .generate_spn(domain_name)
                    .ok_or(OperationError::InvalidEntryState)
                    .map_err(|e| {
                        admin_error!(
                            "Account or group missing name, unable to generate spn!? {:?}",
                            e
                        );
                        e
                    })?;
                trace!("plugin_spn: set spn to {:?}", spn);
                e.set_ava("spn", once(spn));
            }
        }
        Ok(())
    }

    fn pre_modify(
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // Always generate and set *if* spn was an attribute on any of the mod
        // list events.
        let domain_name = qs.get_domain_name();

        for e in cand.iter_mut() {
            if e.attribute_equality("class", &CLASS_GROUP)
                || e.attribute_equality("class", &CLASS_ACCOUNT)
            {
                let spn = e
                    .generate_spn(domain_name)
                    .ok_or(OperationError::InvalidEntryState)
                    .map_err(|e| {
                        admin_error!(
                            "Account or group missing name, unable to generate spn!? {:?}",
                            e
                        );
                        e
                    })?;
                trace!("plugin_spn: set spn to {:?}", spn);
                e.set_ava("spn", once(spn));
            }
        }
        Ok(())
    }

    fn post_modify(
        qs: &QueryServerWriteTransaction,
        // List of what we modified that was valid?
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // On modify, if changing domain_name on UUID_DOMAIN_INFO
        //    trigger the spn regen ... which is expensive. Future
        // TODO #157: will be improvements to modify on large txns.

        let domain_name_changed = cand.iter().zip(pre_cand.iter()).find_map(|(post, pre)| {
            let domain_name = post.get_ava_single("domain_name");
            if post.attribute_equality("uuid", &PV_UUID_DOMAIN_INFO)
                && domain_name != pre.get_ava_single("domain_name")
            {
                domain_name
            } else {
                None
            }
        });

        let domain_name = match domain_name_changed {
            Some(s) => s,
            None => return Ok(()),
        };

        admin_info!(
            "IMPORTANT!!! Changing domain name to \"{:?}\". THIS MAY TAKE A LONG TIME ...",
            domain_name
        );

        // All we do is purge spn, and allow the plugin to recreate. Neat! It's also all still
        // within the transaction, just incase!
        qs.internal_modify(
            &filter!(f_or!([
                f_eq("class", PartialValue::new_class("group")),
                f_eq("class", PartialValue::new_class("account"))
            ])),
            &modlist!([m_purge("spn")]),
        )
    }

    fn verify(qs: &QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Verify that all items with spn's have valid spns.
        //   We need to consider the case that an item has a different origin domain too,
        // so we should be able to verify that *those* spns validate to the trusted domain info
        // we have been sent also. It's not up to use to generate those though ...

        let domain_name = qs.get_domain_name();

        let filt_in = filter!(f_or!([
            f_eq("class", PartialValue::new_class("group")),
            f_eq("class", PartialValue::new_class("account"))
        ]));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let mut r = Vec::new();

        for e in all_cand {
            let g_spn = match e.generate_spn(domain_name) {
                Some(s) => s,
                None => {
                    admin_error!(
                        uuid = ?e.get_uuid(),
                        "Entry SPN could not be generated (missing name!?)",
                    );
                    debug_assert!(false);
                    r.push(Err(ConsistencyError::InvalidSpn(e.get_id())));
                    continue;
                }
            };
            match e.get_ava_single("spn") {
                Some(r_spn) => {
                    trace!("verify spn: s {:?} == ex {:?} ?", r_spn, g_spn);
                    if r_spn != g_spn {
                        admin_error!(
                            uuid = ?e.get_uuid(),
                            "Entry SPN does not match expected s {:?} != ex {:?}",
                            r_spn,
                            g_spn,
                        );
                        debug_assert!(false);
                        r.push(Err(ConsistencyError::InvalidSpn(e.get_id())))
                    }
                }
                None => {
                    admin_error!(uuid = ?e.get_uuid(), "Entry does not contain an SPN");
                    r.push(Err(ConsistencyError::InvalidSpn(e.get_id())))
                }
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn test_spn_generate_create() {
        // on create don't provide
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |_qs_write: &QueryServerWriteTransaction| {}
        );
        // We don't need a validator due to the fn verify above.
    }

    #[test]
    fn test_spn_generate_modify() {
        // on a purge of the spen, generate it.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([m_purge("spn")]),
            None,
            |_| {}
        );
    }

    #[test]
    fn test_spn_validate_create() {
        // on create providing invalid spn, we over-write it.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account"],
                "spn": ["testperson@invalid_domain.com"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |_qs_write: &QueryServerWriteTransaction| {}
        );
    }

    #[test]
    fn test_spn_validate_modify() {
        // On modify (removed/present) of the spn, just regenerate it.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([
                m_purge("spn"),
                m_pres("spn", &Value::new_spn_str("invalid", "spn"))
            ]),
            None,
            |_| {}
        );
    }

    #[test]
    fn test_spn_regen_domain_rename() {
        run_test!(|server: &QueryServer| {
            let server_txn = server.write(duration_from_epoch_now());

            let ex1 = Value::new_spn_str("admin", "example.com");
            let ex2 = Value::new_spn_str("admin", "new.example.com");
            // get the current domain name
            // check the spn on admin is admin@<initial domain>
            let e_pre = server_txn
                .internal_search_uuid(&UUID_ADMIN)
                .expect("must not fail");

            let e_pre_spn = e_pre.get_ava_single("spn").expect("must not fail");
            assert!(e_pre_spn == ex1);

            // trigger the domain_name change (this will be a cli option to the server
            // in the final version), but it will still call the same qs function to perform the
            // change.
            unsafe {
                server_txn
                    .domain_rename_inner("new.example.com")
                    .expect("should not fail!");
            }

            // check the spn on admin is admin@<new domain>
            let e_post = server_txn
                .internal_search_uuid(&UUID_ADMIN)
                .expect("must not fail");

            let e_post_spn = e_post.get_ava_single("spn").expect("must not fail");
            debug!("{:?}", e_post_spn);
            debug!("{:?}", ex2);
            assert!(e_post_spn == ex2);

            server_txn.commit().expect("Must not fail");
        });
    }
}

// Generate and manage spn's for all entries in the domain. Also deals with
// the infrequent - but possible - case where a domain is renamed.
use crate::plugins::Plugin;

use crate::audit::AuditScope;
use crate::constants::UUID_DOMAIN_INFO;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntrySealed};
use crate::event::{CreateEvent, ModifyEvent};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use crate::value::PartialValue;
// use crate::value::{PartialValue, Value};
use kanidm_proto::v1::{ConsistencyError, OperationError};
use uuid::Uuid;

pub struct Spn {}

lazy_static! {
    static ref UUID_DOMAIN_INFO_T: Uuid =
        Uuid::parse_str(UUID_DOMAIN_INFO).expect("Unable to parse constant UUID_DOMAIN_INFO");
    static ref CLASS_GROUP: PartialValue = PartialValue::new_iutf8s("group");
    static ref CLASS_ACCOUNT: PartialValue = PartialValue::new_iutf8s("account");
    static ref PV_UUID_DOMAIN_INFO: PartialValue = PartialValue::new_uuids(UUID_DOMAIN_INFO)
        .expect("Unable to parse constant UUID_DOMAIN_INFO");
}

impl Spn {
    fn get_domain_name(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<String, OperationError> {
        qs.internal_search_uuid(au, &UUID_DOMAIN_INFO_T)
            .and_then(|e| {
                e.get_ava_single_string("domain_name")
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                audit_log!(au, "Error getting domain name -> {:?}", e);
                e
            })
    }

    fn get_domain_name_ro(
        au: &mut AuditScope,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<String, OperationError> {
        qs.internal_search_uuid(au, &UUID_DOMAIN_INFO_T)
            .and_then(|e| {
                e.get_ava_single_string("domain_name")
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                audit_log!(au, "Error getting domain name -> {:?}", e);
                e
            })
    }
}

impl Plugin for Spn {
    fn id() -> &'static str {
        "plugin_spn"
    }

    // hook on pre-create and modify to generate / validate.
    fn pre_create_transform(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Always generate the spn and set it. Why? Because the effort
        // needed to validate is the same as generation, so we may as well
        // just generate and set blindly when required.

        // TODO: Should we work out what classes dynamically from schema into a filter?
        let mut domain_name: Option<String> = None;

        for e in cand.iter_mut() {
            if e.attribute_value_pres("class", &CLASS_GROUP)
                || e.attribute_value_pres("class", &CLASS_ACCOUNT)
            {
                if domain_name.is_none() {
                    domain_name = Some(Self::get_domain_name(au, qs)?);
                }

                // It should be impossible to hit this expect as the is_none case should cause it to be replaced above.
                let some_domain_name = domain_name
                    .as_ref()
                    .expect("Domain name option memory corruption has occured.");

                let spn = e
                    .generate_spn(some_domain_name.as_str())
                    .ok_or(OperationError::InvalidEntryState)
                    .map_err(|e| {
                        audit_log!(
                            au,
                            "Account or group missing name, unable to generate spn!? {:?}",
                            e
                        );
                        e
                    })?;
                audit_log!(au, "plugin_spn: set spn to {:?}", spn);
                e.set_avas("spn", vec![spn]);
            }
        }
        Ok(())
    }

    fn pre_modify(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // Always generate and set *if* spn was an attribute on any of the mod
        // list events.
        let mut domain_name: Option<String> = None;

        for e in cand.iter_mut() {
            if e.attribute_value_pres("class", &CLASS_GROUP)
                || e.attribute_value_pres("class", &CLASS_ACCOUNT)
            {
                if domain_name.is_none() {
                    domain_name = Some(Self::get_domain_name(au, qs)?);
                }

                // It should be impossible to hit this expect as the is_none case should cause it to be replaced above.
                let some_domain_name = domain_name
                    .as_ref()
                    .expect("Domain name option memory corruption has occured.");

                let spn = e
                    .generate_spn(some_domain_name.as_str())
                    .ok_or(OperationError::InvalidEntryState)
                    .map_err(|e| {
                        audit_log!(
                            au,
                            "Account or group missing name, unable to generate spn!? {:?}",
                            e
                        );
                        e
                    })?;
                audit_log!(au, "plugin_spn: set spn to {:?}", spn);
                e.set_avas("spn", vec![spn]);
            }
        }
        Ok(())
    }

    fn post_modify(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        pre_cand: &[Entry<EntrySealed, EntryCommitted>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // On modify, if changing domain_name on UUID_DOMAIN_INFO
        //    trigger the spn regen ... which is expensive. Future
        // todo will be improvements to modify on large txns.

        let domain_name_changed =
            cand.iter()
                .zip(pre_cand.iter())
                .fold(None, |acc, (post, pre)| {
                    if acc.is_some() {
                        acc
                    } else if post.attribute_value_pres("uuid", &PV_UUID_DOMAIN_INFO)
                        && post.get_ava_single("domain_name") != pre.get_ava_single("domain_name")
                    {
                        post.get_ava_single("domain_name")
                    } else {
                        acc
                    }
                });

        let domain_name = match domain_name_changed {
            Some(s) => s,
            None => return Ok(()),
        };

        audit_log!(
            au,
            "IMPORTANT!!! Changing domain name to \"{:?}\". THIS MAY TAKE A LONG TIME ...",
            domain_name
        );

        // All we do is purge spn, and allow the plugin to recreate. Neat! It's also all still
        // within the transaction, just incase!
        qs.internal_modify(
            au,
            filter!(f_or!([
                f_eq("class", PartialValue::new_class("group")),
                f_eq("class", PartialValue::new_class("account"))
            ])),
            modlist!([m_purge("spn")]),
        )
    }

    fn verify(
        au: &mut AuditScope,
        qs: &mut QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        // Verify that all items with spn's have valid spns.
        //   We need to consider the case that an item has a different origin domain too,
        // so we should be able to verify that *those* spns validate to the trusted domain info
        // we have been sent also. It's not up to use to generate those though ...

        let domain_name = match Self::get_domain_name_ro(au, qs)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(dn) => dn,
            Err(e) => return vec![e],
        };

        let filt_in = filter!(f_or!([
            f_eq("class", PartialValue::new_class("group")),
            f_eq("class", PartialValue::new_class("account"))
        ]));

        let all_cand = match qs
            .internal_search(au, filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let mut r = Vec::new();

        for e in all_cand {
            let g_spn = match e.generate_spn(domain_name.as_str()) {
                Some(s) => s,
                None => {
                    audit_log!(
                        au,
                        "Entry {:?} SPN could not be generated (missing name!?)",
                        e.get_uuid()
                    );
                    debug_assert!(false);
                    r.push(Err(ConsistencyError::InvalidSPN(e.get_id())));
                    continue;
                }
            };
            match e.get_ava_single("spn") {
                Some(r_spn) => {
                    audit_log!(au, "verify spn: s {:?} == ex {:?} ?", r_spn, g_spn);
                    if *r_spn != g_spn {
                        audit_log!(
                            au,
                            "Entry {:?} SPN does not match expected s {:?} != ex {:?}",
                            e.get_uuid(),
                            r_spn,
                            g_spn,
                        );
                        debug_assert!(false);
                        r.push(Err(ConsistencyError::InvalidSPN(e.get_id())))
                    } else {
                        audit_log!(au, "spn is ok! 👍");
                    }
                }
                None => {
                    audit_log!(au, "Entry {:?} does not contain an SPN", e.get_uuid(),);
                    r.push(Err(ConsistencyError::InvalidSPN(e.get_id())))
                }
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::UUID_ADMIN;
    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
    use crate::value::{PartialValue, Value};

    #[test]
    fn test_spn_generate_create() {
        // on create don't provide
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            |_au, _qs_write: &QueryServerWriteTransaction| {}
        );
        // We don't need a validator due to the fn verify above.
    }

    #[test]
    fn test_spn_generate_modify() {
        // on a purge of the spen, generate it.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
            modlist!([m_purge("spn")]),
            None,
            |_, _| {}
        );
    }

    #[test]
    fn test_spn_validate_create() {
        // on create providing invalid spn, we over-write it.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            |_au, _qs_write: &QueryServerWriteTransaction| {}
        );
    }

    #[test]
    fn test_spn_validate_modify() {
        // On modify (removed/present) of the spn, just regenerate it.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
            modlist!([
                m_purge("spn"),
                m_pres("spn", &Value::new_spn_str("invalid", "spn"))
            ]),
            None,
            |_, _| {}
        );
    }

    #[test]
    fn test_spn_regen_domain_rename() {
        run_test!(|server: &QueryServer, au: &mut AuditScope| {
            let mut server_txn = server.write(duration_from_epoch_now());

            let ex1 = Value::new_spn_str("admin", "example.com");
            let ex2 = Value::new_spn_str("admin", "new.example.com");
            // get the current domain name
            // check the spn on admin is admin@<initial domain>
            let e_pre = server_txn
                .internal_search_uuid(au, &UUID_ADMIN)
                .expect("must not fail");

            let e_pre_spn = e_pre.get_ava_single("spn").expect("must not fail");
            assert!(*e_pre_spn == ex1);

            // trigger the domain_name change (this will be a cli option to the server
            // in the final version), but it will still call the same qs function to perform the
            // change.
            server_txn
                .domain_rename(au, "new.example.com")
                .expect("should not fail!");

            // check the spn on admin is admin@<new domain>
            let e_post = server_txn
                .internal_search_uuid(au, &UUID_ADMIN)
                .expect("must not fail");

            let e_post_spn = e_post.get_ava_single("spn").expect("must not fail");
            debug!("{:?}", e_post_spn);
            debug!("{:?}", ex2);
            assert!(*e_post_spn == ex2);

            server_txn.commit(au).expect("Must not fail");
        });
    }
}

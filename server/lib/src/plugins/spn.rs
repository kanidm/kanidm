// Generate and manage spn's for all entries in the domain. Also deals with
// the infrequent - but possible - case where a domain is renamed.
use std::collections::BTreeSet;
use std::iter::once;
use std::sync::Arc;

// use crate::value::{PartialValue, Value};
use kanidm_proto::v1::{ConsistencyError, OperationError};

use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntrySealed};
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct Spn {}

impl Plugin for Spn {
    fn id() -> &'static str {
        "plugin_spn"
    }

    // hook on pre-create and modify to generate / validate.
    #[instrument(level = "debug", name = "spn_pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Always generate the spn and set it. Why? Because the effort
        // needed to validate is the same as generation, so we may as well
        // just generate and set blindly when required.
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "spn_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "spn_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "spn_post_modify", skip_all)]
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand)
    }

    #[instrument(level = "debug", name = "spn_post_batch_modify", skip_all)]
    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand)
    }

    #[instrument(level = "debug", name = "spn_post_repl_incremental", skip_all)]
    fn post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        _conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand)
    }

    #[instrument(level = "debug", name = "spn::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Verify that all items with spn's have valid spns.
        //   We need to consider the case that an item has a different origin domain too,
        // so we should be able to verify that *those* spns validate to the trusted domain info
        // we have been sent also. It's not up to use to generate those though ...

        let domain_name = qs.get_domain_name().to_string();

        let filt_in = filter!(f_or!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            f_eq(Attribute::Class, EntryClass::Account.into()),
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
            let Some(g_spn) = e.generate_spn(&domain_name) else {
                admin_error!(
                    uuid = ?e.get_uuid(),
                    "Entry SPN could not be generated (missing name!?)",
                );
                debug_assert!(false);
                r.push(Err(ConsistencyError::InvalidSpn(e.get_id())));
                continue;
            };
            match e.get_ava_single(Attribute::Spn) {
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

impl Spn {
    fn modify_inner<T: Clone + std::fmt::Debug>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        let domain_name = qs.get_domain_name();

        for ent in cand.iter_mut() {
            if ent.attribute_equality(Attribute::Class, &EntryClass::Group.into())
                || ent.attribute_equality(Attribute::Class, &EntryClass::Account.into())
            {
                let spn = ent
                    .generate_spn(domain_name)
                    .ok_or(OperationError::InvalidEntryState)
                    .map_err(|e| {
                        admin_error!(
                            "Account or group missing name, unable to generate spn!? {:?} entry_id = {:?}",
                            e, ent.get_uuid()
                        );
                        e
                    })?;
                trace!(
                    "plugin_{}: set {} to {:?}",
                    Attribute::Spn,
                    Attribute::Spn,
                    spn
                );
                ent.set_ava(Attribute::Spn, once(spn));
            }
        }
        Ok(())
    }

    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        // On modify, if changing domain_name on UUID_DOMAIN_INFO trigger the spn regen

        let domain_name_changed = cand.iter().zip(pre_cand.iter()).find_map(|(post, pre)| {
            let domain_name = post.get_ava_single(Attribute::DomainName);
            if post.attribute_equality(Attribute::Uuid, &PVUUID_DOMAIN_INFO)
                && domain_name != pre.get_ava_single(Attribute::DomainName)
            {
                domain_name
            } else {
                None
            }
        });

        let Some(domain_name) = domain_name_changed else {
            return Ok(());
        };

        // IMPORTANT - we have to *pre-emptively reload the domain info here*
        //
        // If we don't, we don't get the updated domain name in the txn, and then
        // spn rename fails as we recurse and just populate the old name.
        qs.reload_domain_info()?;

        admin_info!(
            "IMPORTANT!!! Changing domain name to \"{:?}\". THIS MAY TAKE A LONG TIME ...",
            domain_name
        );

        // All we do is purge spn, and allow the plugin to recreate. Neat! It's also all still
        // within the transaction, just in case!
        qs.internal_modify(
            &filter!(f_or!([
                f_eq(Attribute::Class, EntryClass::Group.into()),
                f_eq(Attribute::Class, EntryClass::Account.into()),
            ])),
            &modlist!([m_purge(Attribute::Spn)]),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn test_spn_generate_create() {
        // on create don't provide the spn, we generate it.
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let create = vec![e];
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
        // on a purge of the spn, generate it.
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson"))),
            modlist!([m_purge(Attribute::Spn)]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_spn_validate_create() {
        // on create providing invalid spn, we over-write it.

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (
                Attribute::Spn,
                Value::new_utf8s("testperson@invalid_domain.com")
            ),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let create = vec![e];
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

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson"))),
            modlist!([
                m_purge(Attribute::Spn),
                m_pres(
                    Attribute::Spn,
                    &Value::new_spn_str("invalid", Attribute::Spn.as_ref())
                )
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[qs_test]
    async fn test_spn_regen_domain_rename(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let ex1 = Value::new_spn_str("admin", "example.com");
        let ex2 = Value::new_spn_str("admin", "new.example.com");
        // get the current domain name
        // check the spn on admin is admin@<initial domain>
        let e_pre = server_txn
            .internal_search_uuid(UUID_ADMIN)
            .expect("must not fail");

        let e_pre_spn = e_pre.get_ava_single(Attribute::Spn).expect("must not fail");
        assert!(e_pre_spn == ex1);

        // trigger the domain_name change (this will be a cli option to the server
        // in the final version), but it will still call the same qs function to perform the
        // change.
        server_txn
            .danger_domain_rename("new.example.com")
            .expect("should not fail!");

        // check the spn on admin is admin@<new domain>
        let e_post = server_txn
            .internal_search_uuid(UUID_ADMIN)
            .expect("must not fail");

        let e_post_spn = e_post
            .get_ava_single(Attribute::Spn)
            .expect("must not fail");
        debug!("{:?}", e_post_spn);
        debug!("{:?}", ex2);
        assert!(e_post_spn == ex2);

        server_txn.commit().expect("Must not fail");
    }
}

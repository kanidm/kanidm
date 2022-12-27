use hashbrown::HashMap;
use crate::server::ModifyEvent;
use crate::event::ReviveRecycledEvent;
use super::modify::ModifyPartial;
use crate::server::Plugins;
use crate::prelude::*;
use crate::access::AccessControlsTransaction;

impl<'a> QueryServerWriteTransaction<'a> {
    #[instrument(level = "debug", skip_all)]
    pub fn purge_tombstones(&self) -> Result<(), OperationError> {
        // purge everything that is a tombstone.
        let cid = self.cid.sub_secs(CHANGELOG_MAX_AGE).map_err(|e| {
            admin_error!("Unable to generate search cid {:?}", e);
            e
        })?;

        // Delete them - this is a TRUE delete, no going back now!
        self.be_txn
            .reap_tombstones(&cid)
            .map_err(|e| {
                admin_error!(err = ?e, "Tombstone purge operation failed (backend)");
                e
            })
            .map(|_| {
                admin_info!("Tombstone purge operation success");
            })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn purge_recycled(&self) -> Result<(), OperationError> {
        // Send everything that is recycled to tombstone
        // Search all recycled
        let cid = self.cid.sub_secs(RECYCLEBIN_MAX_AGE).map_err(|e| {
            admin_error!(err = ?e, "Unable to generate search cid");
            e
        })?;
        let rc = self.internal_search(filter_all!(f_and!([
            f_eq("class", PVCLASS_RECYCLED.clone()),
            f_lt("last_modified_cid", PartialValue::new_cid(cid)),
        ])))?;

        if rc.is_empty() {
            admin_info!("No recycled present - purge operation success");
            return Ok(());
        }

        // Modify them to strip all avas except uuid
        let tombstone_cand: Result<Vec<_>, _> = rc
            .iter()
            .map(|e| {
                e.to_tombstone(self.cid.clone())
                    .validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation in purge_recycled validate: {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    // seal if it worked.
                    .map(|e| e.seal(&self.schema))
            })
            .collect();

        let tombstone_cand = tombstone_cand?;

        // Backend Modify
        self.be_txn
            .modify(&self.cid, &rc, &tombstone_cand)
            .map_err(|e| {
                admin_error!("Purge recycled operation failed (backend), {:?}", e);
                e
            })
            .map(|_| {
                admin_info!("Purge recycled operation success");
            })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn revive_recycled(&mut self, re: &ReviveRecycledEvent) -> Result<(), OperationError> {
        // Revive an entry to live. This is a specialised function, and draws a lot of
        // inspiration from modify.
        //
        // Access is granted by the ability to ability to search the class=recycled
        // and the ability modify + remove that class from the object.
        if !re.ident.is_internal() {
            security_info!(name = %re.ident, "revive initiator");
        }

        // Get the list of pre_candidates, using impersonate search.
        let pre_candidates =
            self.impersonate_search_valid(re.filter.clone(), re.filter.clone(), &re.ident)?;

        // Is the list empty?
        if pre_candidates.is_empty() {
            if re.ident.is_internal() {
                trace!(
                    "revive: no candidates match filter ... continuing {:?}",
                    re.filter
                );
                return Ok(());
            } else {
                request_error!(
                    "revive: no candidates match filter, failure {:?}",
                    re.filter
                );
                return Err(OperationError::NoMatchingEntries);
            }
        };

        trace!("revive: pre_candidates -> {:?}", pre_candidates);

        // Check access against a "fake" modify.
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            AttrString::from("class"),
            PVCLASS_RECYCLED.clone(),
        )]);

        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            admin_error!("revive recycled modlist Schema Violation {:?}", e);
            OperationError::SchemaViolation(e)
        })?;

        let me =
            ModifyEvent::new_impersonate(&re.ident, re.filter.clone(), re.filter.clone(), m_valid);

        let access = self.get_accesscontrols();
        let op_allow = access
            .modify_allow_operation(&me, &pre_candidates)
            .map_err(|e| {
                admin_error!("Unable to check modify access {:?}", e);
                e
            })?;
        if !op_allow {
            return Err(OperationError::AccessDenied);
        }

        // Are all of the entries actually recycled?
        if pre_candidates.iter().all(|e| e.mask_recycled().is_some()) {
            admin_warn!("Refusing to revive entries that are already live!");
            return Err(OperationError::AccessDenied);
        }

        // Build the list of mods from directmo, to revive memberships.
        let mut dm_mods: HashMap<Uuid, ModifyList<ModifyInvalid>> =
            HashMap::with_capacity(pre_candidates.len());

        for e in &pre_candidates {
            // Get this entries uuid.
            let u: Uuid = e.get_uuid();

            if let Some(riter) = e.get_ava_as_refuuid("directmemberof") {
                for g_uuid in riter {
                    dm_mods
                        .entry(g_uuid)
                        .and_modify(|mlist| {
                            let m = Modify::Present(AttrString::from("member"), Value::Refer(u));
                            mlist.push_mod(m);
                        })
                        .or_insert({
                            let m = Modify::Present(AttrString::from("member"), Value::Refer(u));
                            ModifyList::new_list(vec![m])
                        });
                }
            }
        }

        // clone the writeable entries.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| er.as_ref().clone().invalidate(self.cid.clone()))
            // Mutate to apply the revive.
            .map(|er| er.to_revived())
            .collect();

        // Are they all revived?
        if candidates.iter().all(|e| e.mask_recycled().is_none()) {
            admin_error!("Not all candidates were correctly revived, unable to proceed");
            return Err(OperationError::InvalidEntryState);
        }

        // Do we need to apply pre-mod?
        // Very likely, incase domain has renamed etc.
        Plugins::run_pre_modify(self, &mut candidates, &me).map_err(|e| {
            admin_error!("Revive operation failed (plugin), {:?}", e);
            e
        })?;

        // Schema validate
        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| e.seal(&self.schema))
            })
            .collect();

        let norm_cand: Vec<Entry<_, _>> = res?;

        // build the mod partial
        let mp = ModifyPartial {
            norm_cand,
            pre_candidates,
            me: &me,
        };

        // Call modify_apply
        self.modify_apply(mp)?;

        // If and only if that succeeds, apply the direct membership modifications
        // if possible.
        for (g, mods) in dm_mods {
            // I think the filter/filter_all shouldn't matter here because the only
            // valid direct memberships should be still valid/live references, as refint
            // removes anything that was deleted even from recycled entries.
            let f = filter_all!(f_eq("uuid", PartialValue::Uuid(g)));
            self.internal_modify(&f, &mods)?;
        }

        Ok(())
    }

    /*
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn revive_recycled_legacy(
        &mut self,
        re: &ReviveRecycledEvent,
    ) -> Result<(), OperationError> {
        // Revive an entry to live. This is a specialised function, and draws a lot of
        // inspiration from modify.
        //
        //
        // Access is granted by the ability to ability to search the class=recycled
        // and the ability modify + remove that class from the object.

        // create the modify for access testing.
        // tl;dr, remove the class=recycled
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            AttrString::from("class"),
            PVCLASS_RECYCLED.clone(),
        )]);

        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            admin_error!(
                "Schema Violation in revive recycled modlist validate: {:?}",
                e
            );
            OperationError::SchemaViolation(e)
        })?;

        // Get the entries we are about to revive.
        //    we make a set of per-entry mod lists. A list of lists even ...
        let revive_cands =
            self.impersonate_search_valid(re.filter.clone(), re.filter.clone(), &re.ident)?;

        let mut dm_mods: HashMap<Uuid, ModifyList<ModifyInvalid>> =
            HashMap::with_capacity(revive_cands.len());

        for e in revive_cands {
            // Get this entries uuid.
            let u: Uuid = e.get_uuid();

            if let Some(riter) = e.get_ava_as_refuuid("directmemberof") {
                for g_uuid in riter {
                    dm_mods
                        .entry(g_uuid)
                        .and_modify(|mlist| {
                            let m = Modify::Present(AttrString::from("member"), Value::Refer(u));
                            mlist.push_mod(m);
                        })
                        .or_insert({
                            let m = Modify::Present(AttrString::from("member"), Value::Refer(u));
                            ModifyList::new_list(vec![m])
                        });
                }
            }
        }

        // Now impersonate the modify
        self.impersonate_modify_valid(re.filter.clone(), re.filter.clone(), m_valid, &re.ident)?;
        // If and only if that succeeds, apply the direct membership modifications
        // if possible.
        for (g, mods) in dm_mods {
            // I think the filter/filter_all shouldn't matter here because the only
            // valid direct memberships should be still valid/live references.
            let f = filter_all!(f_eq("uuid", PartialValue::Uuid(g)));
            self.internal_modify(&f, &mods)?;
        }
        Ok(())
    }
    */
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    use crate::event::{CreateEvent, DeleteEvent};
    use crate::server::SearchEvent;
    use crate::server::ModifyEvent;

    use super::ReviveRecycledEvent;

    #[qs_test]
    async fn test_recycle_simple(server: &QueryServer) {
        // First we setup some timestamps
        let time_p1 = duration_from_epoch_now();
        let time_p2 = time_p1 + Duration::from_secs(RECYCLEBIN_MAX_AGE * 2);

        let mut server_txn = server.write(time_p1).await;
        let admin = server_txn.internal_search_uuid(UUID_ADMIN).expect("failed");

        let filt_i_rc = filter_all!(f_eq("class", PartialValue::new_class("recycled")));

        let filt_i_ts = filter_all!(f_eq("class", PartialValue::new_class("tombstone")));

        let filt_i_per = filter_all!(f_eq("class", PartialValue::new_class("person")));

        // Create fake external requests. Probably from admin later
        let me_rc = unsafe {
            ModifyEvent::new_impersonate_entry(
                admin.clone(),
                filt_i_rc.clone(),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("class"),
                    Value::new_class("recycled"),
                )]),
            )
        };

        let de_rc = unsafe { DeleteEvent::new_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

        let se_rc =
            unsafe { SearchEvent::new_ext_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

        let sre_rc =
            unsafe { SearchEvent::new_rec_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

        let rre_rc = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin,
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        // Create some recycled objects
        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson2")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63932"))
            ),
            ("description", Value::new_utf8s("testperson2")),
            ("displayname", Value::new_utf8s("testperson2"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Now we immediately delete these to force them to the correct state.
        let de_sin = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_or!([
                f_eq("name", PartialValue::new_iname("testperson1")),
                f_eq("name", PartialValue::new_iname("testperson2")),
            ])))
        };
        assert!(server_txn.delete(&de_sin).is_ok());

        // Can it be seen (external search)
        let r1 = server_txn.search(&se_rc).expect("search failed");
        assert!(r1.is_empty());

        // Can it be deleted (external delete)
        // Should be err-no candidates.
        assert!(server_txn.delete(&de_rc).is_err());

        // Can it be modified? (external modify)
        // Should be err-no candidates
        assert!(server_txn.modify(&me_rc).is_err());

        // Can in be seen by special search? (external recycle search)
        let r2 = server_txn.search(&sre_rc).expect("search failed");
        assert!(r2.len() == 2);

        // Can it be seen (internal search)
        // Internal search should see it.
        let r2 = server_txn
            .internal_search(filt_i_rc.clone())
            .expect("internal search failed");
        assert!(r2.len() == 2);

        // There are now two paths forward
        //  revival or purge!
        assert!(server_txn.revive_recycled(&rre_rc).is_ok());

        // Not enough time has passed, won't have an effect for purge to TS
        assert!(server_txn.purge_recycled().is_ok());
        let r3 = server_txn
            .internal_search(filt_i_rc.clone())
            .expect("internal search failed");
        assert!(r3.len() == 1);

        // Commit
        assert!(server_txn.commit().is_ok());

        // Now, establish enough time for the recycled items to be purged.
        let server_txn = server.write(time_p2).await;

        //  purge to tombstone, now that time has passed.
        assert!(server_txn.purge_recycled().is_ok());

        // Should be no recycled objects.
        let r4 = server_txn
            .internal_search(filt_i_rc.clone())
            .expect("internal search failed");
        assert!(r4.is_empty());

        // There should be one tombstone
        let r5 = server_txn
            .internal_search(filt_i_ts.clone())
            .expect("internal search failed");
        assert!(r5.len() == 1);

        // There should be one entry
        let r6 = server_txn
            .internal_search(filt_i_per.clone())
            .expect("internal search failed");
        assert!(r6.len() == 1);

        assert!(server_txn.commit().is_ok());
    }

    // The delete test above should be unaffected by recycle anyway
    #[qs_test]
    async fn test_qs_recycle_advanced(server: &QueryServer) {
        // Create items
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let admin = server_txn.internal_search_uuid(UUID_ADMIN).expect("failed");

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());
        // Delete and ensure they became recycled.
        let de_sin = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_eq(
                "name",
                PartialValue::new_iname("testperson1")
            )))
        };
        assert!(server_txn.delete(&de_sin).is_ok());
        // Can in be seen by special search? (external recycle search)
        let filt_rc = filter_all!(f_eq("class", PartialValue::new_class("recycled")));
        let sre_rc = unsafe { SearchEvent::new_rec_impersonate_entry(admin, filt_rc.clone()) };
        let r2 = server_txn.search(&sre_rc).expect("search failed");
        assert!(r2.len() == 1);

        // Create dup uuid (rej)
        // After a delete -> recycle, create duplicate name etc.
        let cr = server_txn.create(&ce);
        assert!(cr.is_err());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_uuid_to_star_recycle(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        assert!(server_txn.uuid_to_rdn(tuuid) == Ok("spn=testperson1@example.com".to_string()));

        assert!(
            server_txn.uuid_to_spn(tuuid)
                == Ok(Some(Value::new_spn_str("testperson1", "example.com")))
        );

        assert!(server_txn.name_to_uuid("testperson1") == Ok(tuuid));

        // delete
        let de_sin = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_eq(
                "name",
                PartialValue::new_iname("testperson1")
            )))
        };
        assert!(server_txn.delete(&de_sin).is_ok());

        // all should fail
        assert!(
            server_txn.uuid_to_rdn(tuuid)
                == Ok("uuid=cc8e95b4-c24f-4d68-ba54-8bed76f63930".to_string())
        );

        assert!(server_txn.uuid_to_spn(tuuid) == Ok(None));

        assert!(server_txn.name_to_uuid("testperson1").is_err());

        // revive
        let admin = server_txn.internal_search_uuid(UUID_ADMIN).expect("failed");
        let rre_rc = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin,
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };
        assert!(server_txn.revive_recycled(&rre_rc).is_ok());

        // all checks pass

        assert!(server_txn.uuid_to_rdn(tuuid) == Ok("spn=testperson1@example.com".to_string()));

        assert!(
            server_txn.uuid_to_spn(tuuid)
                == Ok(Some(Value::new_spn_str("testperson1", "example.com")))
        );

        assert!(server_txn.name_to_uuid("testperson1") == Ok(tuuid));
    }

}


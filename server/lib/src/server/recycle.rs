use super::modify::ModifyPartial;
use crate::event::ReviveRecycledEvent;
use crate::prelude::*;
use crate::server::Plugins;
use hashbrown::HashMap;

impl<'a> QueryServerWriteTransaction<'a> {
    #[instrument(level = "debug", skip_all)]
    pub fn purge_tombstones(&mut self) -> Result<(), OperationError> {
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
    pub fn purge_recycled(&mut self) -> Result<(), OperationError> {
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
        // Very likely, in case domain has renamed etc.
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
    use crate::server::ModifyEvent;
    use crate::server::SearchEvent;

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
        let mut server_txn = server.write(time_p2).await;

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
        let sre_rc = unsafe { SearchEvent::new_rec_impersonate_entry(admin, filt_rc) };
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

    #[qs_test]
    async fn test_tombstone(server: &QueryServer) {
        // First we setup some timestamps
        let time_p1 = duration_from_epoch_now();
        let time_p2 = time_p1 + Duration::from_secs(CHANGELOG_MAX_AGE * 2);
        let time_p3 = time_p2 + Duration::from_secs(CHANGELOG_MAX_AGE * 2);

        trace!("test_tombstone_start");
        let mut server_txn = server.write(time_p1).await;
        let admin = server_txn.internal_search_uuid(UUID_ADMIN).expect("failed");

        let filt_i_ts = filter_all!(f_eq("class", PartialValue::new_class("tombstone")));

        // Create fake external requests. Probably from admin later
        // Should we do this with impersonate instead of using the external
        let me_ts = unsafe {
            ModifyEvent::new_impersonate_entry(
                admin.clone(),
                filt_i_ts.clone(),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("class"),
                    Value::new_class("tombstone"),
                )]),
            )
        };

        let de_ts = unsafe { DeleteEvent::new_impersonate_entry(admin.clone(), filt_i_ts.clone()) };
        let se_ts = unsafe { SearchEvent::new_ext_impersonate_entry(admin, filt_i_ts.clone()) };

        // First, create an entry, then push it through the lifecycle.
        let e_ts = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("9557f49c-97a5-4277-a9a5-097d17eb8317"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );

        let ce = CreateEvent::new_internal(vec![e_ts]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        let de_sin = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_or!([f_eq(
                "name",
                PartialValue::new_iname("testperson1")
            )])))
        };
        assert!(server_txn.delete(&de_sin).is_ok());

        // Commit
        assert!(server_txn.commit().is_ok());

        // Now, establish enough time for the recycled items to be purged.
        let mut server_txn = server.write(time_p2).await;
        assert!(server_txn.purge_recycled().is_ok());

        // Now test the tombstone properties.

        // Can it be seen (external search)
        let r1 = server_txn.search(&se_ts).expect("search failed");
        assert!(r1.is_empty());

        // Can it be deleted (external delete)
        // Should be err-no candidates.
        assert!(server_txn.delete(&de_ts).is_err());

        // Can it be modified? (external modify)
        // Should be err-no candidates
        assert!(server_txn.modify(&me_ts).is_err());

        // Can it be seen (internal search)
        // Internal search should see it.
        let r2 = server_txn
            .internal_search(filt_i_ts.clone())
            .expect("internal search failed");
        assert!(r2.len() == 1);

        // If we purge now, nothing happens, we aren't past the time window.
        assert!(server_txn.purge_tombstones().is_ok());

        let r3 = server_txn
            .internal_search(filt_i_ts.clone())
            .expect("internal search failed");
        assert!(r3.len() == 1);

        // Commit
        assert!(server_txn.commit().is_ok());

        // New txn, push the cid forward.
        let mut server_txn = server.write(time_p3).await;

        // Now purge
        assert!(server_txn.purge_tombstones().is_ok());

        // Assert it's gone
        // Internal search should not see it.
        let r4 = server_txn
            .internal_search(filt_i_ts)
            .expect("internal search failed");
        assert!(r4.is_empty());

        assert!(server_txn.commit().is_ok());
    }

    fn create_user(name: &str, uuid: &str) -> Entry<EntryInit, EntryNew> {
        entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname(name)),
            ("uuid", Value::new_uuid_s(uuid).expect("uuid")),
            ("description", Value::new_utf8s("testperson-entry")),
            ("displayname", Value::new_utf8s(name))
        )
    }

    fn create_group(name: &str, uuid: &str, members: &[&str]) -> Entry<EntryInit, EntryNew> {
        let mut e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("name", Value::new_iname(name)),
            ("uuid", Value::new_uuid_s(uuid).expect("uuid")),
            ("description", Value::new_utf8s("testgroup-entry"))
        );
        members
            .iter()
            .for_each(|m| e1.add_ava("member", Value::new_refer_s(m).unwrap()));
        e1
    }

    fn check_entry_has_mo(qs: &mut QueryServerWriteTransaction, name: &str, mo: &str) -> bool {
        let e = qs
            .internal_search(filter!(f_eq("name", PartialValue::new_iname(name))))
            .unwrap()
            .pop()
            .unwrap();

        e.attribute_equality("memberof", &PartialValue::new_refer_s(mo).unwrap())
    }

    #[qs_test]
    async fn test_revive_advanced_directmemberships(server: &QueryServer) {
        // Create items
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let admin = server_txn.internal_search_uuid(UUID_ADMIN).expect("failed");

        // Right need a user in a direct group.
        let u1 = create_user("u1", "22b47373-d123-421f-859e-9ddd8ab14a2a");
        let g1 = create_group(
            "g1",
            "cca2bbfc-5b43-43f3-be9e-f5b03b3defec",
            &["22b47373-d123-421f-859e-9ddd8ab14a2a"],
        );

        // Need a user in A -> B -> User, such that A/B are re-adde as MO
        let u2 = create_user("u2", "5c19a4a2-b9f0-4429-b130-5782de5fddda");
        let g2a = create_group(
            "g2a",
            "e44cf9cd-9941-44cb-a02f-307b6e15ac54",
            &["5c19a4a2-b9f0-4429-b130-5782de5fddda"],
        );
        let g2b = create_group(
            "g2b",
            "d3132e6e-18ce-4b87-bee1-1d25e4bfe96d",
            &["e44cf9cd-9941-44cb-a02f-307b6e15ac54"],
        );

        // Need a user in a group that is recycled after, then revived at the same time.
        let u3 = create_user("u3", "68467a41-6e8e-44d0-9214-a5164e75ca03");
        let g3 = create_group(
            "g3",
            "36048117-e479-45ed-aeb5-611e8d83d5b1",
            &["68467a41-6e8e-44d0-9214-a5164e75ca03"],
        );

        // A user in a group that is recycled, user is revived, THEN the group is. Group
        // should be present in MO after the second revive.
        let u4 = create_user("u4", "d696b10f-1729-4f1a-83d0-ca06525c2f59");
        let g4 = create_group(
            "g4",
            "d5c59ac6-c533-4b00-989f-d0e183f07bab",
            &["d696b10f-1729-4f1a-83d0-ca06525c2f59"],
        );

        let ce = CreateEvent::new_internal(vec![u1, g1, u2, g2a, g2b, u3, g3, u4, g4]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Now recycle the needed entries.
        let de = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_or(vec![
                f_eq("name", PartialValue::new_iname("u1")),
                f_eq("name", PartialValue::new_iname("u2")),
                f_eq("name", PartialValue::new_iname("u3")),
                f_eq("name", PartialValue::new_iname("g3")),
                f_eq("name", PartialValue::new_iname("u4")),
                f_eq("name", PartialValue::new_iname("g4"))
            ])))
        };
        assert!(server_txn.delete(&de).is_ok());

        // Now revive and check each one, one at a time.
        let rev1 = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("u1"))),
            )
        };
        assert!(server_txn.revive_recycled(&rev1).is_ok());
        // check u1 contains MO ->
        assert!(check_entry_has_mo(
            &mut server_txn,
            "u1",
            "cca2bbfc-5b43-43f3-be9e-f5b03b3defec"
        ));

        // Revive u2 and check it has two mo.
        let rev2 = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("u2"))),
            )
        };
        assert!(server_txn.revive_recycled(&rev2).is_ok());
        assert!(check_entry_has_mo(
            &mut server_txn,
            "u2",
            "e44cf9cd-9941-44cb-a02f-307b6e15ac54"
        ));
        assert!(check_entry_has_mo(
            &mut server_txn,
            "u2",
            "d3132e6e-18ce-4b87-bee1-1d25e4bfe96d"
        ));

        // Revive u3 and g3 at the same time.
        let rev3 = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin.clone(),
                filter_all!(f_or(vec![
                    f_eq("name", PartialValue::new_iname("u3")),
                    f_eq("name", PartialValue::new_iname("g3"))
                ])),
            )
        };
        assert!(server_txn.revive_recycled(&rev3).is_ok());
        assert!(!check_entry_has_mo(
            &mut server_txn,
            "u3",
            "36048117-e479-45ed-aeb5-611e8d83d5b1"
        ));

        // Revive u4, should NOT have the MO.
        let rev4a = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("u4"))),
            )
        };
        assert!(server_txn.revive_recycled(&rev4a).is_ok());
        assert!(!check_entry_has_mo(
            &mut server_txn,
            "u4",
            "d5c59ac6-c533-4b00-989f-d0e183f07bab"
        ));

        // Now revive g4, should allow MO onto u4.
        let rev4b = unsafe {
            ReviveRecycledEvent::new_impersonate_entry(
                admin,
                filter_all!(f_eq("name", PartialValue::new_iname("g4"))),
            )
        };
        assert!(server_txn.revive_recycled(&rev4b).is_ok());
        assert!(!check_entry_has_mo(
            &mut server_txn,
            "u4",
            "d5c59ac6-c533-4b00-989f-d0e183f07bab"
        ));

        assert!(server_txn.commit().is_ok());
    }
}

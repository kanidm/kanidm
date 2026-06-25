use crate::prelude::*;
use crate::server::DeleteEvent;
use crate::server::{ChangeFlag, Plugins};
use std::collections::BTreeMap;

impl QueryServerWriteTransaction<'_> {
    #[allow(clippy::cognitive_complexity)]
    #[instrument(level = "debug", skip_all)]
    pub fn delete(&mut self, de: &DeleteEvent) -> Result<(), OperationError> {
        // Do you have access to view all the set members? Reduce based on your
        // read permissions and attrs
        // THIS IS PRETTY COMPLEX SEE THE DESIGN DOC
        // In this case we need a search, but not INTERNAL to keep the same
        // associated credentials.
        // We only need to retrieve uuid though ...
        if !de.ident.is_internal() {
            security_info!(name = %de.ident, "delete initiator");
        }

        // Now, delete only what you can see
        let mut pre_candidates = self
            .impersonate_search_valid(de.filter.clone(), de.filter_orig.clone(), &de.ident)
            .map_err(|e| {
                admin_error!("delete: error in pre-candidate selection {:?}", e);
                e
            })?;

        // Apply access controls to reduce the set if required.
        // delete_allow_operation
        {
            let access = self.get_accesscontrols();
            let op_allow = access
                .delete_allow_operation(de, &pre_candidates)
                .map_err(|e| {
                    admin_error!("Failed to check delete access {:?}", e);
                    e
                })?;
            if !op_allow {
                return Err(OperationError::AccessDenied);
            }
        }

        // Is the candidate set empty?
        if pre_candidates.is_empty() {
            warn!("delete: no candidates match filter");
            debug!(delete_filter = ?de.filter);
            return Err(OperationError::NoMatchingEntries);
        };

        if pre_candidates.iter().any(|e| e.mask_tombstone().is_none()) {
            warn!("Refusing to delete entries which may be an attempt to bypass replication state machine.");
            return Err(OperationError::AccessDenied);
        }

        // ======= Access Control and Invariants Checked !!! ========

        // We now extend pre-candidates with anything that will be cascade-deleted.
        let references_filt = filter!(f_or(
            pre_candidates
                .iter()
                .map(|entry| { f_eq(Attribute::Refers, PartialValue::Refer(entry.get_uuid())) })
                .collect(),
        ));

        let mut pre_cascade_delete_candidates = self
            .internal_search(references_filt)
            .inspect_err(|err| error!(?err, "unable to find reference entries"))?;
        {
            let access = self.get_accesscontrols();
            // Validate that the requestor has access to delete the cascade candidates as well, so that a crafted referral object doesn't naturally cascade into deleting things they don't have permission over
            let op_allow = access
                .delete_allow_operation(de, &pre_cascade_delete_candidates)
                .map_err(|e| {
                    admin_error!("Failed to check delete access {:?}", e);
                    e
                })?;
            if !op_allow {
                return Err(OperationError::AccessDenied);
            }
        }

        #[cfg(any(test, debug_assertions))]
        {
            use std::collections::BTreeSet;

            let candidate_uuids: BTreeSet<_> =
                pre_candidates.iter().map(|e| e.get_uuid()).collect();
            let ref_candidate_uuids: BTreeSet<_> = pre_cascade_delete_candidates
                .iter()
                .map(|e| e.get_uuid())
                .collect();

            assert!(candidate_uuids.is_disjoint(&ref_candidate_uuids));
        }

        let mut cascade_delete_candidates: Vec<Entry<EntryInvalid, EntryCommitted>> =
            pre_cascade_delete_candidates
                .iter()
                // Invalidate and assign change id's
                .map(|er| {
                    er.as_ref()
                        .clone()
                        .invalidate(self.cid.clone(), &self.trim_cid)
                })
                // These entries are the ones that are being deleted by cascade, so we mark them
                // as such.
                .map(|mut entry| {
                    if let Some(refer_uuid) = entry.get_ava_single_refer(Attribute::Refers) {
                        // Stash the entry that triggered our deleted in this attribute. This
                        // allows us to restore this linkage on revive, and also being a uuid instead
                        // of a refers means that refint won't clean this linkage.
                        entry.add_ava(Attribute::CascadeDeleted, Value::Uuid(refer_uuid));
                    };
                    entry
                })
                .collect();

        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            // Invalidate and assign change id's
            .map(|er| {
                er.as_ref()
                    .clone()
                    .invalidate(self.cid.clone(), &self.trim_cid)
            })
            .collect();

        pre_candidates.append(&mut pre_cascade_delete_candidates);
        candidates.append(&mut cascade_delete_candidates);

        trace!(?candidates, "delete: candidates");

        // If we need to build a memorial to the candidate, ask plugins now.
        let mut memorials: BTreeMap<Uuid, EntryInitNew> = BTreeMap::new();

        Plugins::run_build_memorials(self, &pre_candidates, &mut memorials, de).inspect_err(
            |err| {
                error!(?err, "Delete operation failed (plugin)");
            },
        )?;

        if !memorials.is_empty() {
            let candidates: Vec<Entry<EntryInvalid, EntryNew>> = memorials
                .into_iter()
                .map(|(source_uuid, mut entry)| {
                    // First, ensure that the only class is Memorial.
                    entry.remove_ava(&Attribute::Class);
                    entry.set_ava_set(&Attribute::Uuid, ValueSetUuid::new(Uuid::new_v4()));
                    entry.set_ava_set(&Attribute::InMemoriam, ValueSetUuid::new(source_uuid));
                    entry.set_ava_set(
                        &Attribute::Class,
                        vs_iutf8![EntryClass::Object.into(), EntryClass::Memorial.into()],
                    );
                    // Now setup replication metadata so that we can put this entry
                    // into the invalid state.
                    entry.assign_cid(self.cid.clone(), &self.schema)
                })
                .collect();

            if candidates.iter().any(|e| e.mask_recycled_ts().is_none()) {
                warn!("Refusing to create invalid entries that are attempting to bypass replication state machine.");
                return Err(OperationError::AccessDenied);
            }

            let norm_cand = candidates
                .into_iter()
                .map(|e| {
                    e.validate(&self.schema)
                        .map_err(|e| {
                            error!("Schema Violation in create validate {:?}", e);
                            OperationError::SchemaViolation(e)
                        })
                        .map(|e| {
                            // Then seal the changes?
                            e.seal(&self.schema)
                        })
                })
                .collect::<Result<Vec<EntrySealedNew>, _>>()?;

            let _commit_cand = self
                .be_txn
                .create(&self.cid, norm_cand)
                .inspect_err(|err| {
                    error!(?err, "betxn create failure");
                })?;
        }

        // Pre delete plugs
        Plugins::run_pre_delete(self, &mut candidates, de).inspect_err(|err| {
            error!(?err, "Delete operation failed (plugin)");
        })?;

        trace!(?candidates, "delete: now marking candidates as recycled");

        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
            .into_iter()
            .map(|e| {
                e.to_recycled()
                    .validate(&self.schema)
                    .map_err(|e| {
                        admin_error!(err = ?e, "Schema Violation in delete validate");
                        OperationError::SchemaViolation(e)
                    })
                    // seal if it worked.
                    .map(|e| e.seal(&self.schema))
            })
            .collect();

        let del_cand: Vec<Entry<_, _>> = res?;

        self.be_txn
            .modify(&self.cid, &pre_candidates, &del_cand)
            .map_err(|e| {
                // be_txn is dropped, ie aborted here.
                admin_error!("Delete operation failed (backend), {:?}", e);
                e
            })?;

        // Post delete plugins
        Plugins::run_post_delete(self, &del_cand, de).map_err(|e| {
            admin_error!("Delete operation failed (plugin), {:?}", e);
            e
        })?;

        // We have finished all plugs and now have a successful operation - flag if
        // schema or acp requires reload.
        if !self.changed_flags.contains(ChangeFlag::SCHEMA)
            && del_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::ClassType.into())
                    || e.attribute_equality(Attribute::Class, &EntryClass::AttributeType.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::SCHEMA)
        }
        if !self.changed_flags.contains(ChangeFlag::ACP)
            && del_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::ACP)
        }

        if !self.changed_flags.contains(ChangeFlag::APPLICATION)
            && del_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Application.into()))
        {
            self.changed_flags.insert(ChangeFlag::APPLICATION)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2)
            && del_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
            && del_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into()))
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2_CLIENT)
        }

        if !self.changed_flags.contains(ChangeFlag::FEATURE)
            && del_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Feature.into()))
        {
            self.changed_flags.insert(ChangeFlag::FEATURE)
        }

        if !self.changed_flags.contains(ChangeFlag::DOMAIN)
            && del_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_DOMAIN_INFO))
        {
            self.changed_flags.insert(ChangeFlag::DOMAIN)
        }

        if !self.changed_flags.contains(ChangeFlag::SYSTEM_CONFIG)
            && del_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_SYSTEM_CONFIG))
        {
            self.changed_flags.insert(ChangeFlag::SYSTEM_CONFIG)
        }

        if !self.changed_flags.contains(ChangeFlag::SYNC_AGREEMENT)
            && del_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::SyncAccount.into()))
        {
            self.changed_flags.insert(ChangeFlag::SYNC_AGREEMENT)
        }

        if !self.changed_flags.contains(ChangeFlag::KEY_MATERIAL)
            && del_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::KeyProvider.into())
                    || e.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::KEY_MATERIAL)
        }

        self.changed_uuid
            .extend(del_cand.iter().map(|e| e.get_uuid()));

        trace!(
            changed = ?self.changed_flags.iter_names().collect::<Vec<_>>(),
        );

        // Send result
        if de.ident.is_internal() {
            trace!("Delete operation success");
        } else {
            admin_info!("Delete operation success");
        }
        Ok(())
    }

    pub fn internal_delete(
        &mut self,
        filter: &Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let de = DeleteEvent::new_internal(f_valid);
        self.delete(&de)
    }

    pub fn internal_delete_uuid(&mut self, target_uuid: Uuid) -> Result<(), OperationError> {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let de = DeleteEvent::new_internal(f_valid);
        self.delete(&de)
    }

    pub fn internal_delete_uuid_if_exists(
        &mut self,
        target_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
        self.internal_delete_if_exists(&filter)
    }

    pub fn internal_delete_if_exists(
        &mut self,
        filter: &Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let ee = ExistsEvent::new_internal(f_valid.clone());
        // Submit it
        if self.exists(&ee)? {
            let de = DeleteEvent::new_internal(f_valid);
            self.delete(&de)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::server::CreateEvent;
    use crypto_glue::{traits::DecodePem, x509::Certificate};

    #[qs_test]
    async fn test_delete(server: &QueryServer) {
        // Create
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson2")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63932"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson2"))
        );

        let e3 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson3")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63933"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson3"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2, e3]);

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Delete filter is syntax invalid
        let de_inv = DeleteEvent::new_internal_invalid(filter!(f_pres(Attribute::NonExist)));
        assert!(server_txn.delete(&de_inv).is_err());

        // Delete deletes nothing
        let de_empty = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::Uuid,
            PartialValue::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-000000000000"))
        )));
        assert!(server_txn.delete(&de_empty).is_err());

        // Delete matches one
        let de_sin = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::Name,
            PartialValue::new_iname("testperson3")
        )));
        assert!(server_txn.delete(&de_sin).is_ok());

        // Delete matches many
        let de_mult = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::Description,
            PartialValue::new_utf8s("testperson")
        )));
        assert!(server_txn.delete(&de_mult).is_ok());

        assert!(server_txn.commit().is_ok());
    }

    /// Test that cascade delete is denied when the caller lacks delete access
    /// to the cascade-deleted entries. This prevents an attacker from deleting
    /// an entry that refers to a protected entry, which would cascade-delete
    /// the protected entry without access control.
    ///
    /// Scenario:
    /// - Attacker-controlled service account in group "limited_delete_group"
    /// - ACP grants delete only for entries named "deletable_target"
    /// - "deletable_target" is an entry the attacker can delete
    /// - "protected_cert" is a ClientCertificate that Refers to "deletable_target"
    ///   (cascade victim) — NOT covered by the ACP
    /// - Deleting "deletable_target" should FAIL because cascade would delete
    ///   "protected_cert" which the attacker cannot delete
    #[qs_test]
    async fn test_delete_cascade_access_denied(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await.unwrap();

        let deletable_uuid = uuid!("a0000000-0000-0000-0000-000000000001");
        let protected_cert_uuid = uuid!("a0000000-0000-0000-0000-000000000002");
        let attacker_group_uuid = uuid!("a0000000-0000-0000-0000-000000000003");
        let attacker_acct_uuid = uuid!("a0000000-0000-0000-0000-000000000004");
        let acp_uuid = uuid!("a0000000-0000-0000-0000-000000000005");

        let cert_data = Box::new(
            Certificate::from_pem(crate::constants::TEST_X509_CERT_DATA)
                .expect("Unable to parse test X509 cert data"),
        );

        // Group that receives the ACP
        let e_attacker_group = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("limited_delete_group")),
            (Attribute::Uuid, Value::Uuid(attacker_group_uuid)),
            (Attribute::Member, Value::Refer(attacker_acct_uuid))
        );

        // Attacker's service account (member of the group)
        let e_attacker = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("attacker_account")),
            (Attribute::Uuid, Value::Uuid(attacker_acct_uuid)),
            (Attribute::DisplayName, Value::new_utf8s("attacker_account"))
        );

        // The entry the attacker is allowed to delete
        let e_deletable = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("deletable_target")),
            (Attribute::Uuid, Value::Uuid(deletable_uuid)),
            (Attribute::Description, Value::new_utf8s("deletable")),
            (Attribute::DisplayName, Value::new_utf8s("deletable_target"))
        );

        // Protected entry that Refers to the deletable target — cascade victim.
        // The attacker has NO delete ACP covering this entry.
        let e_protected_cert = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClientCertificate.to_value()),
            (Attribute::Uuid, Value::Uuid(protected_cert_uuid)),
            (Attribute::Refers, Value::Refer(deletable_uuid)),
            (
                Attribute::Certificate,
                Value::Certificate(cert_data.clone())
            )
        );

        // ACP: only allow deletion of entries named "deletable_target"
        // This does NOT cover the ClientCertificate entry.
        let e_acp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Name, Value::new_iname("acp_limited_delete")),
            (Attribute::Uuid, Value::Uuid(acp_uuid)),
            (
                Attribute::AcpReceiverGroup,
                Value::Refer(attacker_group_uuid)
            ),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"eq\":[\"name\",\"deletable_target\"]}")
                    .expect("filter")
            )
        );

        // Also need a search ACP so impersonate_search_valid can find the target
        let acp_search_uuid = uuid!("a0000000-0000-0000-0000-000000000006");
        let e_acp_search = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Name, Value::new_iname("acp_limited_search")),
            (Attribute::Uuid, Value::Uuid(acp_search_uuid)),
            (
                Attribute::AcpReceiverGroup,
                Value::Refer(attacker_group_uuid)
            ),
            (
                Attribute::AcpTargetScope,
                // Broad search scope so the target can be found
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Class)),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Uuid)),
            (
                Attribute::AcpSearchAttr,
                Value::from(Attribute::Description)
            ),
            (
                Attribute::AcpSearchAttr,
                Value::from(Attribute::DisplayName)
            )
        );

        let ce = CreateEvent::new_internal(vec![
            e_attacker_group,
            e_attacker,
            e_deletable,
            e_protected_cert,
            e_acp,
            e_acp_search,
        ]);
        assert!(server_txn.create(&ce).is_ok());
        assert!(server_txn.commit().is_ok());

        // Now attempt to delete as the attacker account
        let mut server_txn = server.write(curtime).await.unwrap();
        let attacker_entry = server_txn
            .internal_search_uuid(attacker_acct_uuid)
            .expect("attacker account not found");

        let de = DeleteEvent::new_impersonate_entry(
            attacker_entry,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("deletable_target")
            )),
        );

        // Delete should FAIL: cascade would delete protected_cert which
        // the attacker's ACP does not cover.
        let result = server_txn.delete(&de);
        assert!(
            matches!(result, Err(OperationError::AccessDenied)),
            "Expected AccessDenied for cascade delete of inaccessible entry, got {:?}",
            result
        );

        // Verify the target entry still exists (delete was fully rejected)
        assert!(server_txn
            .internal_exists_uuid(deletable_uuid)
            .expect("check failed"));
        // Verify the protected cert still exists
        assert!(server_txn
            .internal_exists_uuid(protected_cert_uuid)
            .expect("check failed"));

        drop(server_txn);
    }

    /// Test that cascade delete succeeds when the caller has delete access
    /// to both the primary target AND all cascade-deleted entries.
    ///
    /// Scenario:
    /// - Same setup as test_delete_cascade_access_denied, but the ACP covers
    ///   both the target entry and the ClientCertificate cascade victim.
    /// - Deleting the target should succeed, cascade-deleting the cert.
    #[qs_test]
    async fn test_delete_cascade_access_granted(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await.unwrap();

        let deletable_uuid = uuid!("b0000000-0000-0000-0000-000000000001");
        let cascade_cert_uuid = uuid!("b0000000-0000-0000-0000-000000000002");
        let group_uuid = uuid!("b0000000-0000-0000-0000-000000000003");
        let acct_uuid = uuid!("b0000000-0000-0000-0000-000000000004");
        let acp_uuid = uuid!("b0000000-0000-0000-0000-000000000005");

        let cert_data = Box::new(
            Certificate::from_pem(crate::constants::TEST_X509_CERT_DATA)
                .expect("Unable to parse test X509 cert data"),
        );

        let e_group = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("broad_delete_group")),
            (Attribute::Uuid, Value::Uuid(group_uuid)),
            (Attribute::Member, Value::Refer(acct_uuid))
        );

        let e_acct = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("broad_delete_account")),
            (Attribute::Uuid, Value::Uuid(acct_uuid)),
            (
                Attribute::DisplayName,
                Value::new_utf8s("broad_delete_account")
            )
        );

        let e_deletable = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("target_entry")),
            (Attribute::Uuid, Value::Uuid(deletable_uuid)),
            (Attribute::Description, Value::new_utf8s("target")),
            (Attribute::DisplayName, Value::new_utf8s("target_entry"))
        );

        let e_cascade_cert = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClientCertificate.to_value()),
            (Attribute::Uuid, Value::Uuid(cascade_cert_uuid)),
            (Attribute::Refers, Value::Refer(deletable_uuid)),
            (
                Attribute::Certificate,
                Value::Certificate(cert_data.clone())
            )
        );

        // ACP: broad delete covering all entries with class present
        let e_acp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Name, Value::new_iname("acp_broad_delete")),
            (Attribute::Uuid, Value::Uuid(acp_uuid)),
            (Attribute::AcpReceiverGroup, Value::Refer(group_uuid)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            )
        );

        let acp_search_uuid = uuid!("b0000000-0000-0000-0000-000000000006");
        let e_acp_search = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Name, Value::new_iname("acp_broad_search")),
            (Attribute::Uuid, Value::Uuid(acp_search_uuid)),
            (Attribute::AcpReceiverGroup, Value::Refer(group_uuid)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Class)),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Uuid)),
            (
                Attribute::AcpSearchAttr,
                Value::from(Attribute::Description)
            ),
            (
                Attribute::AcpSearchAttr,
                Value::from(Attribute::DisplayName)
            )
        );

        let ce = CreateEvent::new_internal(vec![
            e_group,
            e_acct,
            e_deletable,
            e_cascade_cert,
            e_acp,
            e_acp_search,
        ]);
        assert!(server_txn.create(&ce).is_ok());
        assert!(server_txn.commit().is_ok());

        // Delete as the account with broad access
        let mut server_txn = server.write(curtime).await.unwrap();
        let acct_entry = server_txn
            .internal_search_uuid(acct_uuid)
            .expect("account not found");

        let de = DeleteEvent::new_impersonate_entry(
            acct_entry,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("target_entry")
            )),
        );

        // Delete should succeed: the ACP covers both the target and the cascade cert
        let result = server_txn.delete(&de);
        assert!(
            result.is_ok(),
            "Expected cascade delete to succeed with full access, got {:?}",
            result
        );

        assert!(server_txn.commit().is_ok());

        // Verify both entries are gone
        let mut server_txn = server.write(curtime).await.unwrap();
        assert!(!server_txn
            .internal_exists_uuid(deletable_uuid)
            .expect("check failed"));
        assert!(!server_txn
            .internal_exists_uuid(cascade_cert_uuid)
            .expect("check failed"));
    }
}

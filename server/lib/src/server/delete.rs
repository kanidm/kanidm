use crate::prelude::*;
use crate::server::DeleteEvent;
use crate::server::{ChangeFlag, Plugins};

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
        let pre_candidates = self
            .impersonate_search_valid(de.filter.clone(), de.filter_orig.clone(), &de.ident)
            .map_err(|e| {
                admin_error!("delete: error in pre-candidate selection {:?}", e);
                e
            })?;

        // Apply access controls to reduce the set if required.
        // delete_allow_operation
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

        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            // Invalidate and assign change id's
            .map(|er| {
                er.as_ref()
                    .clone()
                    .invalidate(self.cid.clone(), &self.trim_cid)
            })
            .collect();

        trace!(?candidates, "delete: candidates");

        // Pre delete plugs
        Plugins::run_pre_delete(self, &mut candidates, de).map_err(|e| {
            admin_error!("Delete operation failed (plugin), {:?}", e);
            e
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

    #[instrument(level = "debug", skip(self))]
    pub fn internal_delete_uuid_if_exists(
        &mut self,
        target_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
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
}

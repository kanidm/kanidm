use crate::prelude::*;
use crate::server::CreateEvent;
use crate::server::Plugins;

impl<'a> QueryServerWriteTransaction<'a> {
    #[instrument(level = "debug", skip_all)]
    pub fn create(&mut self, ce: &CreateEvent) -> Result<(), OperationError> {
        // The create event is a raw, read only representation of the request
        // that was made to us, including information about the identity
        // performing the request.
        if !ce.ident.is_internal() {
            security_info!(name = %ce.ident, "create initiator");
        }

        if ce.entries.is_empty() {
            request_error!("create: empty create request");
            return Err(OperationError::EmptyRequest);
        }

        // TODO #67: Do we need limits on number of creates, or do we constraint
        // based on request size in the frontend?

        // Copy the entries to a writeable form, this involves assigning a
        // change id so we can track what's happening.
        let candidates: Vec<Entry<EntryInit, EntryNew>> = ce.entries.clone();

        // Do we have rights to perform these creates?
        // create_allow_operation
        let access = self.get_accesscontrols();
        let op_allow = access
            .create_allow_operation(ce, &candidates)
            .map_err(|e| {
                admin_error!("Failed to check create access {:?}", e);
                e
            })?;
        if !op_allow {
            return Err(OperationError::AccessDenied);
        }

        // Before we assign replication metadata, we need to assert these entries
        // are valid to create within the set of replication transitions. This
        // means they *can not* be recycled or tombstones!
        if candidates.iter().any(|e| e.mask_recycled_ts().is_none()) {
            admin_warn!("Refusing to create invalid entries that are attempting to bypass replication state machine.");
            return Err(OperationError::AccessDenied);
        }

        // Assign our replication metadata now, since we can proceed with this operation.
        let mut candidates: Vec<Entry<EntryInvalid, EntryNew>> = candidates
            .into_iter()
            .map(|e| e.assign_cid(self.cid.clone(), &self.schema))
            .collect();

        // run any pre plugins, giving them the list of mutable candidates.
        // pre-plugins are defined here in their correct order of calling!
        // I have no intent to make these dynamic or configurable.

        Plugins::run_pre_create_transform(self, &mut candidates, ce).map_err(|e| {
            admin_error!("Create operation failed (pre_transform plugin), {:?}", e);
            e
        })?;

        // NOTE: This is how you map from Vec<Result<T>> to Result<Vec<T>>
        // remember, that you only get the first error and the iter terminates.

        // eprintln!("{:?}", candidates);

        // Now, normalise AND validate!

        let norm_cand = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation in create validate {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| {
                        // Then seal the changes?
                        e.seal(&self.schema)
                    })
            })
            .collect::<Result<Vec<EntrySealedNew>, _>>()?;

        // Run any pre-create plugins now with schema validated entries.
        // This is important for normalisation of certain types IE class
        // or attributes for these checks.
        Plugins::run_pre_create(self, &norm_cand, ce).map_err(|e| {
            admin_error!("Create operation failed (plugin), {:?}", e);
            e
        })?;

        // We may change from ce.entries later to something else?
        let commit_cand = self.be_txn.create(&self.cid, norm_cand).map_err(|e| {
            admin_error!("betxn create failure {:?}", e);
            e
        })?;

        // Run any post plugins

        Plugins::run_post_create(self, &commit_cand, ce).map_err(|e| {
            admin_error!("Create operation failed (post plugin), {:?}", e);
            e
        })?;

        // We have finished all plugs and now have a successful operation - flag if
        // schema or acp requires reload.
        if !self.changed_schema {
            self.changed_schema = commit_cand.iter().any(|e| {
                e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                    || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
            });
        }
        if !self.changed_acp {
            self.changed_acp = commit_cand
                .iter()
                .any(|e| e.attribute_equality("class", &PVCLASS_ACP));
        }
        if !self.changed_oauth2 {
            self.changed_oauth2 = commit_cand
                .iter()
                .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS));
        }
        if !self.changed_domain {
            self.changed_domain = commit_cand
                .iter()
                .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO));
        }

        self.changed_uuid
            .extend(commit_cand.iter().map(|e| e.get_uuid()));
        trace!(
            schema_reload = ?self.changed_schema,
            acp_reload = ?self.changed_acp,
            oauth2_reload = ?self.changed_oauth2,
            domain_reload = ?self.changed_domain,
        );

        // We are complete, finalise logging and return

        if ce.ident.is_internal() {
            trace!("Create operation success");
        } else {
            admin_info!("Create operation success");
        }
        Ok(())
    }

    pub fn internal_create(
        &mut self,
        entries: Vec<Entry<EntryInit, EntryNew>>,
    ) -> Result<(), OperationError> {
        let ce = CreateEvent::new_internal(entries);
        self.create(&ce)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::sync::Arc;

    #[qs_test]
    async fn test_create_user(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let filt = filter!(f_eq("name", PartialValue::new_iname("testperson")));
        let admin = server_txn.internal_search_uuid(UUID_ADMIN).expect("failed");

        let se1 = unsafe { SearchEvent::new_impersonate_entry(admin, filt) };

        let mut e = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson")),
            ("spn", Value::new_spn_str("testperson", "example.com")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e.clone()]);

        let r1 = server_txn.search(&se1).expect("search failure");
        assert!(r1.is_empty());

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        let r2 = server_txn.search(&se1).expect("search failure");
        debug!("--> {:?}", r2);
        assert!(r2.len() == 1);

        // We apply some member-of in the server now, so we add these before we seal.
        e.add_ava("class", Value::new_class("memberof"));
        e.add_ava("memberof", Value::Refer(UUID_IDM_ALL_PERSONS));
        e.add_ava("directmemberof", Value::Refer(UUID_IDM_ALL_PERSONS));
        e.add_ava("memberof", Value::Refer(UUID_IDM_ALL_ACCOUNTS));
        e.add_ava("directmemberof", Value::Refer(UUID_IDM_ALL_ACCOUNTS));

        let expected = unsafe { vec![Arc::new(e.into_sealed_committed())] };

        assert_eq!(r2, expected);

        assert!(server_txn.commit().is_ok());
    }

    #[qs_pair_test]
    async fn test_pair_create_user(server_a: &QueryServer, server_b: &QueryServer) {
        let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
        let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;

        // Create on server a
        let filt = filter!(f_eq("name", PartialValue::new_iname("testperson")));

        let admin = server_a_txn
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let se_a = unsafe { SearchEvent::new_impersonate_entry(admin, filt.clone()) };

        let admin = server_b_txn
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let se_b = unsafe { SearchEvent::new_impersonate_entry(admin, filt) };

        let e = entry_init!(
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson")),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let cr = server_a_txn.internal_create(vec![e.clone()]);
        assert!(cr.is_ok());

        let r1 = server_a_txn.search(&se_a).expect("search failure");
        assert!(!r1.is_empty());

        // Not on sb
        let r2 = server_b_txn.search(&se_b).expect("search failure");
        assert!(r2.is_empty());

        let cr = server_b_txn.internal_create(vec![e]);
        assert!(cr.is_ok());

        // Now is present
        let r2 = server_b_txn.search(&se_b).expect("search failure");
        assert!(!r2.is_empty());

        assert!(server_a_txn.commit().is_ok());
        assert!(server_b_txn.commit().is_ok());
    }
}

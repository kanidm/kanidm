use crate::access::AccessControlsTransaction;
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

        let res: Result<Vec<Entry<EntrySealed, EntryNew>>, OperationError> = candidates
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
            .collect();

        let norm_cand: Vec<Entry<_, _>> = res?;

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
        if !self.changed_schema.get() {
            self.changed_schema.set(commit_cand.iter().any(|e| {
                e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                    || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
            }))
        }
        if !self.changed_acp.get() {
            self.changed_acp.set(
                commit_cand
                    .iter()
                    .any(|e| e.attribute_equality("class", &PVCLASS_ACP)),
            )
        }
        if !self.changed_oauth2.get() {
            self.changed_oauth2.set(
                commit_cand
                    .iter()
                    .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS)),
            )
        }
        if !self.changed_domain.get() {
            self.changed_domain.set(
                commit_cand
                    .iter()
                    .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)),
            )
        }

        let cu = self.changed_uuid.as_ptr();
        unsafe {
            (*cu).extend(commit_cand.iter().map(|e| e.get_uuid()));
        }
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
}

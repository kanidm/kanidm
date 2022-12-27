use crate::access::AccessControlsTransaction;
use crate::plugins::Plugins;
use crate::prelude::*;
use crate::server::DeleteEvent;

impl<'a> QueryServerWriteTransaction<'a> {
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
            request_error!(filter = ?de.filter, "delete: no candidates match filter");
            return Err(OperationError::NoMatchingEntries);
        };

        if pre_candidates.iter().any(|e| e.mask_tombstone().is_none()) {
            admin_warn!("Refusing to delete entries which may be an attempt to bypass replication state machine.");
            return Err(OperationError::AccessDenied);
        }

        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            // Invalidate and assign change id's
            .map(|er| er.as_ref().clone().invalidate(self.cid.clone()))
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
        if !self.changed_schema.get() {
            self.changed_schema.set(del_cand.iter().any(|e| {
                e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                    || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
            }))
        }
        if !self.changed_acp.get() {
            self.changed_acp.set(
                del_cand
                    .iter()
                    .any(|e| e.attribute_equality("class", &PVCLASS_ACP)),
            )
        }
        if !self.changed_oauth2.get() {
            self.changed_oauth2.set(
                del_cand
                    .iter()
                    .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS)),
            )
        }
        if !self.changed_domain.get() {
            self.changed_domain.set(
                del_cand
                    .iter()
                    .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)),
            )
        }

        let cu = self.changed_uuid.as_ptr();
        unsafe {
            (*cu).extend(del_cand.iter().map(|e| e.get_uuid()));
        }

        trace!(
            schema_reload = ?self.changed_schema,
            acp_reload = ?self.changed_acp,
            oauth2_reload = ?self.changed_oauth2,
            domain_reload = ?self.changed_domain,
        );

        // Send result
        if de.ident.is_internal() {
            trace!("Delete operation success");
        } else {
            admin_info!("Delete operation success");
        }
        Ok(())
    }
}

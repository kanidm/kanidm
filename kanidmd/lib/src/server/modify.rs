use std::sync::Arc;

use crate::access::AccessControlsTransaction;
use crate::event::ModifyEvent;
use crate::event::SearchEvent;
use crate::plugins::Plugins;
use crate::prelude::*;

pub(crate) struct ModifyPartial<'a> {
    pub norm_cand: Vec<Entry<EntrySealed, EntryCommitted>>,
    pub pre_candidates: Vec<Arc<Entry<EntrySealed, EntryCommitted>>>,
    pub me: &'a ModifyEvent,
}

impl<'a> QueryServerWriteTransaction<'a> {
    #[instrument(level = "debug", skip_all)]
    pub fn modify(&mut self, me: &ModifyEvent) -> Result<(), OperationError> {
        let mp = unsafe { self.modify_pre_apply(me)? };
        if let Some(mp) = mp {
            self.modify_apply(mp)
        } else {
            // No action to apply, the pre-apply said nothing to be done.
            Ok(())
        }
    }

    /// Unsafety: This is unsafe because you need to be careful about how you handle and check
    /// the Ok(None) case which occurs during internal operations, and that you DO NOT re-order
    /// and call multiple pre-applies at the same time, else you can cause DB corruption.
    #[instrument(level = "debug", skip_all)]
    pub(crate) unsafe fn modify_pre_apply<'x>(
        &mut self,
        me: &'x ModifyEvent,
    ) -> Result<Option<ModifyPartial<'x>>, OperationError> {
        // Get the candidates.
        // Modify applies a modlist to a filter, so we need to internal search
        // then apply.
        if !me.ident.is_internal() {
            security_info!(name = %me.ident, "modify initiator");
        }

        // Validate input.

        // Is the modlist non zero?
        if me.modlist.is_empty() {
            request_error!("modify: empty modify request");
            return Err(OperationError::EmptyRequest);
        }

        // Is the modlist valid?
        // This is now done in the event transform

        // Is the filter invalid to schema?
        // This is now done in the event transform

        // This also checks access controls due to use of the impersonation.
        let pre_candidates = self
            .impersonate_search_valid(me.filter.clone(), me.filter_orig.clone(), &me.ident)
            .map_err(|e| {
                admin_error!("modify: error in pre-candidate selection {:?}", e);
                e
            })?;

        if pre_candidates.is_empty() {
            if me.ident.is_internal() {
                trace!(
                    "modify: no candidates match filter ... continuing {:?}",
                    me.filter
                );
                return Ok(None);
            } else {
                request_error!(
                    "modify: no candidates match filter, failure {:?}",
                    me.filter
                );
                return Err(OperationError::NoMatchingEntries);
            }
        };

        trace!("modify: pre_candidates -> {:?}", pre_candidates);
        trace!("modify: modlist -> {:?}", me.modlist);

        // Are we allowed to make the changes we want to?
        // modify_allow_operation
        let access = self.get_accesscontrols();
        let op_allow = access
            .modify_allow_operation(me, &pre_candidates)
            .map_err(|e| {
                admin_error!("Unable to check modify access {:?}", e);
                e
            })?;
        if !op_allow {
            return Err(OperationError::AccessDenied);
        }

        // Clone a set of writeables.
        // Apply the modlist -> Remember, we have a set of origs
        // and the new modified ents.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| er.as_ref().clone().invalidate(self.cid.clone()))
            .collect();

        candidates.iter_mut().try_for_each(|er| {
            er.apply_modlist(&me.modlist).map_err(|e| {
                error!("Modification failed for {:?}", er.get_uuid());
                e
            })
        })?;

        trace!("modify: candidates -> {:?}", candidates);

        // Did any of the candidates now become masked?
        if std::iter::zip(
            pre_candidates
                .iter()
                .map(|e| e.mask_recycled_ts().is_none()),
            candidates.iter().map(|e| e.mask_recycled_ts().is_none()),
        )
        .any(|(a, b)| a != b)
        {
            admin_warn!("Refusing to apply modifications that are attempting to bypass replication state machine.");
            return Err(OperationError::AccessDenied);
        }

        // Pre mod plugins
        // We should probably supply the pre-post cands here.
        Plugins::run_pre_modify(self, &mut candidates, me).map_err(|e| {
            admin_error!("Pre-Modify operation failed (plugin), {:?}", e);
            e
        })?;

        // NOTE: There is a potential optimisation here, where if
        // candidates == pre-candidates, then we don't need to store anything
        // because we effectively just did an assert. However, like all
        // optimisations, this could be premature - so we for now, just
        // do the CORRECT thing and recommit as we may find later we always
        // want to add CSN's or other.

        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
            .into_iter()
            .map(|entry| {
                entry
                    .validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation in validation of modify_pre_apply {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|entry| entry.seal(&self.schema))
            })
            .collect();

        let norm_cand: Vec<Entry<_, _>> = res?;

        Ok(Some(ModifyPartial {
            norm_cand,
            pre_candidates,
            me,
        }))
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn modify_apply(&mut self, mp: ModifyPartial<'_>) -> Result<(), OperationError> {
        let ModifyPartial {
            norm_cand,
            pre_candidates,
            me,
        } = mp;

        // Backend Modify
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("Modify operation failed (backend), {:?}", e);
                e
            })?;

        // Post Plugins
        //
        // memberOf actually wants the pre cand list and the norm_cand list to see what
        // changed. Could be optimised, but this is correct still ...
        Plugins::run_post_modify(self, &pre_candidates, &norm_cand, me).map_err(|e| {
            admin_error!("Post-Modify operation failed (plugin), {:?}", e);
            e
        })?;

        // We have finished all plugs and now have a successful operation - flag if
        // schema or acp requires reload. Remember, this is a modify, so we need to check
        // pre and post cands.
        if !self.changed_schema.get() {
            self.changed_schema.set(
                norm_cand
                    .iter()
                    .chain(pre_candidates.iter().map(|e| e.as_ref()))
                    .any(|e| {
                        e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                            || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
                    }),
            )
        }
        if !self.changed_acp.get() {
            self.changed_acp.set(
                norm_cand
                    .iter()
                    .chain(pre_candidates.iter().map(|e| e.as_ref()))
                    .any(|e| e.attribute_equality("class", &PVCLASS_ACP)),
            )
        }
        if !self.changed_oauth2.get() {
            self.changed_oauth2.set(
                norm_cand
                    .iter()
                    .chain(pre_candidates.iter().map(|e| e.as_ref()))
                    .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS)),
            )
        }
        if !self.changed_domain.get() {
            self.changed_domain.set(
                norm_cand
                    .iter()
                    .chain(pre_candidates.iter().map(|e| e.as_ref()))
                    .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)),
            )
        }

        let cu = self.changed_uuid.as_ptr();
        unsafe {
            (*cu).extend(
                norm_cand
                    .iter()
                    .map(|e| e.get_uuid())
                    .chain(pre_candidates.iter().map(|e| e.get_uuid())),
            );
        }

        trace!(
            schema_reload = ?self.changed_schema,
            acp_reload = ?self.changed_acp,
            oauth2_reload = ?self.changed_oauth2,
            domain_reload = ?self.changed_domain,
        );

        // return
        if me.ident.is_internal() {
            trace!("Modify operation success");
        } else {
            admin_info!("Modify operation success");
        }
        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    /// Used in conjunction with internal_apply_writable, to get a pre/post
    /// pair, where post is pre-configured with metadata to allow
    /// modificiation before submit back to internal_apply_writable
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn internal_search_writeable(
        &self,
        filter: &Filter<FilterInvalid>,
    ) -> Result<Vec<EntryTuple>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let se = SearchEvent::new_internal(f_valid);
        self.search(&se).map(|vs| {
            vs.into_iter()
                .map(|e| {
                    let writeable = e.as_ref().clone().invalidate(self.cid.clone());
                    (e, writeable)
                })
                .collect()
        })
    }

    /// Allows writing batches of modified entries without going through
    /// the modlist path. This allows more effecient batch transformations
    /// such as memberof, but at the expense that YOU must guarantee you
    /// uphold all other plugin and state rules that are important. You
    /// probably want modify instead.
    #[allow(clippy::needless_pass_by_value)]
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn internal_apply_writable(
        &self,
        pre_candidates: Vec<Arc<EntrySealedCommitted>>,
        candidates: Vec<Entry<EntryInvalid, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        if pre_candidates.is_empty() && candidates.is_empty() {
            // No action needed.
            return Ok(());
        }

        if pre_candidates.len() != candidates.len() {
            admin_error!("internal_apply_writable - cand lengths differ");
            return Err(OperationError::InvalidRequestState);
        }

        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|e| {
                        admin_error!(
                            "Schema Violation in internal_apply_writable validate: {:?}",
                            e
                        );
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| e.seal(&self.schema))
            })
            .collect();

        let norm_cand: Vec<Entry<_, _>> = res?;

        if cfg!(debug_assertions) {
            pre_candidates
                .iter()
                .zip(norm_cand.iter())
                .try_for_each(|(pre, post)| {
                    if pre.get_uuid() == post.get_uuid() {
                        Ok(())
                    } else {
                        admin_error!("modify - cand sets not correctly aligned");
                        Err(OperationError::InvalidRequestState)
                    }
                })?;
        }

        // Backend Modify
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("Modify operation failed (backend), {:?}", e);
                e
            })?;

        if !self.changed_schema.get() {
            self.changed_schema.set(
                norm_cand
                    .iter()
                    .chain(pre_candidates.iter().map(|e| e.as_ref()))
                    .any(|e| {
                        e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                            || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
                    }),
            )
        }
        if !self.changed_acp.get() {
            self.changed_acp.set(
                norm_cand
                    .iter()
                    .chain(pre_candidates.iter().map(|e| e.as_ref()))
                    .any(|e| e.attribute_equality("class", &PVCLASS_ACP)),
            )
        }
        if !self.changed_oauth2.get() {
            self.changed_oauth2.set(
                norm_cand
                    .iter()
                    .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS)),
            )
        }
        if !self.changed_domain.get() {
            self.changed_domain.set(
                norm_cand
                    .iter()
                    .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)),
            )
        }
        let cu = self.changed_uuid.as_ptr();
        unsafe {
            (*cu).extend(
                norm_cand
                    .iter()
                    .map(|e| e.get_uuid())
                    .chain(pre_candidates.iter().map(|e| e.get_uuid())),
            );
        }
        trace!(
            schema_reload = ?self.changed_schema,
            acp_reload = ?self.changed_acp,
            oauth2_reload = ?self.changed_oauth2,
            domain_reload = ?self.changed_domain,
        );

        trace!("Modify operation success");
        Ok(())
    }
}

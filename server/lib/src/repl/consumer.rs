use super::proto::*;
use crate::plugins::Plugins;
use crate::prelude::*;

impl<'a> QueryServerReadTransaction<'a> {
    // Get the current state of "where we are up to"
    //
    // There are two approaches we can use here. We can either store a cookie
    // related to the supplier we are fetching from, or we can use our RUV state.
    //
    // Initially I'm using RUV state, because it lets us select exactly what has
    // changed, where the cookie approach is more coarse grained. The cookie also
    // requires some more knowledge about what supplier we are communicating too
    // where the RUV approach doesn't since the supplier calcs the diff.

    #[instrument(level = "debug", skip_all)]
    pub fn consumer_get_state(&mut self) -> Result<(), OperationError> {

        // We need the RUV as a state of
        //
        // [ s_uuid, cid_min, cid_max ]
        // [ s_uuid, cid_min, cid_max ]
        // [ s_uuid, cid_min, cid_max ]
        // ...
        //
        // This way the remote can diff against it's knowledge and work out:
        //
        // [ s_uuid, from_cid, to_cid ]
        // [ s_uuid, from_cid, to_cid ]
        //
        // ...

        // Which then the supplier will use to actually retrieve the set of entries.
        // and the needed attributes we need.

        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    // Apply the state changes if they are valid.

    #[instrument(level = "debug", skip_all)]
    pub fn consumer_apply_changes(&mut self) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn consumer_apply_refresh(
        &mut self,
        ctx: &ReplRefreshContext,
    ) -> Result<(), OperationError> {
        match ctx {
            ReplRefreshContext::V1 {
                domain_version,
                domain_uuid,
                schema_entries,
                meta_entries,
                entries,
            } => self.consumer_apply_refresh_v1(
                *domain_version,
                *domain_uuid,
                schema_entries,
                meta_entries,
                entries,
            ),
        }
    }

    fn consumer_refresh_create_entries(
        &mut self,
        ctx_entries: &[ReplEntryV1],
    ) -> Result<(), OperationError> {
        let candidates = ctx_entries
            .iter()
            .map(EntryRefreshNew::from_repl_entry_v1)
            .collect::<Result<Vec<EntryRefreshNew>, _>>()
            .map_err(|e| {
                error!("Failed to convert entries from supplier");
                e
            })?;

        Plugins::run_pre_repl_refresh(self, candidates.as_slice()).map_err(|e| {
            admin_error!(
                "Refresh operation failed (pre_repl_refresh plugin), {:?}",
                e
            );
            e
        })?;

        // No need to assign CID's since this is a repl import.
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

        // Do not run plugs!

        let commit_cand = self.be_txn.refresh(norm_cand).map_err(|e| {
            admin_error!("betxn create failure {:?}", e);
            e
        })?;

        Plugins::run_post_repl_refresh(self, &commit_cand).map_err(|e| {
            admin_error!(
                "Refresh operation failed (post_repl_refresh plugin), {:?}",
                e
            );
            e
        })?;

        self.changed_uuid
            .extend(commit_cand.iter().map(|e| e.get_uuid()));

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn consumer_apply_refresh_v1(
        &mut self,
        ctx_domain_version: DomainVersion,
        ctx_domain_uuid: Uuid,
        ctx_schema_entries: &[ReplEntryV1],
        ctx_meta_entries: &[ReplEntryV1],
        ctx_entries: &[ReplEntryV1],
    ) -> Result<(), OperationError> {
        // Can we apply the domain version validly?
        // if domain_version >= min_support ...

        if ctx_domain_version < DOMAIN_MIN_LEVEL {
            error!("Unable to proceed with consumer refresh - incoming domain level is lower than our minimum supported level. {} < {}", ctx_domain_version, DOMAIN_MIN_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if ctx_domain_version > DOMAIN_MAX_LEVEL {
            error!("Unable to proceed with consumer refresh - incoming domain level is greater than our maximum supported level. {} > {}", ctx_domain_version, DOMAIN_MAX_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else {
            debug!(
                "Proceeding to refresh from domain at level {}",
                ctx_domain_version
            );
        };

        // == ⚠️  Below this point we begin to make changes! ==

        // Update the d_uuid. This is what defines us as being part of this repl topology!
        self.be_txn.set_db_d_uuid(ctx_domain_uuid).map_err(|e| {
            error!("Failed to reset domain uuid");
            e
        })?;

        // Do we need to reset our s_uuid to avoid potential RUV conflicts?
        //   - I don't think so, since the refresh is supplying and rebuilding
        //     our local state.

        // Delete all entries - *proper delete, not just tombstone!*

        self.be_txn.danger_delete_all_db_content().map_err(|e| {
            error!("Failed to clear existing server database content");
            e
        })?;

        // Reset this transactions schema to a completely clean slate.
        self.schema.generate_in_memory().map_err(|e| {
            error!("Failed to reset in memory schema to clean state");
            e
        })?;

        // Apply the schema entries first. This is the foundation that everything
        // else will build upon!
        self.consumer_refresh_create_entries(ctx_schema_entries)
            .map_err(|e| {
                error!("Failed to refresh schema entries");
                e
            })?;

        // We need to reload schema now!
        self.reload_schema().map_err(|e| {
            error!("Failed to reload schema");
            e
        })?;

        // We have to reindex to force all the existing indexes to be dumped
        // and recreated before we start to import.
        self.reindex().map_err(|e| {
            error!("Failed to reload schema");
            e
        })?;

        // Apply the domain info entry / system info / system config entry?
        self.consumer_refresh_create_entries(ctx_meta_entries)
            .map_err(|e| {
                error!("Failed to refresh schema entries");
                e
            })?;

        // NOTE: The domain info we receive here will have the domain version populated!
        // That's okay though, because all the incoming data is already at the right
        // version!
        self.reload_domain_info().map_err(|e| {
            error!("Failed to reload domain info");
            e
        })?;

        // Mark that everything changed so that post commit hooks function as expected.
        self.changed_schema = true;
        self.changed_acp = true;
        self.changed_oauth2 = true;
        self.changed_domain = true;

        // That's it! We are GOOD to go!

        // Create all the entries. Note we don't hit plugins here beside post repl plugs.
        self.consumer_refresh_create_entries(ctx_entries)
            .map_err(|e| {
                error!("Failed to refresh schema entries");
                e
            })?;

        // Run post repl plugins

        Ok(())
    }
}

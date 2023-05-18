use super::proto::*;
use crate::be::BackendTransaction;
use crate::plugins::Plugins;
use crate::prelude::*;
use crate::repl::proto::ReplRuvRange;
use crate::repl::ruv::ReplicationUpdateVectorTransaction;
use std::collections::BTreeMap;
use std::sync::Arc;

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
    pub fn consumer_get_state(&mut self) -> Result<ReplRuvRange, OperationError> {
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
        let ruv_snapshot = self.get_be_txn().get_ruv();

        // What's the current set of ranges?
        ruv_snapshot
            .current_ruv_range()
            .map(|ranges| ReplRuvRange::V1 { ranges })
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    // Apply the state changes if they are valid.

    fn consumer_incremental_apply_entries(
        &mut self,
        ctx_entries: &[ReplIncrementalEntryV1],
    ) -> Result<(), OperationError> {
        trace!(?ctx_entries);

        // No action needed for this if the entries are empty.
        if ctx_entries.is_empty() {
            debug!("No entries to act upon");
            return Ok(());
        }

        /*
         *  Incremental is very similar to modify in how we have to treat the entries
         *  with a pre and post state. However we need an incremental prepare so that
         *  when new entries are provided to us we can merge to a stub and then commit
         *  it correctly. This takes an extra backend interface that prepares the
         *  entry stubs for us.
         */

        // I think we need to rehydrate all the repl content to a partial
        // entry. This way all the types are consistent and ready.
        let ctx_entries: Vec<_> = ctx_entries.iter().map(
            EntryIncrementalNew::rehydrate
        )
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            error!(err = ?e, "Unable to process replication incremental entries to valid entry states for replication");
            e
        })?;

        let db_entries = self.be_txn.incremental_prepare(&ctx_entries).map_err(|e| {
            error!("Failed to access entries from db");
            e
        })?;

        // Need to probably handle conflicts here in this phase. I think they
        // need to be pushed to a seperate list where they are then "created"
        // as a conflict.

        // First find if entries are in a conflict state.

        let (conflicts, proceed): (Vec<_>, Vec<_>) = ctx_entries
            .iter()
            .zip(db_entries.into_iter())
            .partition(|(ctx_ent, db_ent)| ctx_ent.is_add_conflict(db_ent.as_ref()));

        // Now we have a set of conflicts and a set of entries to proceed.
        //
        //    /- entries that need to be created as conflicts.
        //    |                /- entries that survive and need update to the db in place.
        //    v                v
        let (conflict_create, conflict_update): (
            Vec<EntrySealedNew>,
            Vec<(EntryIncrementalCommitted, Arc<EntrySealedCommitted>)>,
        ) = conflicts
            .into_iter()
            .map(|(_ctx_ent, _db_ent)| {
                // Determine which of the entries must become the conflict
                // and which will now persist. There are two possible cases.
                //
                // 1. The ReplIncremental is after the DBEntry, and becomes the conflict.
                //    This means we just update the db entry with itself.
                //
                // 2. The ReplIncremental is before the DBEntry, and becomes live.
                //    This means we have to take the DBEntry as it exists, convert
                //    it to a new entry. Then we have to take the repl incremental
                //    entry and place it into the update queue.
                todo!();
            })
            .unzip();

        let proceed_update: Vec<(EntryIncrementalCommitted, Arc<EntrySealedCommitted>)> = proceed
            .into_iter()
            .map(|(ctx_ent, db_ent)| {
                // This now is the set of entries that are able to be updated. Merge
                // their attribute sets/states per the change state rules.

                // This must create an EntryInvalidCommitted
                let merge_ent = ctx_ent.merge_state(db_ent.as_ref(), &self.schema);
                (merge_ent, db_ent)
            })
            .collect();

        // To be consistent to Modify, we need to run pre-modify here.
        let mut all_updates = conflict_update
            .into_iter()
            .chain(proceed_update.into_iter())
            .collect::<Vec<_>>();

        // Plugins can mark entries into a conflict status.
        Plugins::run_pre_repl_incremental(self, all_updates.as_mut_slice()).map_err(|e| {
            admin_error!(
                "Refresh operation failed (pre_repl_incremental plugin), {:?}",
                e
            );
            e
        })?;

        // Now we have to schema check our data and seperate to schema_valid and
        // invalid.
        let all_updates_valid = all_updates
            .into_iter()
            .map(|(ctx_ent, db_ent)| {
                // Check the schema
                //
                // In these cases when an entry fails schema, we mark it to
                // a conflict state and then retain it in the update process.
                //
                // The marking is done INSIDE this function!
                ctx_ent
                    .validate_repl(&self.schema)
                    .map(|valid_ent| valid_ent.seal(&self.schema))
                    .map(|sealed_ent| (sealed_ent, db_ent))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                error!(err = ?e, "Failed to validate schema of incremental entries");
                OperationError::SchemaViolation(e)
            })?;

        // We now have three sets!
        //
        // * conflict_create - entries to be created that are conflicted via add statements (duplicate uuid)
        // * schema_invalid - entries that were merged and their attribute state has now become invalid to schema.
        // * schema_valid - entries that were merged and are schema valid.
        //
        // From these sets, we will move conflict_create and schema_invalid into the replication masked
        // state. However schema_valid needs to be processed to check for plugin rules as well. If
        // anything hits one of these states we need to have a way to handle this too in a consistent
        // manner.
        //

        // Then similar to modify, we need the pre and post candidates.

        // We need to unzip the schema_valid and invalid entries.

        self.be_txn
            .incremental_apply(&all_updates_valid, &conflict_create)
            .map_err(|e| {
                admin_error!("betxn create failure {:?}", e);
                e
            })?;

        // Plugins need these unzipped
        let (cand, pre_cand): (Vec<_>, Vec<_>) = all_updates_valid.into_iter().unzip();

        // We don't need to process conflict_creates here, since they are all conflicting
        // uuids which means that the uuids are all *here* so they will trigger anything
        // that requires processing anyway.
        Plugins::run_post_repl_incremental(self, pre_cand.as_slice(), cand.as_slice()).map_err(
            |e| {
                admin_error!(
                    "Refresh operation failed (post_repl_incremental plugin), {:?}",
                    e
                );
                e
            },
        )?;

        self.changed_uuid.extend(cand.iter().map(|e| e.get_uuid()));

        todo!(); // change on acp, oauth2

        // Ok(())
    }

    pub fn consumer_apply_changes(
        &mut self,
        ctx: &ReplIncrementalContext,
    ) -> Result<(), OperationError> {
        match ctx {
            ReplIncrementalContext::NoChangesAvailable => {
                info!("no changes are available");
                Ok(())
            }
            ReplIncrementalContext::RefreshRequired => {
                todo!();
            }
            ReplIncrementalContext::UnwillingToSupply => {
                todo!();
            }
            ReplIncrementalContext::V1 {
                domain_version,
                domain_uuid,
                ranges,
                schema_entries,
                meta_entries,
                entries,
            } => self.consumer_apply_changes_v1(
                *domain_version,
                *domain_uuid,
                ranges,
                schema_entries,
                meta_entries,
                entries,
            ),
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn consumer_apply_changes_v1(
        &mut self,
        ctx_domain_version: DomainVersion,
        ctx_domain_uuid: Uuid,
        ctx_ranges: &BTreeMap<Uuid, ReplCidRange>,
        ctx_schema_entries: &[ReplIncrementalEntryV1],
        ctx_meta_entries: &[ReplIncrementalEntryV1],
        ctx_entries: &[ReplIncrementalEntryV1],
    ) -> Result<(), OperationError> {
        if ctx_domain_version < DOMAIN_MIN_LEVEL {
            error!("Unable to proceed with consumer incremental - incoming domain level is lower than our minimum supported level. {} < {}", ctx_domain_version, DOMAIN_MIN_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if ctx_domain_version > DOMAIN_MAX_LEVEL {
            error!("Unable to proceed with consumer incremental - incoming domain level is greater than our maximum supported level. {} > {}", ctx_domain_version, DOMAIN_MAX_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        };

        // Assert that the d_uuid matches the repl domain uuid.
        let db_uuid = self.be_txn.get_db_d_uuid();
        if db_uuid != ctx_domain_uuid {
            error!("Unable to proceed with consumer incremental - incoming domain uuid does not match our database uuid. You must investigate this situation. {:?} != {:?}", db_uuid, ctx_domain_uuid);
            return Err(OperationError::ReplDomainUuidMismatch);
        }

        debug!(
            "Proceeding to apply incremental from domain {:?} at level {}",
            ctx_domain_uuid, ctx_domain_version
        );

        // == ⚠️  Below this point we begin to make changes! ==

        // Apply the schema entries first.
        self.consumer_incremental_apply_entries(ctx_schema_entries)
            .map_err(|e| {
                error!("Failed to apply incremental schema entries");
                e
            })?;

        // We need to reload schema now!
        self.reload_schema().map_err(|e| {
            error!("Failed to reload schema");
            e
        })?;

        // Apply meta entries now.
        self.consumer_incremental_apply_entries(ctx_meta_entries)
            .map_err(|e| {
                error!("Failed to apply incremental schema entries");
                e
            })?;

        // This is re-loaded in case the domain name changed on the remote. Also needed for changing
        // the domain version.
        self.reload_domain_info().map_err(|e| {
            error!("Failed to reload domain info");
            e
        })?;

        // Trigger for post commit hooks. Should we detect better in the entry
        // apply phases?
        self.changed_schema = true;
        self.changed_domain = true;

        // Update all other entries now.
        self.consumer_incremental_apply_entries(ctx_entries)
            .map_err(|e| {
                error!("Failed to apply incremental schema entries");
                e
            })?;

        // Finally, confirm that the ranges that we have added match the ranges from our
        // context. Note that we get this in a writeable form!
        let ruv = self.be_txn.get_ruv_write();

        ruv.refresh_validate_ruv(ctx_ranges).map_err(|e| {
            error!("RUV ranges were not rebuilt correctly.");
            e
        })?;

        ruv.refresh_update_ruv(ctx_ranges).map_err(|e| {
            error!("Unable to update RUV with supplier ranges.");
            e
        })?;

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
                ranges,
                schema_entries,
                meta_entries,
                entries,
            } => self.consumer_apply_refresh_v1(
                *domain_version,
                *domain_uuid,
                ranges,
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
                        admin_error!("Schema Violation in refresh validate {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| {
                        // Then seal the changes?
                        e.seal(&self.schema)
                    })
            })
            .collect::<Result<Vec<EntrySealedNew>, _>>()?;

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
        ctx_ranges: &BTreeMap<Uuid, ReplCidRange>,
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
                error!("Failed to refresh meta entries");
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

        // Finally, confirm that the ranges that we have recreated match the ranges from our
        // context. Note that we get this in a writeable form!
        let ruv = self.be_txn.get_ruv_write();

        ruv.refresh_validate_ruv(ctx_ranges).map_err(|e| {
            error!("RUV ranges were not rebuilt correctly.");
            e
        })?;

        ruv.refresh_update_ruv(ctx_ranges).map_err(|e| {
            error!("Unable to update RUV with supplier ranges.");
            e
        })?;

        Ok(())
    }
}


use std::time::Duration;
use kanidm_proto::v1::SchemaError;

use crate::prelude::*;

use super::ServerPhase;

impl QueryServer {
    #[instrument(level = "info", name = "system_initialisation", skip_all)]
    pub async fn initialise_helper(&self, ts: Duration) -> Result<(), OperationError> {
        // Check our database version - attempt to do an initial indexing
        // based on the in memory configuration
        //
        // If we ever change the core in memory schema, or the schema that we ship
        // in fixtures, we have to bump these values. This is how we manage the
        // first-run and upgrade reindexings.
        //
        // A major reason here to split to multiple transactions is to allow schema
        // reloading to occur, which causes the idxmeta to update, and allows validation
        // of the schema in the subsequent steps as we proceed.
        let mut reindex_write_1 = self.write(ts).await;
        reindex_write_1
            .upgrade_reindex(SYSTEM_INDEX_VERSION)
            .and_then(|_| reindex_write_1.commit())?;

        // Because we init the schema here, and commit, this reloads meaning
        // that the on-disk index meta has been loaded, so our subsequent
        // migrations will be correctly indexed.
        //
        // Remember, that this would normally mean that it's possible for schema
        // to be mis-indexed (IE we index the new schemas here before we read
        // the schema to tell us what's indexed), but because we have the in
        // mem schema that defines how schema is structuded, and this is all
        // marked "system", then we won't have an issue here.
        let mut ts_write_1 = self.write(ts).await;
        ts_write_1
            .initialise_schema_core()
            .and_then(|_| ts_write_1.commit())?;

        let mut ts_write_2 = self.write(ts).await;
        ts_write_2
            .initialise_schema_idm()
            .and_then(|_| ts_write_2.commit())?;

        // reindex and set to version + 1, this way when we bump the version
        // we are essetially pushing this version id back up to step write_1
        let mut reindex_write_2 = self.write(ts).await;
        reindex_write_2
            .upgrade_reindex(SYSTEM_INDEX_VERSION + 1)
            .and_then(|_| reindex_write_2.commit())?;

        // Force the schema to reload - this is so that any changes to index slope
        // analysis are now reflected correctly.
        //
        // A side effect of these reloads is that other plugins or elements that reload
        // on schema change are now setup.
        let mut slope_reload = self.write(ts).await;
        slope_reload.set_phase(ServerPhase::SchemaReady);
        slope_reload.force_schema_reload();
        slope_reload.commit()?;

        // Now, based on the system version apply migrations. You may ask "should you not
        // be doing migrations before indexes?". And this is a very good question! The issue
        // is within a migration we must be able to search for content by pres index, and those
        // rely on us being indexed! It *is* safe to index content even if the
        // migration would cause a value type change (ie name changing from iutf8s to iname) because
        // the indexing subsystem is schema/value agnostic - the fact the values still let their keys
        // be extracted, means that the pres indexes will be valid even though the entries are pending
        // migration. We must be sure to NOT use EQ/SUB indexes in the migration code however!
        let mut migrate_txn = self.write(ts).await;
        // If we are "in the process of being setup" this is 0, and the migrations will have no
        // effect as ... there is nothing to migrate! It allows reset of the version to 0 to force
        // db migrations to take place.
        let system_info_version = match migrate_txn.internal_search_uuid(UUID_SYSTEM_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32("version").unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;
        admin_debug!(?system_info_version);

        if system_info_version < 3 {
            migrate_txn.migrate_2_to_3()?;
        }

        if system_info_version < 4 {
            migrate_txn.migrate_3_to_4()?;
        }

        if system_info_version < 5 {
            migrate_txn.migrate_4_to_5()?;
        }

        if system_info_version < 6 {
            migrate_txn.migrate_5_to_6()?;
        }

        if system_info_version < 7 {
            migrate_txn.migrate_6_to_7()?;
        }

        if system_info_version < 8 {
            migrate_txn.migrate_7_to_8()?;
        }

        if system_info_version < 9 {
            migrate_txn.migrate_8_to_9()?;
        }

        migrate_txn.commit()?;
        // Migrations complete. Init idm will now set the version as needed.

        let mut ts_write_3 = self.write(ts).await;
        ts_write_3.initialise_idm().and_then(|_| {
            ts_write_3.set_phase(ServerPhase::Running);
            ts_write_3.commit()
        })?;
        // TODO: work out if we've actually done any migrations before printing this
        admin_debug!("Database version check and migrations success! ☀️  ");
        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    /// Migrate 2 to 3 changes the name, domain_name types from iutf8 to iname.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_2_to_3(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 2 to 3 migration. THIS MAY TAKE A LONG TIME!");
        // Get all entries where pres name or domain_name. INCLUDE TS + RECYCLE.

        let filt = filter_all!(f_or!([f_pres("name"), f_pres("domain_name"),]));

        let pre_candidates = self.internal_search(filt).map_err(|e| {
            admin_error!(err = ?e, "migrate_2_to_3 internal search failure");
            e
        })?;

        // If there is nothing, we donn't need to do anything.
        if pre_candidates.is_empty() {
            admin_info!("migrate_2_to_3 no entries to migrate, complete");
            return Ok(());
        }

        // Change the value type.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| er.as_ref().clone().invalidate(self.cid.clone()))
            .collect();

        candidates.iter_mut().try_for_each(|er| {
            let nvs = if let Some(vs) = er.get_ava_set("name") {
                vs.migrate_iutf8_iname()?
            } else {
                None
            };
            if let Some(nvs) = nvs {
                er.set_ava_set("name", nvs)
            }

            let nvs = if let Some(vs) = er.get_ava_set("domain_name") {
                vs.migrate_iutf8_iname()?
            } else {
                None
            };
            if let Some(nvs) = nvs {
                er.set_ava_set("domain_name", nvs)
            }

            Ok(())
        })?;

        // Schema check all.
        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema).map(|e| e.seal(&self.schema)))
            .collect();

        let norm_cand: Vec<Entry<_, _>> = match res {
            Ok(v) => v,
            Err(e) => {
                admin_error!("migrate_2_to_3 schema error -> {:?}", e);
                return Err(OperationError::SchemaViolation(e));
            }
        };

        // Write them back.
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("migrate_2_to_3 modification failure -> {:?}", e);
                e
            })
        // Complete
    }

    /// Migrate 3 to 4 - this triggers a regen of the domains security token
    /// as we previously did not have it in the entry.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_3_to_4(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 3 to 4 migration.");
        let filter = filter!(f_eq("uuid", (*PVUUID_DOMAIN_INFO).clone()));
        let modlist = ModifyList::new_purge("domain_token_key");
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 4 to 5 - this triggers a regen of all oauth2 RS es256 der keys
    /// as we previously did not generate them on entry creation.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_4_to_5(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 4 to 5 migration.");
        let filter = filter!(f_and!([
            f_eq("class", (*PVCLASS_OAUTH2_RS).clone()),
            f_andnot(f_pres("es256_private_key_der")),
        ]));
        let modlist = ModifyList::new_purge("es256_private_key_der");
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 5 to 6 - This updates the domain info item to reset the token
    /// keys based on the new encryption types.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_5_to_6(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 5 to 6 migration.");
        let filter = filter!(f_eq("uuid", (*PVUUID_DOMAIN_INFO).clone()));
        let mut modlist = ModifyList::new_purge("domain_token_key");
        // We need to also push the version here so that we pass schema.
        modlist.push_mod(Modify::Present(
            AttrString::from("version"),
            Value::Uint32(0),
        ));
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 6 to 7
    ///
    /// Modify accounts that are not persons, to be service accounts so that the extension
    /// rules remain valid.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_6_to_7(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 6 to 7 migration.");
        let filter = filter!(f_and!([
            f_eq("class", (*PVCLASS_ACCOUNT).clone()),
            f_andnot(f_eq("class", (*PVCLASS_PERSON).clone())),
        ]));
        let modlist = ModifyList::new_append("class", Value::new_class("service_account"));
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 7 to 8
    ///
    /// Touch all service accounts to trigger a regen of their es256 jws keys for api tokens
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_7_to_8(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 7 to 8 migration.");
        let filter = filter!(f_eq("class", (*PVCLASS_SERVICE_ACCOUNT).clone()));
        let modlist = ModifyList::new_append("class", Value::new_class("service_account"));
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 8 to 9
    ///
    /// This migration updates properties of oauth2 relying server properties. First, it changes
    /// the former basic value to a secret utf8string.
    ///
    /// The second change improves the current scope system to remove the implicit scope type.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_8_to_9(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 8 to 9 migration.");
        let filt = filter_all!(f_or!([
            f_eq("class", PVCLASS_OAUTH2_RS.clone()),
            f_eq("class", PVCLASS_OAUTH2_BASIC.clone()),
        ]));

        let pre_candidates = self.internal_search(filt).map_err(|e| {
            admin_error!(err = ?e, "migrate_8_to_9 internal search failure");
            e
        })?;

        // If there is nothing, we donn't need to do anything.
        if pre_candidates.is_empty() {
            admin_info!("migrate_8_to_9 no entries to migrate, complete");
            return Ok(());
        }

        // Change the value type.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| er.as_ref().clone().invalidate(self.cid.clone()))
            .collect();

        candidates.iter_mut().try_for_each(|er| {
            // Migrate basic secrets if they exist.
            let nvs = er
                .get_ava_set("oauth2_rs_basic_secret")
                .and_then(|vs| vs.as_utf8_iter())
                .and_then(|vs_iter| {
                    ValueSetSecret::from_iter(vs_iter.map(|s: &str| s.to_string()))
                });
            if let Some(nvs) = nvs {
                er.set_ava_set("oauth2_rs_basic_secret", nvs)
            }

            // Migrate implicit scopes if they exist.
            let nv = if let Some(vs) = er.get_ava_set("oauth2_rs_implicit_scopes") {
                vs.as_oauthscope_set()
                    .map(|v| Value::OauthScopeMap(UUID_IDM_ALL_PERSONS, v.clone()))
            } else {
                None
            };

            if let Some(nv) = nv {
                er.add_ava("oauth2_rs_scope_map", nv)
            }
            er.purge_ava("oauth2_rs_implicit_scopes");

            Ok(())
        })?;

        // Schema check all.
        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema).map(|e| e.seal(&self.schema)))
            .collect();

        let norm_cand: Vec<Entry<_, _>> = match res {
            Ok(v) => v,
            Err(e) => {
                admin_error!("migrate_8_to_9 schema error -> {:?}", e);
                return Err(OperationError::SchemaViolation(e));
            }
        };

        // Write them back.
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("migrate_8_to_9 modification failure -> {:?}", e);
                e
            })
        // Complete
    }
}


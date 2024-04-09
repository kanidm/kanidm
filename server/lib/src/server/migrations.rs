use crate::value::CredentialType;
use std::time::Duration;

use crate::prelude::*;

use kanidm_proto::internal::{
    DomainUpgradeCheckItem as ProtoDomainUpgradeCheckItem,
    DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport,
    DomainUpgradeCheckStatus as ProtoDomainUpgradeCheckStatus,
};

use super::ServerPhase;

impl QueryServer {
    #[instrument(level = "info", name = "system_initialisation", skip_all)]
    pub async fn initialise_helper(
        &self,
        ts: Duration,
        domain_target_level: DomainVersion,
    ) -> Result<(), OperationError> {
        // We need to perform this in a single transaction pass to prevent tainting
        // databases during upgrades.
        let mut write_txn = self.write(ts).await;

        // Check our database version - attempt to do an initial indexing
        // based on the in memory configuration. This ONLY triggers ONCE on
        // the very first run of the instance when the DB in newely created.
        write_txn.upgrade_reindex(SYSTEM_INDEX_VERSION)?;

        // Because we init the schema here, and commit, this reloads meaning
        // that the on-disk index meta has been loaded, so our subsequent
        // migrations will be correctly indexed.
        //
        // Remember, that this would normally mean that it's possible for schema
        // to be mis-indexed (IE we index the new schemas here before we read
        // the schema to tell us what's indexed), but because we have the in
        // mem schema that defines how schema is structuded, and this is all
        // marked "system", then we won't have an issue here.
        write_txn
            .initialise_schema_core()
            .and_then(|_| write_txn.reload())?;

        write_txn.reload()?;

        // Now, based on the system version apply migrations. You may ask "should you not
        // be doing migrations before indexes?". And this is a very good question! The issue
        // is within a migration we must be able to search for content by pres index, and those
        // rely on us being indexed! It *is* safe to index content even if the
        // migration would cause a value type change (ie name changing from iutf8s to iname) because
        // the indexing subsystem is schema/value agnostic - the fact the values still let their keys
        // be extracted, means that the pres indexes will be valid even though the entries are pending
        // migration. We must be sure to NOT use EQ/SUB indexes in the migration code however!
        //
        // If we are "in the process of being setup" this is 0, and the migrations will have no
        // effect as ... there is nothing to migrate! It allows reset of the version to 0 to force
        // db migrations to take place.
        let system_info_version = match write_txn.internal_search_uuid(UUID_SYSTEM_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32(Attribute::Version).unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;
        admin_debug!(?system_info_version);

        if system_info_version > 0 {
            if system_info_version <= 9 {
                error!("Your instance of Kanidm is version 1.1.0-alpha.10 or lower, and you are trying to perform a skip upgrade. This will not work.");
                error!("You need to upgrade one version at a time to ensure upgrade migrations are performed in the correct order.");
                return Err(OperationError::InvalidState);
            }

            if system_info_version < 9 {
                write_txn.migrate_8_to_9()?;
            }

            if system_info_version < 10 {
                write_txn.migrate_9_to_10()?;
            }

            if system_info_version < 11 {
                write_txn.migrate_10_to_11()?;
            }

            if system_info_version < 12 {
                write_txn.migrate_11_to_12()?;
            }

            if system_info_version < 13 {
                write_txn.migrate_12_to_13()?;
            }

            if system_info_version < 14 {
                write_txn.migrate_13_to_14()?;
            }

            if system_info_version < 15 {
                write_txn.migrate_14_to_15()?;
            }

            if system_info_version < 16 {
                write_txn.migrate_15_to_16()?;
            }

            if system_info_version < 17 {
                write_txn.initialise_schema_idm()?;

                write_txn.reload()?;

                write_txn.migrate_16_to_17()?;
            }

            if system_info_version < 18 {
                // Automate fix for #2391 - during the changes to the access controls
                // and the recent domain migration work, this stage was not being run
                // if a larger "jump" of migrations was performed such as rc.15 to main.
                //
                // This allows "forcing" a single once off run of init idm *before*
                // the domain migrations kick in again.
                write_txn.initialise_idm()?;
            }

            if system_info_version < 19 {
                write_txn.migrate_18_to_19()?;
            }
        }

        // Reload if anything in the (older) system migrations requires it.
        write_txn.reload()?;

        // This is what tells us if the domain entry existed before or not. This
        // is now the primary method of migrations and version detection.
        let db_domain_version = match write_txn.internal_search_uuid(UUID_DOMAIN_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32(Attribute::Version).unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;

        debug!(?db_domain_version, "Before setting internal domain info");

        // No domain info was present, so neither was the rest of the IDM. We need to bootstrap
        // the base-schema here.
        if db_domain_version == 0 {
            write_txn.initialise_schema_idm()?;

            write_txn.reload()?;

            // Since we just loaded in a ton of schema, lets reindex it to make
            // sure that some base IDM operations are fast. Since this is still
            // very early in the bootstrap process, and very few entries exist,
            // reindexing is very fast here.
            write_txn.reindex()?;
        }

        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        write_txn.set_phase(ServerPhase::SchemaReady);

        // Init idm will now set the system config version and minimum domain
        // level if none was present
        write_txn.initialise_domain_info()?;

        // No domain info was present, so neither was the rest of the IDM. We need to bootstrap
        // the base entries here.
        if db_domain_version == 0 {
            write_txn.initialise_idm()?;
        }

        // Reload as init idm affects access controls.
        write_txn.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        write_txn.set_phase(ServerPhase::DomainInfoReady);

        // This is the start of domain info related migrations which we will need in future
        // to handle replication. Due to the access control rework, and the addition of "managed by"
        // syntax, we need to ensure both node "fence" replication from each other. We do this
        // by changing domain infos to be incompatible during this phase.

        // The reloads will have populated this structure now.
        let domain_info_version = write_txn.get_domain_version();
        debug!(?db_domain_version, "After setting internal domain info");

        if domain_info_version < domain_target_level {
            write_txn
                .internal_modify_uuid(
                    UUID_DOMAIN_INFO,
                    &ModifyList::new_purge_and_set(
                        Attribute::Version,
                        Value::new_uint32(domain_target_level),
                    ),
                )
                .map(|()| {
                    warn!("Domain level has been raised to {}", domain_target_level);
                })?;
        } else {
            // This forces pre-release versions to re-migrate each start up. This solves
            // the domain-version-sprawl issue so that during a development cycle we can
            // do a single domain version bump, and continue to extend the migrations
            // within that release cycle to contain what we require.
            //
            // If this is a pre-release build
            // AND
            // we are NOT in a test environment
            // AND
            // We did not already need a version migration as above
            if option_env!("KANIDM_PRE_RELEASE").is_some() && !cfg!(test) {
                write_txn.domain_remigrate(DOMAIN_PREVIOUS_TGT_LEVEL)?;
            }
        }

        // Reload if anything in migrations requires it - this triggers the domain migrations
        // which in turn can trigger schema reloads etc.
        write_txn.reload()?;

        // We are ready to run
        write_txn.set_phase(ServerPhase::Running);

        // Commit all changes, this also triggers the reload.
        write_txn.commit()?;

        debug!("Database version check and migrations success! ☀️  ");
        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    /// Apply a domain migration `to_level`. Panics if `to_level` is not greater than the active
    /// level.
    #[cfg(test)]
    pub(crate) fn internal_apply_domain_migration(
        &mut self,
        to_level: u32,
    ) -> Result<(), OperationError> {
        assert!(to_level > self.get_domain_version());
        self.internal_modify_uuid(
            UUID_DOMAIN_INFO,
            &ModifyList::new_purge_and_set(Attribute::Version, Value::new_uint32(to_level)),
        )
        .and_then(|()| self.reload())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn internal_migrate_or_create_str(&mut self, e_str: &str) -> Result<(), OperationError> {
        let res = Entry::from_proto_entry_str(e_str, self)
            /*
            .and_then(|e: Entry<EntryInvalid, EntryNew>| {
                let schema = self.get_schema();
                e.validate(schema).map_err(OperationError::SchemaViolation)
            })
            */
            .and_then(|e: Entry<EntryInit, EntryNew>| self.internal_migrate_or_create(e));
        trace!(?res);
        debug_assert!(res.is_ok());
        res
    }

    #[instrument(level = "debug", skip_all)]
    /// - If the thing exists:
    ///   - Ensure the set of attributes match and are present
    ///     (but don't delete multivalue, or extended attributes in the situation.
    /// - If not:
    ///   - Create the entry
    ///
    /// This will extra classes an attributes alone!
    ///
    /// NOTE: `gen_modlist*` IS schema aware and will handle multivalue correctly!
    pub fn internal_migrate_or_create(
        &mut self,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        trace!("internal_migrate_or_create operating on {:?}", e.get_uuid());

        let Some(filt) = e.filter_from_attrs(&[Attribute::Uuid.into()]) else {
            return Err(OperationError::FilterGeneration);
        };

        trace!("internal_migrate_or_create search {:?}", filt);

        let results = self.internal_search(filt.clone())?;

        if results.is_empty() {
            // It does not exist. Create it.
            self.internal_create(vec![e])
        } else if results.len() == 1 {
            // If the thing is subset, pass
            match e.gen_modlist_assert(&self.schema) {
                Ok(modlist) => {
                    // Apply to &results[0]
                    trace!("Generated modlist -> {:?}", modlist);
                    self.internal_modify(&filt, &modlist)
                }
                Err(e) => Err(OperationError::SchemaViolation(e)),
            }
        } else {
            admin_error!(
                "Invalid Result Set - Expected One Entry for {:?} - {:?}",
                filt,
                results
            );
            Err(OperationError::InvalidDbState)
        }
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
            f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
            f_eq(
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.into()
            ),
        ]));

        let pre_candidates = self.internal_search(filt).map_err(|e| {
            admin_error!(err = ?e, "migrate_8_to_9 internal search failure");
            e
        })?;

        // If there is nothing, we don't need to do anything.
        if pre_candidates.is_empty() {
            admin_info!("migrate_8_to_9 no entries to migrate, complete");
            return Ok(());
        }

        // Change the value type.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| {
                er.as_ref()
                    .clone()
                    .invalidate(self.cid.clone(), &self.trim_cid)
            })
            .collect();

        candidates.iter_mut().try_for_each(|er| {
            // Migrate basic secrets if they exist.
            let nvs = er
                .get_ava_set(Attribute::OAuth2RsBasicSecret)
                .and_then(|vs| vs.as_utf8_iter())
                .and_then(|vs_iter| {
                    ValueSetSecret::from_iter(vs_iter.map(|s: &str| s.to_string()))
                });
            if let Some(nvs) = nvs {
                er.set_ava_set(Attribute::OAuth2RsBasicSecret, nvs)
            }

            // Migrate implicit scopes if they exist.
            let nv = if let Some(vs) = er.get_ava_set(Attribute::OAuth2RsImplicitScopes) {
                vs.as_oauthscope_set()
                    .map(|v| Value::OauthScopeMap(UUID_IDM_ALL_PERSONS, v.clone()))
            } else {
                None
            };

            if let Some(nv) = nv {
                er.add_ava(Attribute::OAuth2RsScopeMap, nv)
            }
            er.purge_ava(Attribute::OAuth2RsImplicitScopes);

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

    /// Migrate 9 to 10
    ///
    /// This forces a load and rewrite of all credentials stored on all accounts so that they are
    /// updated to new on-disk formats. This will allow us to purge some older on disk formats in
    /// a future version.
    ///
    /// An extended feature of this is the ability to store multiple TOTP's per entry.
    #[instrument(level = "info", skip_all)]
    pub fn migrate_9_to_10(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 9 to 10 migration.");
        let filter = filter!(f_or!([
            f_pres(Attribute::PrimaryCredential),
            f_pres(Attribute::UnixPassword),
        ]));
        // This "does nothing" since everything has object anyway, but it forces the entry to be
        // loaded and rewritten.
        let modlist = ModifyList::new_append(Attribute::Class, EntryClass::Object.to_value());
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 10 to 11
    ///
    /// This forces a load of all credentials, and then examines if any are "passkey" capable. If they
    /// are, they are migrated to the passkey type, allowing us to deprecate and remove the older
    /// credential behaviour.
    ///
    #[instrument(level = "info", skip_all)]
    pub fn migrate_10_to_11(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 9 to 10 migration.");
        let filter = filter!(f_pres(Attribute::PrimaryCredential));

        let pre_candidates = self.internal_search(filter).map_err(|e| {
            admin_error!(err = ?e, "migrate_10_to_11 internal search failure");
            e
        })?;

        // First, filter based on if any credentials present actually are the legacy
        // webauthn type.
        let modset: Vec<_> = pre_candidates
            .into_iter()
            .filter_map(|ent| {
                ent.get_ava_single_credential(Attribute::PrimaryCredential)
                    .and_then(|cred| cred.passkey_ref().ok())
                    .map(|pk_map| {
                        let modlist = pk_map
                            .iter()
                            .map(|(t, k)| {
                                Modify::Present(
                                    "passkeys".into(),
                                    Value::Passkey(Uuid::new_v4(), t.clone(), k.clone()),
                                )
                            })
                            .chain(std::iter::once(m_purge(Attribute::PrimaryCredential)))
                            .collect();
                        (ent.get_uuid(), ModifyList::new_list(modlist))
                    })
            })
            .collect();

        // If there is nothing, we don't need to do anything.
        if modset.is_empty() {
            admin_info!("migrate_10_to_11 no entries to migrate, complete");
            return Ok(());
        }

        // Apply the batch mod.
        self.internal_batch_modify(modset.into_iter())
    }

    /// Migrate 11 to 12
    ///
    /// Rewrite api-tokens from session to a dedicated API token type.
    ///
    #[instrument(level = "info", skip_all)]
    pub fn migrate_11_to_12(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 11 to 12 migration.");
        // sync_token_session
        let filter = filter!(f_or!([
            f_pres(Attribute::ApiTokenSession),
            f_pres(Attribute::SyncTokenSession),
        ]));

        let mut mod_candidates = self.internal_search_writeable(&filter).map_err(|e| {
            admin_error!(err = ?e, "migrate_11_to_12 internal search failure");
            e
        })?;

        // If there is nothing, we don't need to do anything.
        if mod_candidates.is_empty() {
            admin_info!("migrate_11_to_12 no entries to migrate, complete");
            return Ok(());
        }

        // First, filter based on if any credentials present actually are the legacy
        // webauthn type.

        for (_, ent) in mod_candidates.iter_mut() {
            if let Some(api_token_session) = ent.pop_ava(Attribute::ApiTokenSession) {
                let api_token_session =
                    api_token_session
                        .migrate_session_to_apitoken()
                        .map_err(|e| {
                            error!(
                                "Failed to convert {} from session -> apitoken",
                                Attribute::ApiTokenSession
                            );
                            e
                        })?;

                ent.set_ava_set(Attribute::ApiTokenSession, api_token_session);
            }

            if let Some(sync_token_session) = ent.pop_ava(Attribute::SyncTokenSession) {
                let sync_token_session =
                    sync_token_session
                        .migrate_session_to_apitoken()
                        .map_err(|e| {
                            error!("Failed to convert sync_token_session from session -> apitoken");
                            e
                        })?;

                ent.set_ava_set(Attribute::SyncTokenSession, sync_token_session);
            }
        }

        // Apply the batch mod.
        self.internal_apply_writable(mod_candidates)
    }

    #[instrument(level = "info", skip_all)]
    /// Deletes the Domain info privatecookiekey to force a regeneration as we changed the format
    pub fn migrate_12_to_13(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 12 to 13 migration.");
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::DomainInfo.into()),
            f_eq(Attribute::Uuid, PVUUID_DOMAIN_INFO.clone()),
        ]));
        // Delete the existing cookie key to trigger a regeneration.
        let modlist = ModifyList::new_purge(Attribute::PrivateCookieKey);
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    #[instrument(level = "info", skip_all)]
    /// - Deletes the incorrectly added "member" attribute on dynamic groups
    pub fn migrate_13_to_14(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 13 to 14 migration.");
        let filter = filter!(f_eq(
            Attribute::Class,
            EntryClass::DynGroup.to_partialvalue()
        ));
        // Delete the incorrectly added "member" attr.
        let modlist = ModifyList::new_purge(Attribute::Member);
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    #[instrument(level = "info", skip_all)]
    /// - Deletes the non-existing attribute for idverification private key which triggers it to regen
    pub fn migrate_14_to_15(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 14 to 15 migration.");
        let filter = filter!(f_eq(Attribute::Class, EntryClass::Person.into()));
        // Delete the non-existing attr for idv private key which triggers it to regen.
        let modlist = ModifyList::new_purge(Attribute::IdVerificationEcKey);
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    #[instrument(level = "info", skip_all)]
    /// - updates the system config to include the new session expiry values.
    /// - adds the account policy object to idm_all_accounts
    pub fn migrate_15_to_16(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 15 to 16 migration.");

        let sysconfig_entry = match self.internal_search_uuid(UUID_SYSTEM_CONFIG) {
            Ok(entry) => entry,
            Err(OperationError::NoMatchingEntries) => return Ok(()),
            Err(e) => return Err(e),
        };

        let mut all_account_modlist = Vec::with_capacity(3);

        all_account_modlist.push(Modify::Present(
            Attribute::Class.into(),
            EntryClass::AccountPolicy.to_value(),
        ));

        if let Some(auth_exp) = sysconfig_entry.get_ava_single_uint32(Attribute::AuthSessionExpiry)
        {
            all_account_modlist.push(Modify::Present(
                Attribute::AuthSessionExpiry.into(),
                Value::Uint32(auth_exp),
            ));
        }

        if let Some(priv_exp) = sysconfig_entry.get_ava_single_uint32(Attribute::PrivilegeExpiry) {
            all_account_modlist.push(Modify::Present(
                Attribute::PrivilegeExpiry.into(),
                Value::Uint32(priv_exp),
            ));
        }

        self.internal_batch_modify(
            [
                (
                    UUID_SYSTEM_CONFIG,
                    ModifyList::new_list(vec![
                        Modify::Purged(Attribute::AuthSessionExpiry.into()),
                        Modify::Purged(Attribute::PrivilegeExpiry.into()),
                    ]),
                ),
                (
                    UUID_IDM_ALL_ACCOUNTS,
                    ModifyList::new_list(all_account_modlist),
                ),
            ]
            .into_iter(),
        )
        // Complete
    }

    #[instrument(level = "info", skip_all)]
    /// This migration will:
    /// * ensure that all access controls have the needed group receiver type
    /// * delete legacy entries that are no longer needed.
    pub fn migrate_16_to_17(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 16 to 17 migration.");

        let filter = filter!(f_and!([
            f_or!([
                f_pres(Attribute::AcpReceiverGroup),
                f_pres(Attribute::AcpTargetScope),
            ]),
            f_eq(
                Attribute::Class,
                EntryClass::AccessControlProfile.to_partialvalue()
            )
        ]));
        // Delete the incorrectly added "member" attr.
        let modlist = ModifyList::new_list(vec![
            Modify::Present(
                Attribute::Class.into(),
                EntryClass::AccessControlReceiverGroup.to_value(),
            ),
            Modify::Present(
                Attribute::Class.into(),
                EntryClass::AccessControlTargetScope.to_value(),
            ),
        ]);
        self.internal_modify(&filter, &modlist)?;

        let delete_entries = [
            UUID_IDM_ACP_OAUTH2_READ_PRIV_V1,
            UUID_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1,
            UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
            UUID_IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1,
            UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1,
            UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1,
            UUID_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1,
            UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1,
            UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1,
            UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1,
            UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1,
            UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1,
            UUID_IDM_ACP_GROUP_WRITE_PRIV_V1,
            UUID_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1,
            UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1,
            UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1,
            UUID_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1,
            UUID_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            UUID_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1,
            UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            UUID_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1,
            UUID_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
            UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
            UUID_IDM_ACP_HP_PEOPLE_READ_PRIV_V1,
            UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1,
            UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1,
            UUID_IDM_RADIUS_SECRET_READ_PRIV_V1,
            UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV,
            UUID_IDM_PEOPLE_EXTEND_PRIV,
            UUID_IDM_HP_PEOPLE_EXTEND_PRIV,
            UUID_IDM_HP_GROUP_MANAGE_PRIV,
            UUID_IDM_HP_GROUP_WRITE_PRIV,
            UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
            UUID_IDM_GROUP_ACCOUNT_POLICY_MANAGE_PRIV,
            UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV,
            UUID_IDM_GROUP_WRITE_PRIV,
            UUID_IDM_GROUP_UNIX_EXTEND_PRIV,
            UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV,
            UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV,
            UUID_IDM_PEOPLE_WRITE_PRIV,
            UUID_IDM_HP_PEOPLE_READ_PRIV,
            UUID_IDM_HP_PEOPLE_WRITE_PRIV,
            UUID_IDM_PEOPLE_WRITE_PRIV,
            UUID_IDM_ACCOUNT_READ_PRIV,
            UUID_IDM_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_ACCOUNT_WRITE_PRIV,
            UUID_IDM_HP_ACCOUNT_READ_PRIV,
            UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_HP_ACCOUNT_WRITE_PRIV,
        ];

        let res: Result<(), _> = delete_entries
            .into_iter()
            .try_for_each(|entry_uuid| self.internal_delete_uuid_if_exists(entry_uuid));
        if res.is_ok() {
            admin_debug!("migrate 16 to 17 -> result Ok!");
        } else {
            admin_error!(?res, "migrate 16 to 17 -> result");
        }
        debug_assert!(res.is_ok());
        res
    }

    #[instrument(level = "info", skip_all)]
    /// Automate fix for #2470 - force the domain version to be lowered, to allow
    /// it to re-raise and force re-run migrations. This is because we accidentally
    /// were "overwriting" the changes from domain migrations on startup due to
    /// a logic error. At this point in the startup, the server phase is lower than
    /// domain info ready, so the change won't immediately trigger remigrations. Rather
    /// it will force them later in the startup.
    pub fn migrate_18_to_19(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 18 to 19 migration.");

        debug_assert!(*self.phase < ServerPhase::DomainInfoReady);
        if *self.phase >= ServerPhase::DomainInfoReady {
            error!("Unable to perform system migration as server phase is greater or equal to domain info ready");
            return Err(OperationError::MG0003ServerPhaseInvalidForMigration);
        };

        self.internal_modify_uuid(
            UUID_DOMAIN_INFO,
            &ModifyList::new_purge_and_set(Attribute::Version, Value::new_uint32(DOMAIN_LEVEL_2)),
        )
        .map(|()| {
            warn!(
                "Domain level has been temporarily lowered to {}",
                DOMAIN_LEVEL_2
            );
        })
    }

    #[instrument(level = "info", skip_all)]
    /// This migration will
    ///  * Trigger a "once off" mfa account policy rule on all persons.
    pub(crate) fn migrate_domain_2_to_3(&mut self) -> Result<(), OperationError> {
        let idm_all_persons = match self.internal_search_uuid(UUID_IDM_ALL_PERSONS) {
            Ok(entry) => entry,
            Err(OperationError::NoMatchingEntries) => return Ok(()),
            Err(e) => return Err(e),
        };

        let credential_policy =
            idm_all_persons.get_ava_single_credential_type(Attribute::CredentialTypeMinimum);

        if credential_policy.is_some() {
            debug!("Credential policy already present, not applying change.");
            return Ok(());
        }

        self.internal_modify_uuid(
            UUID_IDM_ALL_PERSONS,
            &ModifyList::new_purge_and_set(
                Attribute::CredentialTypeMinimum,
                CredentialType::Mfa.into(),
            ),
        )
        .map(|()| {
            info!("Upgraded default account policy to enforce MFA");
        })
    }

    #[instrument(level = "info", skip_all)]
    /// Migrations for Oauth to support multiple origins, and custom claims.
    pub(crate) fn migrate_domain_3_to_4(&mut self) -> Result<(), OperationError> {
        let idm_schema_attrs = [
            SCHEMA_ATTR_OAUTH2_RS_CLAIM_MAP_DL4.clone().into(),
            SCHEMA_ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT_DL4
                .clone()
                .into(),
        ];

        idm_schema_attrs
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_3_to_4 -> Error");
                err
            })?;

        let idm_schema_classes = [
            SCHEMA_CLASS_OAUTH2_RS_DL4.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_PUBLIC_DL4.clone().into(),
            IDM_ACP_OAUTH2_MANAGE_DL4.clone().into(),
        ];

        idm_schema_classes
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_3_to_4 -> Error");
                err
            })
    }

    #[instrument(level = "info", skip_all)]
    /// Migrations for Oauth to move rs name from a dedicated type to name
    /// and to allow oauth2 sessions on resource servers for client credentials
    /// grants. Accounts, persons and service accounts have some attributes
    /// relocated to allow oauth2 rs to become accounts.
    pub(crate) fn migrate_domain_4_to_5(&mut self) -> Result<(), OperationError> {
        let idm_schema_classes = [
            SCHEMA_CLASS_PERSON_DL5.clone().into(),
            SCHEMA_CLASS_ACCOUNT_DL5.clone().into(),
            SCHEMA_CLASS_SERVICE_ACCOUNT_DL5.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_DL5.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_BASIC_DL5.clone().into(),
            IDM_ACP_OAUTH2_MANAGE_DL5.clone().into(),
        ];

        idm_schema_classes
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_4_to_5 -> Error");
                err
            })?;

        // Reload mid txn so that the next modification works.
        self.force_schema_reload();
        self.reload()?;

        // Now we remove attributes from service accounts that have been unable to be set
        // via a user interface for more than a year.
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Account.into()),
            f_eq(Attribute::Class, EntryClass::ServiceAccount.into()),
        ]));
        let modlist = ModifyList::new_list(vec![
            Modify::Purged(Attribute::PassKeys.into()),
            Modify::Purged(Attribute::AttestedPasskeys.into()),
            Modify::Purged(Attribute::CredentialUpdateIntentToken.into()),
            Modify::Purged(Attribute::RadiusSecret.into()),
        ]);
        self.internal_modify(&filter, &modlist)?;

        // Now move all oauth2 rs name.
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
            f_pres(Attribute::OAuth2RsName),
        ]));

        let pre_candidates = self.internal_search(filter).map_err(|err| {
            admin_error!(?err, "migrate_domain_4_to_5 internal search failure");
            err
        })?;

        let modset: Vec<_> = pre_candidates
            .into_iter()
            .filter_map(|ent| {
                ent.get_ava_single_iname(Attribute::OAuth2RsName)
                    .map(|rs_name| {
                        let modlist = vec![
                            Modify::Present(Attribute::Class.into(), EntryClass::Account.into()),
                            Modify::Present(Attribute::Name.into(), Value::new_iname(rs_name)),
                            m_purge(Attribute::OAuth2RsName),
                        ];

                        (ent.get_uuid(), ModifyList::new_list(modlist))
                    })
            })
            .collect();

        // If there is nothing, we don't need to do anything.
        if modset.is_empty() {
            admin_info!("migrate_domain_4_to_5 no entries to migrate, complete");
            return Ok(());
        }

        // Apply the batch mod.
        self.internal_batch_modify(modset.into_iter())
    }

    /// Migration domain level 5 to 6 - support query limits in account policy.
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_5_to_6(&mut self) -> Result<(), OperationError> {
        let idm_schema_classes = [
            SCHEMA_ATTR_LIMIT_SEARCH_MAX_RESULTS_DL6.clone().into(),
            SCHEMA_ATTR_LIMIT_SEARCH_MAX_FILTER_TEST_DL6.clone().into(),
            SCHEMA_ATTR_KEY_INTERNAL_DATA_DL6.clone().into(),
            SCHEMA_ATTR_KEY_PROVIDER_DL6.clone().into(),
            SCHEMA_ATTR_KEY_ACTION_ROTATE_DL6.clone().into(),
            SCHEMA_ATTR_KEY_ACTION_REVOKE_DL6.clone().into(),
            SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_ES256_DL6.clone().into(),
            SCHEMA_CLASS_ACCOUNT_POLICY_DL6.clone().into(),
            SCHEMA_CLASS_DOMAIN_INFO_DL6.clone().into(),
            SCHEMA_CLASS_SERVICE_ACCOUNT_DL6.clone().into(),
            SCHEMA_CLASS_SYNC_ACCOUNT_DL6.clone().into(),
            SCHEMA_CLASS_KEY_PROVIDER_DL6.clone().into(),
            SCHEMA_CLASS_KEY_PROVIDER_INTERNAL_DL6.clone().into(),
            SCHEMA_CLASS_KEY_OBJECT_DL6.clone().into(),
            SCHEMA_CLASS_KEY_OBJECT_JWT_ES256_DL6.clone().into(),
            SCHEMA_CLASS_KEY_OBJECT_JWE_A128GCM_DL6.clone().into(),
            SCHEMA_CLASS_KEY_OBJECT_INTERNAL_DL6.clone().into(),
        ];

        idm_schema_classes
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_5_to_6 -> Error");
                err
            })?;

        self.reload()?;

        let idm_data = [
            // Update access controls.
            IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_DL6.clone().into(),
            IDM_ACP_PEOPLE_CREATE_DL6.clone().into(),
            IDM_ACP_GROUP_MANAGE_DL6.clone().into(),
            // Update anonymous with the correct entry manager,
            BUILTIN_ACCOUNT_ANONYMOUS_DL6.clone().into(),
            // Add the internal key provider.
            E_KEY_PROVIDER_INTERNAL_DL6.clone().into(),
        ];

        idm_data
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_5_to_6 -> Error");
                err
            })?;

        // all existing built-in objects get a builtin class
        let filter = f_lt(
            Attribute::Uuid,
            PartialValue::Uuid(DYNAMIC_RANGE_MINIMUM_UUID),
        );
        let modlist = modlist!([m_pres(Attribute::Class, &EntryClass::Builtin.into())]);

        self.internal_modify(&filter!(filter), &modlist)?;

        // Reload such that the new default key provider is loaded.
        self.reload()?;

        // Update the domain entry to contain it's key object, which can now be generated.
        let idm_data = [E_DOMAIN_INFO_DL6.clone().into()];
        idm_data
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_5_to_6 -> Error");
                err
            })?;

        // Migrate the domain key to a retained key on the key object.
        let domain_es256_private_key = self.get_domain_es256_private_key().map_err(|err| {
            error!(?err, "migrate_domain_5_to_6 -> Error");
            err
        })?;

        // Migrate all service/scim account keys to the domain key for verification.
        let filter = filter!(f_or!([
            f_eq(Attribute::Class, EntryClass::ServiceAccount.into()),
            f_eq(Attribute::Class, EntryClass::SyncAccount.into())
        ]));
        let entry_keys_to_migrate = self.internal_search(filter)?;

        let mut modlist = Vec::with_capacity(1 + entry_keys_to_migrate.len());

        modlist.push(Modify::Present(
            Attribute::KeyActionImportJwsEs256.into(),
            Value::PrivateBinary(domain_es256_private_key),
        ));

        for entry in entry_keys_to_migrate {
            // In these entries, the keys are in JwsEs256PrivateKey.
            if let Some(jws_signer) =
                entry.get_ava_single_jws_key_es256(Attribute::JwsEs256PrivateKey)
            {
                let es256_private_key = jws_signer.private_key_to_der().map_err(|err| {
                    error!(?err, uuid = ?entry.get_display_id(), "unable to convert signer to der");
                    OperationError::InvalidValueState
                })?;

                modlist.push(Modify::Present(
                    Attribute::KeyActionImportJwsEs256.into(),
                    Value::PrivateBinary(es256_private_key),
                ));
            }
        }

        let modlist = ModifyList::new_list(modlist);

        self.internal_modify_uuid(UUID_DOMAIN_INFO, &modlist)?;

        Ok(())
    }

    /// Migration domain level 6 to 7
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_6_to_7(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) {
            error!("Unable to raise domain level from 6 to 7.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // ============== Apply constraints ===============

        // Due to changes in gidnumber allocation, in the *extremely* unlikely
        // case that a user's ID was generated outside the valid range, we re-request
        // the creation of their gid number to proceed.
        let filter = filter!(f_and!([
            f_or!([
                f_eq(Attribute::Class, EntryClass::PosixAccount.into()),
                f_eq(Attribute::Class, EntryClass::PosixGroup.into())
            ]),
            // This logic gets a bit messy but it would be:
            // If ! (
            //    (GID_REGULAR_USER_MIN < value < GID_REGULAR_USER_MAX) ||
            //    (GID_UNUSED_A_MIN < value < GID_UNUSED_A_MAX) ||
            //    (GID_UNUSED_B_MIN < value < GID_UNUSED_B_MAX) ||
            //    (GID_UNUSED_C_MIN < value < GID_UNUSED_D_MAX)
            // )
            f_andnot(f_or!([
                f_and!([
                    // The gid value must be less than GID_REGULAR_USER_MAX
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_REGULAR_USER_MAX)
                    ),
                    // This bit of mental gymnastics is "greater than".
                    // The gid value must not be less than USER_MIN
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_REGULAR_USER_MIN)
                    ))
                ]),
                f_and!([
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_A_MAX)
                    ),
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_A_MIN)
                    ))
                ]),
                f_and!([
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_B_MAX)
                    ),
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_B_MIN)
                    ))
                ]),
                // If both of these conditions are true we get:
                // C_MIN < value < D_MAX, which the outer and-not inverts.
                f_and!([
                    // The gid value must be less than GID_UNUSED_D_MAX
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_D_MAX)
                    ),
                    // This bit of mental gymnastics is "greater than".
                    // The gid value must not be less than C_MIN
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_C_MIN)
                    ))
                ]),
            ]))
        ]));

        let results = self.internal_search(filter).map_err(|err| {
            error!(?err, "migrate_domain_6_to_7 -> Error");
            err
        })?;

        if !results.is_empty() {
            error!("Unable to proceed. Not all entries meet gid/uid constraints.");
            for entry in results {
                error!(gid_invalid = ?entry.get_display_id());
            }
            return Err(OperationError::MG0005GidConstraintsNotMet);
        }

        // =========== Apply changes ==============

        // Do this before schema change since domain info has cookie key
        // as may at this point.
        //
        // Domain info should have the attribute private cookie key removed.
        let modlist = ModifyList::new_list(vec![
            Modify::Purged(Attribute::PrivateCookieKey.into()),
            Modify::Purged(Attribute::Es256PrivateKeyDer.into()),
            Modify::Purged(Attribute::FernetPrivateKeyStr.into()),
        ]);

        self.internal_modify_uuid(UUID_DOMAIN_INFO, &modlist)?;

        let filter = filter!(f_or!([
            f_eq(Attribute::Class, EntryClass::ServiceAccount.into()),
            f_eq(Attribute::Class, EntryClass::SyncAccount.into())
        ]));

        let modlist =
            ModifyList::new_list(vec![Modify::Purged(Attribute::JwsEs256PrivateKey.into())]);

        self.internal_modify(&filter, &modlist)?;

        // Now update schema

        let idm_schema_classes = [
            SCHEMA_CLASS_DOMAIN_INFO_DL7.clone().into(),
            SCHEMA_CLASS_SERVICE_ACCOUNT_DL7.clone().into(),
            SCHEMA_CLASS_SYNC_ACCOUNT_DL7.clone().into(),
        ];

        idm_schema_classes
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_6_to_7 -> Error");
                err
            })?;

        self.reload()?;

        // Post schema changes.

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub fn initialise_schema_core(&mut self) -> Result<(), OperationError> {
        admin_debug!("initialise_schema_core -> start ...");
        // Load in all the "core" schema, that we already have in "memory".
        let entries = self.schema.to_entries();

        // admin_debug!("Dumping schemas: {:?}", entries);

        // internal_migrate_or_create.
        let r: Result<_, _> = entries.into_iter().try_for_each(|e| {
            trace!(?e, "init schema entry");
            self.internal_migrate_or_create(e)
        });
        if r.is_ok() {
            admin_debug!("initialise_schema_core -> Ok!");
        } else {
            admin_error!(?r, "initialise_schema_core -> Error");
        }
        // why do we have error handling if it's always supposed to be `Ok`?
        debug_assert!(r.is_ok());
        r
    }

    #[instrument(level = "info", skip_all)]
    pub fn initialise_schema_idm(&mut self) -> Result<(), OperationError> {
        admin_debug!("initialise_schema_idm -> start ...");

        // ⚠️  DOMAIN LEVEL 1 SCHEMA ATTRIBUTES ⚠️
        // Future schema attributes need to be added via migrations.
        //
        // DO NOT MODIFY THIS DEFINITION
        let idm_schema_attrs = [
            SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL.clone().into(),
            SCHEMA_ATTR_SYNC_YIELD_AUTHORITY.clone().into(),
        ];

        let r: Result<(), _> = idm_schema_attrs
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if r.is_err() {
            error!(res = ?r, "initialise_schema_idm -> Error");
        }
        debug_assert!(r.is_ok());

        // ⚠️  DOMAIN LEVEL 1 SCHEMA ATTRIBUTES ⚠️
        // Future schema classes need to be added via migrations.
        //
        // DO NOT MODIFY THIS DEFINITION
        let idm_schema: Vec<EntryInitNew> = vec![
            SCHEMA_ATTR_MAIL.clone().into(),
            SCHEMA_ATTR_ACCOUNT_EXPIRE.clone().into(),
            SCHEMA_ATTR_ACCOUNT_VALID_FROM.clone().into(),
            SCHEMA_ATTR_API_TOKEN_SESSION.clone().into(),
            SCHEMA_ATTR_AUTH_SESSION_EXPIRY.clone().into(),
            SCHEMA_ATTR_AUTH_PRIVILEGE_EXPIRY.clone().into(),
            SCHEMA_ATTR_AUTH_PASSWORD_MINIMUM_LENGTH.clone().into(),
            SCHEMA_ATTR_BADLIST_PASSWORD.clone().into(),
            SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN.clone().into(),
            SCHEMA_ATTR_ATTESTED_PASSKEYS.clone().into(),
            SCHEMA_ATTR_DISPLAYNAME.clone().into(),
            SCHEMA_ATTR_DOMAIN_DISPLAY_NAME.clone().into(),
            SCHEMA_ATTR_DOMAIN_LDAP_BASEDN.clone().into(),
            SCHEMA_ATTR_DOMAIN_NAME.clone().into(),
            SCHEMA_ATTR_LDAP_ALLOW_UNIX_PW_BIND.clone().into(),
            SCHEMA_ATTR_DOMAIN_SSID.clone().into(),
            SCHEMA_ATTR_DOMAIN_TOKEN_KEY.clone().into(),
            SCHEMA_ATTR_DOMAIN_UUID.clone().into(),
            SCHEMA_ATTR_DYNGROUP_FILTER.clone().into(),
            SCHEMA_ATTR_EC_KEY_PRIVATE.clone().into(),
            SCHEMA_ATTR_ES256_PRIVATE_KEY_DER.clone().into(),
            SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR.clone().into(),
            SCHEMA_ATTR_GIDNUMBER.clone().into(),
            SCHEMA_ATTR_GRANT_UI_HINT.clone().into(),
            SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY.clone().into(),
            SCHEMA_ATTR_LEGALNAME.clone().into(),
            SCHEMA_ATTR_LOGINSHELL.clone().into(),
            SCHEMA_ATTR_NAME_HISTORY.clone().into(),
            SCHEMA_ATTR_NSUNIQUEID.clone().into(),
            SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
                .clone()
                .into(),
            SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP.clone().into(),
            SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.clone().into(),
            SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_NAME.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_ORIGIN.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY.clone().into(),
            SCHEMA_ATTR_OAUTH2_SESSION.clone().into(),
            SCHEMA_ATTR_PASSKEYS.clone().into(),
            SCHEMA_ATTR_PRIMARY_CREDENTIAL.clone().into(),
            SCHEMA_ATTR_PRIVATE_COOKIE_KEY.clone().into(),
            SCHEMA_ATTR_RADIUS_SECRET.clone().into(),
            SCHEMA_ATTR_RS256_PRIVATE_KEY_DER.clone().into(),
            SCHEMA_ATTR_SSH_PUBLICKEY.clone().into(),
            SCHEMA_ATTR_SYNC_COOKIE.clone().into(),
            SCHEMA_ATTR_SYNC_TOKEN_SESSION.clone().into(),
            SCHEMA_ATTR_UNIX_PASSWORD.clone().into(),
            SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION.clone().into(),
            SCHEMA_ATTR_DENIED_NAME.clone().into(),
            SCHEMA_ATTR_CREDENTIAL_TYPE_MINIMUM.clone().into(),
            SCHEMA_ATTR_WEBAUTHN_ATTESTATION_CA_LIST.clone().into(),
        ];

        let r = idm_schema
            .into_iter()
            // Each item individually logs it's result
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if r.is_err() {
            error!(res = ?r, "initialise_schema_idm -> Error");
        }

        debug_assert!(r.is_ok());

        // ⚠️  DOMAIN LEVEL 1 SCHEMA CLASSES ⚠️
        // Future schema classes need to be added via migrations.
        //
        // DO NOT MODIFY THIS DEFINITION
        let idm_schema_classes_dl1: Vec<EntryInitNew> = vec![
            SCHEMA_CLASS_ACCOUNT.clone().into(),
            SCHEMA_CLASS_ACCOUNT_POLICY.clone().into(),
            SCHEMA_CLASS_DOMAIN_INFO.clone().into(),
            SCHEMA_CLASS_DYNGROUP.clone().into(),
            SCHEMA_CLASS_GROUP.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS.clone().into(),
            SCHEMA_CLASS_ORGPERSON.clone().into(),
            SCHEMA_CLASS_PERSON.clone().into(),
            SCHEMA_CLASS_POSIXACCOUNT.clone().into(),
            SCHEMA_CLASS_POSIXGROUP.clone().into(),
            SCHEMA_CLASS_SERVICE_ACCOUNT.clone().into(),
            SCHEMA_CLASS_SYNC_ACCOUNT.clone().into(),
            SCHEMA_CLASS_SYSTEM_CONFIG.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_BASIC.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_PUBLIC.clone().into(),
        ];

        let r: Result<(), _> = idm_schema_classes_dl1
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if r.is_err() {
            error!(res = ?r, "initialise_schema_idm -> Error");
        }
        debug_assert!(r.is_ok());

        debug!("initialise_schema_idm -> Ok!");

        r
    }

    #[instrument(level = "info", skip_all)]
    /// This function is idempotent, runs all the startup functionality and checks
    pub fn initialise_domain_info(&mut self) -> Result<(), OperationError> {
        // First, check the system_info object. This stores some server information
        // and details. It's a pretty const thing. Also check anonymous, important to many
        // concepts.
        let res = self
            .internal_migrate_or_create(E_SYSTEM_INFO_V1.clone())
            .and_then(|_| self.internal_migrate_or_create(E_DOMAIN_INFO_V1.clone()))
            .and_then(|_| self.internal_migrate_or_create(E_SYSTEM_CONFIG_V1.clone()));
        if res.is_err() {
            admin_error!("initialise_domain_info -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        res
    }

    #[instrument(level = "info", skip_all)]
    /// This function is idempotent, runs all the startup functionality and checks
    pub fn initialise_idm(&mut self) -> Result<(), OperationError> {
        // The domain info now exists, we should be able to do these migrations as they will
        // cause SPN regenerations to occur

        // Delete entries that no longer need to exist.
        // TODO: Shouldn't this be a migration?
        // Check the admin object exists (migrations).
        // Create the default idm_admin group.
        let admin_entries: Vec<EntryInitNew> = idm_builtin_admin_entries()?;
        let res: Result<(), _> = admin_entries
            .into_iter()
            // Each item individually logs it's result
            .try_for_each(|ent| self.internal_migrate_or_create(ent));
        if res.is_ok() {
            admin_debug!("initialise_idm p1 -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p1 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        let res: Result<(), _> = idm_builtin_non_admin_groups()
            .into_iter()
            .try_for_each(|e| self.internal_migrate_or_create(e.clone().try_into()?));
        if res.is_ok() {
            admin_debug!("initialise_idm p2 -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p2 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        // ⚠️  DOMAIN LEVEL 1 ENTRIES ⚠️
        // Future entries need to be added via migrations.
        //
        // DO NOT MODIFY THIS DEFINITION
        let idm_entries: Vec<BuiltinAcp> = vec![
            // Built in access controls.
            IDM_ACP_RECYCLE_BIN_SEARCH_V1.clone(),
            IDM_ACP_RECYCLE_BIN_REVIVE_V1.clone(),
            IDM_ACP_SCHEMA_WRITE_ATTRS_V1.clone(),
            IDM_ACP_SCHEMA_WRITE_CLASSES_V1.clone(),
            IDM_ACP_ACP_MANAGE_V1.clone(),
            IDM_ACP_GROUP_ENTRY_MANAGED_BY_MODIFY_V1.clone(),
            IDM_ACP_GROUP_ENTRY_MANAGER_V1.clone(),
            IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_V1.clone(),
            IDM_ACP_OAUTH2_MANAGE_V1.clone(),
            IDM_ACP_DOMAIN_ADMIN_V1.clone(),
            IDM_ACP_SYNC_ACCOUNT_MANAGE_V1.clone(),
            IDM_ACP_RADIUS_SERVERS_V1.clone(),
            IDM_ACP_RADIUS_SECRET_MANAGE_V1.clone(),
            IDM_ACP_PEOPLE_SELF_WRITE_MAIL_V1.clone(),
            IDM_ACP_SELF_READ_V1.clone(),
            IDM_ACP_SELF_WRITE_V1.clone(),
            IDM_ACP_ACCOUNT_SELF_WRITE_V1.clone(),
            IDM_ACP_SELF_NAME_WRITE_V1.clone(),
            IDM_ACP_ALL_ACCOUNTS_POSIX_READ_V1.clone(),
            IDM_ACP_ACCOUNT_MAIL_READ_V1.clone(),
            IDM_ACP_SYSTEM_CONFIG_ACCOUNT_POLICY_MANAGE_V1.clone(),
            IDM_ACP_GROUP_UNIX_MANAGE_V1.clone(),
            IDM_ACP_HP_GROUP_UNIX_MANAGE_V1.clone(),
            IDM_ACP_GROUP_READ_V1.clone(),
            IDM_ACP_GROUP_MANAGE_V1.clone(),
            IDM_ACP_ACCOUNT_UNIX_EXTEND_V1.clone(),
            IDM_ACP_PEOPLE_PII_READ_V1.clone(),
            IDM_ACP_PEOPLE_PII_MANAGE_V1.clone(),
            IDM_ACP_PEOPLE_CREATE_V1.clone(),
            IDM_ACP_PEOPLE_READ_V1.clone(),
            IDM_ACP_PEOPLE_MANAGE_V1.clone(),
            IDM_ACP_PEOPLE_DELETE_V1.clone(),
            IDM_ACP_PEOPLE_CREDENTIAL_RESET_V1.clone(),
            IDM_ACP_HP_PEOPLE_CREDENTIAL_RESET_V1.clone(),
            IDM_ACP_SERVICE_ACCOUNT_CREATE_V1.clone(),
            IDM_ACP_SERVICE_ACCOUNT_DELETE_V1.clone(),
            IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGER_V1.clone(),
            IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY_V1.clone(),
            IDM_ACP_HP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY_V1.clone(),
            IDM_ACP_SERVICE_ACCOUNT_MANAGE_V1.clone(),
        ];

        let res: Result<(), _> = idm_entries
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry.into()));
        if res.is_ok() {
            admin_debug!("initialise_idm p3 -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res
    }
}

impl<'a> QueryServerReadTransaction<'a> {
    /// Retrieve the domain info of this server
    pub fn domain_upgrade_check(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckReport, OperationError> {
        let d_info = &self.d_info;

        let name = d_info.d_name.clone();
        let uuid = d_info.d_uuid;
        let current_level = d_info.d_vers;
        let upgrade_level = DOMAIN_NEXT_LEVEL;

        let mut report_items = Vec::with_capacity(1);

        if current_level <= DOMAIN_LEVEL_6 && upgrade_level >= DOMAIN_LEVEL_7 {
            let item = self
                .domain_upgrade_check_6_to_7_gidnumber()
                .map_err(|err| {
                    error!(
                        ?err,
                        "Failed to perform domain upgrade check 6 to 7 - gidnumber"
                    );
                    err
                })?;
            report_items.push(item);
        }

        Ok(ProtoDomainUpgradeCheckReport {
            name,
            uuid,
            current_level,
            upgrade_level,
            report_items,
        })
    }

    pub(crate) fn domain_upgrade_check_6_to_7_gidnumber(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckItem, OperationError> {
        let filter = filter!(f_and!([
            f_or!([
                f_eq(Attribute::Class, EntryClass::PosixAccount.into()),
                f_eq(Attribute::Class, EntryClass::PosixGroup.into())
            ]),
            // This logic gets a bit messy but it would be:
            // If ! (
            //    (GID_REGULAR_USER_MIN < value < GID_REGULAR_USER_MAX) ||
            //    (GID_UNUSED_A_MIN < value < GID_UNUSED_A_MAX) ||
            //    (GID_UNUSED_B_MIN < value < GID_UNUSED_B_MAX) ||
            //    (GID_UNUSED_C_MIN < value < GID_UNUSED_D_MAX)
            // )
            f_andnot(f_or!([
                f_and!([
                    // The gid value must be less than GID_REGULAR_USER_MAX
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_REGULAR_USER_MAX)
                    ),
                    // This bit of mental gymnastics is "greater than".
                    // The gid value must not be less than USER_MIN
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_REGULAR_USER_MIN)
                    ))
                ]),
                f_and!([
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_A_MAX)
                    ),
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_A_MIN)
                    ))
                ]),
                f_and!([
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_B_MAX)
                    ),
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_B_MIN)
                    ))
                ]),
                // If both of these conditions are true we get:
                // C_MIN < value < D_MAX, which the outer and-not inverts.
                f_and!([
                    // The gid value must be less than GID_UNUSED_D_MAX
                    f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_D_MAX)
                    ),
                    // This bit of mental gymnastics is "greater than".
                    // The gid value must not be less than C_MIN
                    f_andnot(f_lt(
                        Attribute::GidNumber,
                        PartialValue::Uint32(crate::plugins::gidnumber::GID_UNUSED_C_MIN)
                    ))
                ]),
            ]))
        ]));

        let results = self.internal_search(filter)?;

        let affected_entries = results
            .into_iter()
            .map(|entry| entry.get_display_id())
            .collect::<Vec<_>>();

        let status = if affected_entries.is_empty() {
            ProtoDomainUpgradeCheckStatus::Pass6To7Gidnumber
        } else {
            ProtoDomainUpgradeCheckStatus::Fail6To7Gidnumber
        };

        Ok(ProtoDomainUpgradeCheckItem {
            status,
            from_level: DOMAIN_LEVEL_6,
            to_level: DOMAIN_LEVEL_7,
            affected_entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[qs_test]
    async fn test_init_idempotent_schema_core(server: &QueryServer) {
        {
            // Setup and abort.
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
        {
            // Now do it again in a new txn, but abort
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            // Now do it again in a new txn.
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_5)]
    async fn test_migrations_dl5_dl6(server: &QueryServer) {
        // Assert our instance was setup to version 5
        let mut write_txn = server.write(duration_from_epoch_now()).await;

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_5);

        // Entry doesn't exist yet.
        let _entry_not_found = write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_LIMIT_SEARCH_MAX_RESULTS)
            .expect_err("unable to newly migrated schema entry");

        // Set the version to 6.
        write_txn
            .internal_modify_uuid(
                UUID_DOMAIN_INFO,
                &ModifyList::new_purge_and_set(
                    Attribute::Version,
                    Value::new_uint32(DOMAIN_LEVEL_6),
                ),
            )
            .expect("Unable to set domain level to version 6");

        // Re-load - this applies the migrations.
        write_txn.reload().expect("Unable to reload transaction");

        // It now exists as the migrations were run.
        let _entry = write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_LIMIT_SEARCH_MAX_RESULTS)
            .expect("unable to newly migrated schema entry");

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_6)]
    async fn test_migrations_dl6_dl7(server: &QueryServer) {
        // Assert our instance was setup to version 6
        let mut write_txn = server.write(duration_from_epoch_now()).await;

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_6);

        // per migration verification.
        let domain_entry = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("Unable to access domain entry");

        assert!(domain_entry.attribute_pres(Attribute::PrivateCookieKey));

        // Set the version to 7.
        write_txn
            .internal_modify_uuid(
                UUID_DOMAIN_INFO,
                &ModifyList::new_purge_and_set(
                    Attribute::Version,
                    Value::new_uint32(DOMAIN_LEVEL_7),
                ),
            )
            .expect("Unable to set domain level to version 7");

        // Re-load - this applies the migrations.
        write_txn.reload().expect("Unable to reload transaction");

        // post migration verification.
        let domain_entry = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("Unable to access domain entry");

        assert!(!domain_entry.attribute_pres(Attribute::PrivateCookieKey));

        write_txn.commit().expect("Unable to commit");
    }
}

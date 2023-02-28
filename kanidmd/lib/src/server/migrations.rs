use kanidm_proto::v1::SchemaError;
use std::time::Duration;

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

        if system_info_version > 0 {
            if system_info_version <= 9 {
                error!("Your instance of Kanidm is version 1.1.0-alpha.10 or lower, and you are trying to perform a skip upgrade. This will not work.");
                error!("You need to upgrade one version at a time to ensure upgrade migrations are performed in the correct order.");
                return Err(OperationError::InvalidState);
            }

            if system_info_version < 9 {
                migrate_txn.migrate_8_to_9()?;
            }

            if system_info_version < 10 {
                migrate_txn.migrate_9_to_10()?;
            }

            if system_info_version < 11 {
                migrate_txn.migrate_10_to_11()?;
            }

            if system_info_version < 12 {
                migrate_txn.migrate_11_to_12()?;
            }
        }

        migrate_txn.commit()?;
        // Migrations complete. Init idm will now set the version as needed.

        let mut ts_write_3 = self.write(ts).await;
        ts_write_3.initialise_idm().and_then(|_| {
            ts_write_3.set_phase(ServerPhase::Running);
            ts_write_3.commit()
        })?;

        // Here is where in the future we will need to apply domain version increments.
        // The actually migrations are done in a transaction though, this just needs to
        // bump the version in it's own transaction.

        admin_debug!("Database version check and migrations success! ☀️  ");
        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
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

    pub fn internal_migrate_or_create(
        &mut self,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        // if the thing exists, ensure the set of attributes on
        // Entry A match and are present (but don't delete multivalue, or extended
        // attributes in the situation.
        // If not exist, create from Entry B
        //
        // This will extra classes an attributes alone!
        //
        // NOTE: gen modlist IS schema aware and will handle multivalue
        // correctly!
        trace!("internal_migrate_or_create operating on {:?}", e.get_uuid());

        let filt = match e.filter_from_attrs(&[AttrString::from("uuid")]) {
            Some(f) => f,
            None => return Err(OperationError::FilterGeneration),
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
            f_eq("class", PVCLASS_OAUTH2_RS.clone()),
            f_eq("class", PVCLASS_OAUTH2_BASIC.clone()),
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

    /// Migrate 9 to 10
    ///
    /// This forces a load and rewrite of all credentials stored on all accounts so that they are
    /// updated to new on-disk formats. This will allow us to purge some older on disk formats in
    /// a future version.
    ///
    /// An extended feature of this is the ability to store multiple TOTP's per entry.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_9_to_10(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 9 to 10 migration.");
        let filter = filter!(f_or!([
            f_pres("primary_credential"),
            f_pres("unix_password"),
        ]));
        // This "does nothing" since everything has object anyway, but it forces the entry to be
        // loaded and rewritten.
        let modlist = ModifyList::new_append("class", Value::new_class("object"));
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 10 to 11
    ///
    /// This forces a load of all credentials, and then examines if any are "passkey" capable. If they
    /// are, they are migrated to the passkey type, allowing us to deprecate and remove the older
    /// credential behaviour.
    ///
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_10_to_11(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 9 to 10 migration.");
        let filter = filter!(f_pres("primary_credential"));

        let pre_candidates = self.internal_search(filter).map_err(|e| {
            admin_error!(err = ?e, "migrate_10_to_11 internal search failure");
            e
        })?;

        // First, filter based on if any credentials present actually are the legacy
        // webauthn type.
        let modset: Vec<_> = pre_candidates
            .into_iter()
            .filter_map(|ent| {
                ent.get_ava_single_credential("primary_credential")
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
                            .chain(std::iter::once(m_purge("primary_credential")))
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
    /// Rewrite api-tokens from session to a dedicated api token type.
    ///
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_11_to_12(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 11 to 12 migration.");
        // sync_token_session
        let filter = filter!(f_or!([
            f_pres("api_token_session"),
            f_pres("sync_token_session"),
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
            if let Some(api_token_session) = ent.pop_ava("api_token_session") {
                let api_token_session =
                    api_token_session
                        .migrate_session_to_apitoken()
                        .map_err(|e| {
                            error!("Failed to convert api_token_session from session -> apitoken");
                            e
                        })?;

                ent.set_ava_set("api_token_session", api_token_session);
            }

            if let Some(sync_token_session) = ent.pop_ava("sync_token_session") {
                let sync_token_session =
                    sync_token_session
                        .migrate_session_to_apitoken()
                        .map_err(|e| {
                            error!("Failed to convert sync_token_session from session -> apitoken");
                            e
                        })?;

                ent.set_ava_set("sync_token_session", sync_token_session);
            }
        }

        // Apply the batch mod.
        self.internal_apply_writable(mod_candidates)
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
        // List of IDM schemas to init.
        let idm_schema: Vec<&str> = vec![
            JSON_SCHEMA_ATTR_DISPLAYNAME,
            JSON_SCHEMA_ATTR_LEGALNAME,
            JSON_SCHEMA_ATTR_MAIL,
            JSON_SCHEMA_ATTR_SSH_PUBLICKEY,
            JSON_SCHEMA_ATTR_PRIMARY_CREDENTIAL,
            JSON_SCHEMA_ATTR_RADIUS_SECRET,
            JSON_SCHEMA_ATTR_DOMAIN_NAME,
            JSON_SCHEMA_ATTR_DOMAIN_DISPLAY_NAME,
            JSON_SCHEMA_ATTR_DOMAIN_UUID,
            JSON_SCHEMA_ATTR_DOMAIN_SSID,
            JSON_SCHEMA_ATTR_DOMAIN_TOKEN_KEY,
            JSON_SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR,
            JSON_SCHEMA_ATTR_GIDNUMBER,
            JSON_SCHEMA_ATTR_BADLIST_PASSWORD,
            JSON_SCHEMA_ATTR_LOGINSHELL,
            JSON_SCHEMA_ATTR_UNIX_PASSWORD,
            JSON_SCHEMA_ATTR_ACCOUNT_EXPIRE,
            JSON_SCHEMA_ATTR_ACCOUNT_VALID_FROM,
            JSON_SCHEMA_ATTR_OAUTH2_RS_NAME,
            JSON_SCHEMA_ATTR_OAUTH2_RS_ORIGIN,
            JSON_SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP,
            JSON_SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
            JSON_SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET,
            JSON_SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY,
            JSON_SCHEMA_ATTR_ES256_PRIVATE_KEY_DER,
            JSON_SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE,
            JSON_SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
            JSON_SCHEMA_ATTR_RS256_PRIVATE_KEY_DER,
            JSON_SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
            JSON_SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP,
            JSON_SCHEMA_ATTR_PASSKEYS,
            JSON_SCHEMA_ATTR_DEVICEKEYS,
            JSON_SCHEMA_ATTR_DYNGROUP_FILTER,
            JSON_SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY,
            JSON_SCHEMA_ATTR_API_TOKEN_SESSION,
            JSON_SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
            JSON_SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION,
            JSON_SCHEMA_ATTR_OAUTH2_SESSION,
            JSON_SCHEMA_ATTR_NSUNIQUEID,
            JSON_SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME,
            JSON_SCHEMA_ATTR_SYNC_TOKEN_SESSION,
            JSON_SCHEMA_ATTR_SYNC_COOKIE,
            JSON_SCHEMA_ATTR_GRANT_UI_HINT,
            JSON_SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING,
            JSON_SCHEMA_CLASS_PERSON,
            JSON_SCHEMA_CLASS_ORGPERSON,
            JSON_SCHEMA_CLASS_GROUP,
            JSON_SCHEMA_CLASS_DYNGROUP,
            JSON_SCHEMA_CLASS_ACCOUNT,
            JSON_SCHEMA_CLASS_SERVICE_ACCOUNT,
            JSON_SCHEMA_CLASS_DOMAIN_INFO,
            JSON_SCHEMA_CLASS_POSIXACCOUNT,
            JSON_SCHEMA_CLASS_POSIXGROUP,
            JSON_SCHEMA_CLASS_SYSTEM_CONFIG,
            JSON_SCHEMA_CLASS_OAUTH2_RS,
            JSON_SCHEMA_CLASS_OAUTH2_RS_BASIC,
            JSON_SCHEMA_CLASS_SYNC_ACCOUNT,
            JSON_SCHEMA_ATTR_PRIVATE_COOKIE_KEY,
        ];

        let r = idm_schema
            .iter()
            // Each item individually logs it's result
            .try_for_each(|e_str| self.internal_migrate_or_create_str(e_str));

        if r.is_ok() {
            admin_debug!("initialise_schema_idm -> Ok!");
        } else {
            admin_error!(res = ?r, "initialise_schema_idm -> Error");
        }
        debug_assert!(r.is_ok()); // why return a result if we assert it's `Ok`?

        r
    }

    // This function is idempotent
    #[instrument(level = "info", skip_all)]
    pub fn initialise_idm(&mut self) -> Result<(), OperationError> {
        // First, check the system_info object. This stores some server information
        // and details. It's a pretty const thing. Also check anonymous, important to many
        // concepts.
        let res = self
            .internal_migrate_or_create(E_SYSTEM_INFO_V1.clone())
            .and_then(|_| self.internal_migrate_or_create(E_DOMAIN_INFO_V1.clone()))
            .and_then(|_| self.internal_migrate_or_create(E_SYSTEM_CONFIG_V1.clone()));
        if res.is_err() {
            admin_error!("initialise_idm p1 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        res?;

        // The domain info now exists, we should be able to do these migrations as they will
        // cause SPN regenerations to occur

        // Check the admin object exists (migrations).
        // Create the default idm_admin group.
        let admin_entries = [
            E_ANONYMOUS_V1.clone(),
            E_ADMIN_V1.clone(),
            E_IDM_ADMIN_V1.clone(),
            E_IDM_ADMINS_V1.clone(),
            E_SYSTEM_ADMINS_V1.clone(),
        ];
        let res: Result<(), _> = admin_entries
            .into_iter()
            // Each item individually logs it's result
            .try_for_each(|ent| self.internal_migrate_or_create(ent));
        if res.is_err() {
            admin_error!("initialise_idm p2 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        res?;

        // Create any system default schema entries.

        // Create any system default access profile entries.
        let idm_entries = [
            // Builtin dyn groups,
            JSON_IDM_ALL_PERSONS,
            JSON_IDM_ALL_ACCOUNTS,
            // Builtin groups
            JSON_IDM_PEOPLE_MANAGE_PRIV_V1,
            JSON_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
            JSON_IDM_PEOPLE_EXTEND_PRIV_V1,
            JSON_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV_V1,
            JSON_IDM_PEOPLE_WRITE_PRIV_V1,
            JSON_IDM_PEOPLE_READ_PRIV_V1,
            JSON_IDM_HP_PEOPLE_EXTEND_PRIV_V1,
            JSON_IDM_HP_PEOPLE_WRITE_PRIV_V1,
            JSON_IDM_HP_PEOPLE_READ_PRIV_V1,
            JSON_IDM_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_GROUP_WRITE_PRIV_V1,
            JSON_IDM_GROUP_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_RADIUS_SECRET_WRITE_PRIV_V1,
            JSON_IDM_RADIUS_SECRET_READ_PRIV_V1,
            JSON_IDM_RADIUS_SERVERS_V1,
            // Write deps on read, so write must be added first.
            JSON_IDM_HP_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_HP_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_SCHEMA_MANAGE_PRIV_V1,
            JSON_IDM_HP_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_HP_GROUP_WRITE_PRIV_V1,
            JSON_IDM_HP_GROUP_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACP_MANAGE_PRIV_V1,
            JSON_DOMAIN_ADMINS,
            JSON_IDM_HP_OAUTH2_MANAGE_PRIV_V1,
            JSON_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
            JSON_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV,
            // All members must exist before we write HP
            JSON_IDM_HIGH_PRIVILEGE_V1,
            // Built in access controls.
            JSON_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1,
            JSON_IDM_ADMINS_ACP_REVIVE_V1,
            // JSON_IDM_ADMINS_ACP_MANAGE_V1,
            JSON_IDM_ALL_ACP_READ_V1,
            JSON_IDM_SELF_ACP_READ_V1,
            JSON_IDM_SELF_ACP_WRITE_V1,
            JSON_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_READ_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_WRITE_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_MANAGE_PRIV_V1,
            JSON_IDM_ACP_GROUP_WRITE_PRIV_V1,
            JSON_IDM_ACP_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_ACP_RADIUS_SERVERS_V1,
            JSON_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_ACP_HP_GROUP_WRITE_PRIV_V1,
            JSON_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1,
        ];

        let res: Result<(), _> = idm_entries
            .iter()
            .try_for_each(|e_str| self.internal_migrate_or_create_str(e_str));
        if res.is_ok() {
            admin_debug!("initialise_idm -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        let idm_entries = [
            E_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1.clone(),
            E_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1.clone(),
            E_IDM_ACP_ACP_MANAGE_PRIV_V1.clone(),
            E_IDM_ACP_DOMAIN_ADMIN_PRIV_V1.clone(),
            E_IDM_ACP_SYSTEM_CONFIG_PRIV_V1.clone(),
            E_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1.clone(),
            E_IDM_ACP_PEOPLE_EXTEND_PRIV_V1.clone(),
            E_IDM_ACP_HP_PEOPLE_READ_PRIV_V1.clone(),
            E_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1.clone(),
            E_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1.clone(),
            E_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1.clone(),
            E_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1.clone(),
            E_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1.clone(),
            E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1.clone(),
            E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1.clone(),
            E_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES.clone(),
            E_IDM_ACCOUNT_MAIL_READ_PRIV.clone(),
            E_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1.clone(),
        ];

        let res: Result<(), _> = idm_entries
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));
        if res.is_ok() {
            admin_debug!("initialise_idm -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        // Delete entries that no longer need to exist.
        let delete_entries = [UUID_IDM_ACP_OAUTH2_READ_PRIV_V1];

        let res: Result<(), _> = delete_entries
            .into_iter()
            .try_for_each(|entry_uuid| self.internal_delete_uuid_if_exists(entry_uuid));
        if res.is_ok() {
            admin_debug!("initialise_idm -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        self.changed_schema = true;
        self.changed_acp = true;

        Ok(())
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

    /*
    #[qs_test_no_init]
    async fn test_qs_upgrade_entry_attrs(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        assert!(server_txn.upgrade_reindex(SYSTEM_INDEX_VERSION).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        server_txn.initialise_schema_core().unwrap();
        server_txn.initialise_schema_idm().unwrap();
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        assert!(server_txn.upgrade_reindex(SYSTEM_INDEX_VERSION + 1).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        assert!(server_txn
            .internal_migrate_or_create_str(JSON_SYSTEM_INFO_V1)
            .is_ok());
        assert!(server_txn
            .internal_migrate_or_create_str(JSON_DOMAIN_INFO_V1)
            .is_ok());
        assert!(server_txn
            .internal_migrate_or_create_str(JSON_SYSTEM_CONFIG_V1)
            .is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // ++ Mod the schema to set name to the old string type
        let me_syn = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_or!([
                    f_eq("attributename", PartialValue::new_iutf8("name")),
                    f_eq("attributename", PartialValue::new_iutf8("domain_name")),
                ])),
                ModifyList::new_purge_and_set(
                    "syntax",
                    Value::new_syntaxs("UTF8STRING_INSENSITIVE").unwrap(),
                ),
            )
        };
        assert!(server_txn.modify(&me_syn).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // ++ Mod domain name and name to be the old type.
        let me_dn = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("uuid", PartialValue::Uuid(UUID_DOMAIN_INFO))),
                ModifyList::new_list(vec![
                    Modify::Purged(AttrString::from("name")),
                    Modify::Purged(AttrString::from("domain_name")),
                    Modify::Present(AttrString::from("name"), Value::new_iutf8("domain_local")),
                    Modify::Present(
                        AttrString::from("domain_name"),
                        Value::new_iutf8("example.com"),
                    ),
                ]),
            )
        };
        assert!(server_txn.modify(&me_dn).is_ok());

        // Now, both the types are invalid.

        // WARNING! We can't commit here because this triggers domain_reload which will fail
        // due to incorrect syntax of the domain name! Run the migration in the same txn!
        // Trigger a schema reload.
        assert!(server_txn.reload_schema().is_ok());

        // We can't just re-run the migrate here because name takes it's definition from
        // in memory, and we can't re-run the initial memory gen. So we just fix it to match
        // what the migrate "would do".
        let me_syn = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_or!([
                    f_eq("attributename", PartialValue::new_iutf8("name")),
                    f_eq("attributename", PartialValue::new_iutf8("domain_name")),
                ])),
                ModifyList::new_purge_and_set(
                    "syntax",
                    Value::new_syntaxs("UTF8STRING_INAME").unwrap(),
                ),
            )
        };
        assert!(server_txn.modify(&me_syn).is_ok());

        // WARNING! We can't commit here because this triggers domain_reload which will fail
        // due to incorrect syntax of the domain name! Run the migration in the same txn!
        // Trigger a schema reload.
        assert!(server_txn.reload_schema().is_ok());

        // ++ Run the upgrade for X to Y
        assert!(server_txn.migrate_2_to_3().is_ok());

        assert!(server_txn.commit().is_ok());

        // Assert that it migrated and worked as expected.
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let domain = server_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("failed");
        // ++ assert all names are iname
        assert!(
            domain.get_ava_set("name").expect("no name?").syntax() == SyntaxType::Utf8StringIname
        );
        // ++ assert all domain/domain_name are iname
        assert!(
            domain
                .get_ava_set("domain_name")
                .expect("no domain_name?")
                .syntax()
                == SyntaxType::Utf8StringIname
        );
        assert!(server_txn.commit().is_ok());
    }
    */
}

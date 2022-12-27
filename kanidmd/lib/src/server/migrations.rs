
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
            .internal_migrate_or_create_str(JSON_SYSTEM_INFO_V1)
            .and_then(|_| self.internal_migrate_or_create_str(JSON_DOMAIN_INFO_V1))
            .and_then(|_| self.internal_migrate_or_create_str(JSON_SYSTEM_CONFIG_V1));
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
            JSON_ANONYMOUS_V1,
            JSON_ADMIN_V1,
            JSON_IDM_ADMIN_V1,
            JSON_IDM_ADMINS_V1,
            JSON_SYSTEM_ADMINS_V1,
        ];
        let res: Result<(), _> = admin_entries
            .iter()
            // Each item individually logs it's result
            .try_for_each(|e_str| self.internal_migrate_or_create_str(e_str));
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
            JSON_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1,
            JSON_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1,
            JSON_IDM_ACP_ACP_MANAGE_PRIV_V1,
            JSON_IDM_ACP_DOMAIN_ADMIN_PRIV_V1,
            JSON_IDM_ACP_SYSTEM_CONFIG_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_EXTEND_PRIV_V1,
            JSON_IDM_ACP_HP_PEOPLE_READ_PRIV_V1,
            JSON_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1,
            JSON_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1,
            JSON_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1,
            JSON_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1,
            JSON_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1,
            JSON_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1,
            JSON_IDM_ACP_OAUTH2_READ_PRIV_V1,
            JSON_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1,
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

        self.changed_schema.set(true);
        self.changed_acp.set(true);

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
        let server_txn = server.write(duration_from_epoch_now()).await;
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
}


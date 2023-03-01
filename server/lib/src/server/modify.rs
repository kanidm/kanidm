use std::sync::Arc;

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
        if !self.changed_schema {
            self.changed_schema = norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                        || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
                });
        }
        if !self.changed_acp {
            self.changed_acp = norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality("class", &PVCLASS_ACP))
        }
        if !self.changed_oauth2 {
            self.changed_oauth2 = norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS));
        }
        if !self.changed_domain {
            self.changed_domain = norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO));
        }

        self.changed_uuid.extend(
            norm_cand
                .iter()
                .map(|e| e.get_uuid())
                .chain(pre_candidates.iter().map(|e| e.get_uuid())),
        );

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
        &mut self,
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
    /// the modlist path. This allows more efficient batch transformations
    /// such as memberof, but at the expense that YOU must guarantee you
    /// uphold all other plugin and state rules that are important. You
    /// probably want modify instead.
    #[allow(clippy::needless_pass_by_value)]
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn internal_apply_writable(
        &mut self,
        candidate_tuples: Vec<(Arc<EntrySealedCommitted>, EntryInvalidCommitted)>,
    ) -> Result<(), OperationError> {
        if candidate_tuples.is_empty() {
            // No action needed.
            return Ok(());
        }

        let (pre_candidates, candidates): (
            Vec<Arc<EntrySealedCommitted>>,
            Vec<EntryInvalidCommitted>,
        ) = candidate_tuples.into_iter().unzip();

        /*
        let mut pre_candidates = Vec::with_capacity(candidate_tuples.len());
        let mut candidates = Vec::with_capacity(candidate_tuples.len());

        for (pre, post) in candidate_tuples.into_iter() {
            pre_candidates.push(pre);
            candidates.push(post);
        }
        */

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

        if !self.changed_schema {
            self.changed_schema = norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality("class", &PVCLASS_CLASSTYPE)
                        || e.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE)
                });
        }
        if !self.changed_acp {
            self.changed_acp = norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality("class", &PVCLASS_ACP));
        }
        if !self.changed_oauth2 {
            self.changed_oauth2 = norm_cand
                .iter()
                .any(|e| e.attribute_equality("class", &PVCLASS_OAUTH2_RS));
        }
        if !self.changed_domain {
            self.changed_domain = norm_cand
                .iter()
                .any(|e| e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO));
        }
        self.changed_uuid.extend(
            norm_cand
                .iter()
                .map(|e| e.get_uuid())
                .chain(pre_candidates.iter().map(|e| e.get_uuid())),
        );
        trace!(
            schema_reload = ?self.changed_schema,
            acp_reload = ?self.changed_acp,
            oauth2_reload = ?self.changed_oauth2,
            domain_reload = ?self.changed_domain,
        );

        trace!("Modify operation success");
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn internal_modify(
        &mut self,
        filter: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let m_valid = modlist
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let me = ModifyEvent::new_internal(f_valid, m_valid);
        self.modify(&me)
    }

    pub fn internal_modify_uuid(
        &mut self,
        target_uuid: Uuid,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let filter = filter!(f_eq("uuid", PartialValue::Uuid(target_uuid)));
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let m_valid = modlist
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let me = ModifyEvent::new_internal(f_valid, m_valid);
        self.modify(&me)
    }

    pub fn impersonate_modify_valid(
        &mut self,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        m_valid: ModifyList<ModifyValid>,
        event: &Identity,
    ) -> Result<(), OperationError> {
        let me = ModifyEvent::new_impersonate(event, f_valid, f_intent_valid, m_valid);
        self.modify(&me)
    }

    pub fn impersonate_modify(
        &mut self,
        filter: &Filter<FilterInvalid>,
        filter_intent: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
        event: &Identity,
    ) -> Result<(), OperationError> {
        let f_valid = filter.validate(self.get_schema()).map_err(|e| {
            admin_error!("filter Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let f_intent_valid = filter_intent.validate(self.get_schema()).map_err(|e| {
            admin_error!("f_intent Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            admin_error!("modlist Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        self.impersonate_modify_valid(f_valid, f_intent_valid, m_valid, event)
    }

    pub fn impersonate_modify_gen_event(
        &mut self,
        filter: &Filter<FilterInvalid>,
        filter_intent: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
        event: &Identity,
    ) -> Result<ModifyEvent, OperationError> {
        let f_valid = filter.validate(self.get_schema()).map_err(|e| {
            admin_error!("filter Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let f_intent_valid = filter_intent.validate(self.get_schema()).map_err(|e| {
            admin_error!("f_intent Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            admin_error!("modlist Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        Ok(ModifyEvent::new_impersonate(
            event,
            f_valid,
            f_intent_valid,
            m_valid,
        ))
    }
}

#[cfg(test)]
mod tests {
    use kanidm_lib_crypto::CryptoPolicy;
    use crate::credential::Credential;
    use crate::prelude::*;

    #[qs_test]
    async fn test_modify(server: &QueryServer) {
        // Create an object
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson2")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63932"))
            ),
            ("description", Value::new_utf8s("testperson2")),
            ("displayname", Value::new_utf8s("testperson2"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Empty Modlist (filter is valid)
        let me_emp = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_pres("class")),
                ModifyList::new_list(vec![]),
            )
        };
        assert!(server_txn.modify(&me_emp) == Err(OperationError::EmptyRequest));

        // Mod changes no objects
        let me_nochg = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter!(f_eq("name", PartialValue::new_iname("flarbalgarble"))),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("description"),
                    Value::from("anusaosu"),
                )]),
            )
        };
        assert!(server_txn.modify(&me_nochg) == Err(OperationError::NoMatchingEntries));

        // Filter is invalid to schema - to check this due to changes in the way events are
        // handled, we put this via the internal modify function to get the modlist
        // checked for us. Normal server operation doesn't allow weird bypasses like
        // this.
        let r_inv_1 = server_txn.internal_modify(
            &filter!(f_eq("tnanuanou", PartialValue::new_iname("Flarbalgarble"))),
            &ModifyList::new_list(vec![Modify::Present(
                AttrString::from("description"),
                Value::from("anusaosu"),
            )]),
        );
        assert!(
            r_inv_1
                == Err(OperationError::SchemaViolation(
                    SchemaError::InvalidAttribute("tnanuanou".to_string())
                ))
        );

        // Mod is invalid to schema
        let me_inv_m = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_pres("class")),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("htnaonu"),
                    Value::from("anusaosu"),
                )]),
            )
        };
        assert!(
            server_txn.modify(&me_inv_m)
                == Err(OperationError::SchemaViolation(
                    SchemaError::InvalidAttribute("htnaonu".to_string())
                ))
        );

        // Mod single object
        let me_sin = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("testperson2"))),
                ModifyList::new_list(vec![
                    Modify::Purged(AttrString::from("description")),
                    Modify::Present(AttrString::from("description"), Value::from("anusaosu")),
                ]),
            )
        };
        assert!(server_txn.modify(&me_sin).is_ok());

        // Mod multiple object
        let me_mult = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_or!([
                    f_eq("name", PartialValue::new_iname("testperson1")),
                    f_eq("name", PartialValue::new_iname("testperson2")),
                ])),
                ModifyList::new_list(vec![
                    Modify::Purged(AttrString::from("description")),
                    Modify::Present(AttrString::from("description"), Value::from("anusaosu")),
                ]),
            )
        };
        assert!(server_txn.modify(&me_mult).is_ok());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_modify_assert(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let t_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();

        assert!(server_txn
            .internal_create(vec![entry_init!(
                ("class", Value::new_class("object")),
                ("uuid", Value::Uuid(t_uuid))
            ),])
            .is_ok());

        // This assertion will FAIL
        assert!(matches!(
            server_txn.internal_modify_uuid(
                t_uuid,
                &ModifyList::new_list(vec![
                    m_assert("uuid", &PartialValue::Uuid(r_uuid)),
                    m_pres("description", &Value::Utf8("test".into()))
                ])
            ),
            Err(OperationError::ModifyAssertionFailed)
        ));

        // This assertion will PASS
        assert!(server_txn
            .internal_modify_uuid(
                t_uuid,
                &ModifyList::new_list(vec![
                    m_assert("uuid", &PartialValue::Uuid(t_uuid)),
                    m_pres("description", &Value::Utf8("test".into()))
                ])
            )
            .is_ok());
    }

    #[qs_test]
    async fn test_modify_invalid_class(server: &QueryServer) {
        // Test modifying an entry and adding an extra class, that would cause the entry
        // to no longer conform to schema.
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );

        let ce = CreateEvent::new_internal(vec![e1]);

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Add class but no values
        let me_sin = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("class"),
                    Value::new_class("system_info"),
                )]),
            )
        };
        assert!(server_txn.modify(&me_sin).is_err());

        // Add multivalue where not valid
        let me_sin = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("name"),
                    Value::new_iname("testpersonx"),
                )]),
            )
        };
        assert!(server_txn.modify(&me_sin).is_err());

        // add class and valid values?
        let me_sin = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                ModifyList::new_list(vec![
                    Modify::Present(AttrString::from("class"), Value::new_class("system_info")),
                    // Modify::Present("domain".to_string(), Value::new_iutf8("domain.name")),
                    Modify::Present(AttrString::from("version"), Value::new_uint32(1)),
                ]),
            )
        };
        assert!(server_txn.modify(&me_sin).is_ok());

        // Replace a value
        let me_sin = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                ModifyList::new_list(vec![
                    Modify::Purged(AttrString::from("name")),
                    Modify::Present(AttrString::from("name"), Value::new_iname("testpersonx")),
                ]),
            )
        };
        assert!(server_txn.modify(&me_sin).is_ok());
    }

    #[qs_test]
    async fn test_modify_password_only(server: &QueryServer) {
        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Add the entry. Today we have no syntax to take simple str to a credential
        // but honestly, that's probably okay :)
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Build the credential.
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        let v_cred = Value::new_credential("primary", cred);
        assert!(v_cred.validate());

        // now modify and provide a primary credential.
        let me_inv_m = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("primary_credential"),
                    v_cred,
                )]),
            )
        };
        // go!
        assert!(server_txn.modify(&me_inv_m).is_ok());

        // assert it exists and the password checks out
        let test_ent = server_txn
            .internal_search_uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            .expect("failed");
        // get the primary ava
        let cred_ref = test_ent
            .get_ava_single_credential("primary_credential")
            .expect("Failed");
        // do a pw check.
        assert!(cred_ref.verify_password("test_password").unwrap());
    }
}

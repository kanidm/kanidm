use crate::prelude::*;
use crate::server::batch_modify::{BatchModifyEvent, ModSetValid};
use kanidm_proto::scim_v1::client::ScimEntryPutGeneric;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ScimEntryPutEvent {
    /// The identity performing the change.
    pub ident: Identity,

    // future - etags to detect version changes.
    /// The target entry that will be changed
    pub target: Uuid,
    /// Update an attribute to contain the following value state.
    /// If the attribute is None, it is removed.
    pub attrs: BTreeMap<Attribute, Option<ValueSet>>,
}

impl ScimEntryPutEvent {
    pub fn try_from(
        ident: Identity,
        entry: ScimEntryPutGeneric,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let target = entry.id;

        let attrs = entry
            .attrs
            .into_iter()
            .map(|(attr, json_value)| {
                qs.resolve_scim_json_put(&attr, json_value)
                    .map(|kani_value| (attr, kani_value))
            })
            .collect::<Result<_, _>>()?;

        Ok(ScimEntryPutEvent {
            ident,
            target,
            attrs,
        })
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    /// SCIM PUT is the handler where a single entry is updated. In a SCIM PUT request
    /// the request defines the state of an attribute in entirety for the update. This
    /// means if the caller wants to add one email address, they must PUT all existing
    /// addresses in addition to the addition of the new one.
    pub fn scim_put(
        &mut self,
        scim_entry_put: ScimEntryPutEvent,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let ScimEntryPutEvent {
            ident,
            target,
            attrs,
        } = scim_entry_put;

        // This function transforms the put event into a modify event.
        let mods_invalid: ModifyList<ModifyInvalid> = attrs.into();

        let mods_valid = mods_invalid
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let mut modset = ModSetValid::default();

        modset.insert(target, mods_valid);

        let modify_event = BatchModifyEvent {
            ident: ident.clone(),
            modset,
        };

        // dispatch to batch modify
        self.batch_modify(&modify_event)?;

        // Now get the entry. We handle a lot of the errors here nicely,
        // but if we got to this point, they really can't happen.
        let filter_intent = filter!(f_and!([f_eq(Attribute::Uuid, PartialValue::Uuid(target))]));

        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let f_valid = f_intent_valid.clone().into_ignore_hidden();

        let se = SearchEvent {
            ident,
            filter: f_valid,
            filter_orig: f_intent_valid,
            // Return all attributes, even ones we didn't affect
            attrs: None,
        };

        let mut vs = self.search_ext(&se)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => entry.to_scim_kanidm(self),
            _ => {
                if vs.is_empty() {
                    Err(OperationError::NoMatchingEntries)
                } else {
                    // Multiple entries matched, should not be possible!
                    Err(OperationError::UniqueConstraintViolation)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScimEntryPutEvent;
    use crate::prelude::*;
    use kanidm_proto::scim_v1::client::ScimEntryPutKanidm;
    use kanidm_proto::scim_v1::server::ScimReference;

    #[qs_test]
    async fn scim_put_basic(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let idm_admin_entry = server_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();

        let idm_admin_ident = Identity::from_impersonate_entry_readwrite(idm_admin_entry);

        // Make an entry.
        let group_uuid = Uuid::new_v4();

        // We need to extra entries that well serve as members to our group.
        let extra1_uuid = Uuid::new_v4();
        let extra2_uuid = Uuid::new_v4();
        let extra3_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(group_uuid))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("extra_1")),
            (Attribute::Uuid, Value::Uuid(extra1_uuid))
        );

        let e3 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("extra_2")),
            (Attribute::Uuid, Value::Uuid(extra2_uuid))
        );

        let e4 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("extra_3")),
            (Attribute::Uuid, Value::Uuid(extra3_uuid))
        );

        assert!(server_txn.internal_create(vec![e1, e2, e3, e4]).is_ok());

        // Set an attr
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(Attribute::Description, Some("Group Description".into()))].into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let desc = updated_entry.attrs.get(&Attribute::Description).unwrap();

        match desc {
            ScimValueKanidm::String(gdesc) if gdesc == "Group Description" => {}
            _ => assert!(false),
        };

        // null removes attr
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(Attribute::Description, None)].into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        assert!(updated_entry.attrs.get(&Attribute::Description).is_none());

        // set one
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::EntryReferences(vec![ScimReference {
                    uuid: extra1_uuid,
                    // Doesn't matter what this is, because there is a UUID, it's ignored
                    value: String::default(),
                }])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        trace!(?members);

        match members {
            ScimValueKanidm::EntryReferences(member_set) if member_set.len() == 1 => {
                assert!(member_set.contains(&ScimReference {
                    uuid: extra1_uuid,
                    value: "extra_1@example.com".to_string(),
                }));
            }
            _ => assert!(false),
        };

        // set many
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::EntryReferences(vec![
                    ScimReference {
                        uuid: extra1_uuid,
                        value: String::default(),
                    },
                    ScimReference {
                        uuid: extra2_uuid,
                        value: String::default(),
                    },
                    ScimReference {
                        uuid: extra3_uuid,
                        value: String::default(),
                    },
                ])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        trace!(?members);

        match members {
            ScimValueKanidm::EntryReferences(member_set) if member_set.len() == 3 => {
                assert!(member_set.contains(&ScimReference {
                    uuid: extra1_uuid,
                    value: "extra_1@example.com".to_string(),
                }));
                assert!(member_set.contains(&ScimReference {
                    uuid: extra2_uuid,
                    value: "extra_2@example.com".to_string(),
                }));
                assert!(member_set.contains(&ScimReference {
                    uuid: extra3_uuid,
                    value: "extra_3@example.com".to_string(),
                }));
            }
            _ => assert!(false),
        };

        // set many with a removal
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::EntryReferences(vec![
                    ScimReference {
                        uuid: extra1_uuid,
                        value: String::default(),
                    },
                    ScimReference {
                        uuid: extra3_uuid,
                        value: String::default(),
                    },
                ])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        trace!(?members);

        match members {
            ScimValueKanidm::EntryReferences(member_set) if member_set.len() == 2 => {
                assert!(member_set.contains(&ScimReference {
                    uuid: extra1_uuid,
                    value: "extra_1@example.com".to_string(),
                }));
                assert!(member_set.contains(&ScimReference {
                    uuid: extra3_uuid,
                    value: "extra_3@example.com".to_string(),
                }));
                // Member 2 is gone
                assert!(!member_set.contains(&ScimReference {
                    uuid: extra2_uuid,
                    value: "extra_2@example.com".to_string(),
                }));
            }
            _ => assert!(false),
        };

        // empty set removes attr
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(Attribute::Member, None)].into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        assert!(updated_entry.attrs.get(&Attribute::Member).is_none());
    }
}

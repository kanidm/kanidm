use crate::prelude::*;
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
        _scim_entry_put: ScimEntryPutEvent,
    ) -> Result<ScimEntryKanidm, OperationError> {
        // There are two options here
        // 1. We make scim put it's own event type and copy what we do in modify to achieve it.
        // 2. We make scim put transform into a modify event and submit that instead.

        // I think we do 2. because there is enough in the modify that is different
        // such as schema checking and transform that we have to account for, and then
        // we can directly call set_ava on the entry.

        // Need to transform ScimPut attrs from json Value ->

        // Should this be earlier in the process?

        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::ScimEntryPutEvent;
    use crate::prelude::*;
    use kanidm_proto::scim_v1::client::ScimEntryPutKanidm;

    #[qs_test]
    async fn scim_put_basic(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let internal_ident = Identity::from_internal();
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
            ScimEntryPutEvent::try_from(internal_ident.clone(), put_generic, &mut server_txn)
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
            ScimEntryPutEvent::try_from(internal_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        assert!(updated_entry.attrs.get(&Attribute::Description).is_none());

        // set one
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::ArrayUuid(vec![extra1_uuid])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(internal_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        match members {
            ScimValueKanidm::ArrayUuid(member_set) if member_set.len() == 1 => {
                assert!(member_set.contains(&extra1_uuid));
            }
            _ => assert!(false),
        };

        // set many
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::ArrayUuid(vec![
                    extra1_uuid,
                    extra2_uuid,
                    extra3_uuid,
                ])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(internal_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        match members {
            ScimValueKanidm::ArrayUuid(member_set) if member_set.len() == 3 => {
                assert!(member_set.contains(&extra1_uuid));
                assert!(member_set.contains(&extra2_uuid));
                assert!(member_set.contains(&extra3_uuid));
            }
            _ => assert!(false),
        };

        // set many with a removal
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::ArrayUuid(vec![extra1_uuid, extra3_uuid])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(internal_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        match members {
            ScimValueKanidm::ArrayUuid(member_set) if member_set.len() == 2 => {
                assert!(member_set.contains(&extra1_uuid));
                assert!(member_set.contains(&extra3_uuid));
            }
            _ => assert!(false),
        };

        // empty set removes attr
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(Attribute::Member, Some(ScimValueKanidm::Uuid(extra1_uuid)))].into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(internal_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        assert!(updated_entry.attrs.get(&Attribute::Member).is_none());
    }
}

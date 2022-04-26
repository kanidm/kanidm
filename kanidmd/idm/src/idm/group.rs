use crate::entry::{Entry, EntryCommitted, EntryReduced, EntrySealed};
use crate::prelude::*;
use crate::value::PartialValue;
use kanidm_proto::v1::Group as ProtoGroup;
use kanidm_proto::v1::OperationError;

use uuid::Uuid;

lazy_static! {
    static ref PVCLASS_GROUP: PartialValue = PartialValue::new_class("group");
}

#[derive(Debug, Clone)]
pub struct Group {
    name: String,
    uuid: Uuid,
    // We'll probably add policy and claims later to this
}

macro_rules! try_from_account_e {
    ($value:expr, $qs:expr) => {{
        let name = $value
            .get_ava_single_str("name")
            .map(str::to_string)
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;

        let uuid = *$value.get_uuid();

        let upg = Group { name, uuid };

        let mut groups: Vec<Group> = match $value.get_ava_as_refuuid("memberof") {
            Some(riter) => {
                // given a list of uuid, make a filter: even if this is empty, the be will
                // just give and empty result set.
                let f = filter!(f_or(
                    riter
                        .map(|u| f_eq("uuid", PartialValue::new_uuidr(u)))
                        .collect()
                ));
                let ges: Vec<_> = $qs.internal_search(f).map_err(|e| {
                    admin_error!(?e, "internal search failed");
                    e
                })?;
                // Now convert the group entries to groups.
                let groups: Result<Vec<_>, _> = ges
                    .iter()
                    .map(|e| Group::try_from_entry(e.as_ref()))
                    .collect();
                groups.map_err(|e| {
                    admin_error!(?e, "failed to transform group entries to groups");
                    e
                })?
            }
            None => {
                // No memberof, no groups!
                vec![]
            }
        };
        groups.push(upg);
        Ok(groups)
    }};
}

impl Group {
    pub fn try_from_account_entry_red_ro(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_e!(value, qs)
    }

    pub fn try_from_account_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_e!(value, qs)
    }

    pub fn try_from_account_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_e!(value, qs)
    }

    pub fn try_from_entry(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality("class", &PVCLASS_GROUP) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: group".to_string(),
            ));
        }

        // Now extract our needed attributes
        let name = value
            .get_ava_single_str("name")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;

        let uuid = *value.get_uuid();

        Ok(Group { name, uuid })
    }

    pub fn to_proto(&self) -> ProtoGroup {
        ProtoGroup {
            name: self.name.clone(),
            uuid: self.uuid.to_hyphenated_ref().to_string(),
        }
    }
}

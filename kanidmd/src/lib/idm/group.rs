use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntrySealed};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
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
    ($au:expr, $value:expr, $qs:expr) => {{
        let groups: Vec<Group> = match $value.get_ava_reference_uuid("memberof") {
            Some(l) => {
                // given a list of uuid, make a filter: even if this is empty, the be will
                // just give and empty result set.
                let f = filter!(f_or(
                    l.into_iter()
                        .map(|u| f_eq("uuid", PartialValue::new_uuidr(u)))
                        .collect()
                ));
                let ges: Vec<_> = $qs.internal_search($au, f).map_err(|e| {
                    // log
                    e
                })?;
                // Now convert the group entries to groups.
                let groups: Result<Vec<_>, _> =
                    ges.into_iter().map(Group::try_from_entry).collect();
                groups.map_err(|e| {
                    // log
                    e
                })?
            }
            None => {
                // No memberof, no groups!
                vec![]
            }
        };
        Ok(groups)
    }};
}

impl Group {
    pub fn try_from_account_entry_red_ro(
        au: &mut AuditScope,
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_e!(au, value, qs)
    }

    pub fn try_from_account_entry_ro(
        au: &mut AuditScope,
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_e!(au, value, qs)
    }

    pub fn try_from_account_entry_rw(
        au: &mut AuditScope,
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_e!(au, value, qs)
    }

    pub fn try_from_entry(
        value: Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", &PVCLASS_GROUP) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: group".to_string(),
            ));
        }

        // Now extract our needed attributes
        let name = value.get_ava_single_string("name").ok_or_else(|| {
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

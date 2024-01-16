use std::collections::BTreeSet;

use kanidm_proto::v1::UiHint;
use kanidm_proto::v1::{Group as ProtoGroup, OperationError};
use uuid::Uuid;

use super::accountpolicy::{AccountPolicy, ResolvedAccountPolicy};
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntrySealed};
use crate::prelude::*;
use crate::value::PartialValue;

#[derive(Debug, Clone)]
pub struct Group {
    spn: String,
    uuid: Uuid,
    // We'll probably add policy and claims later to this
    pub ui_hints: BTreeSet<UiHint>,
}

macro_rules! entry_groups {
    ($value:expr, $qs:expr) => {{
        match $value.get_ava_as_refuuid(Attribute::MemberOf) {
            Some(riter) => {
                // given a list of uuid, make a filter: even if this is empty, the be will
                // just give and empty result set.
                let f = filter!(f_or(
                    riter
                        .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                        .collect()
                ));
                $qs.internal_search(f).map_err(|e| {
                    admin_error!(?e, "internal search failed");
                    e
                })?
            }
            None => {
                // No memberof, no groups!
                vec![]
            }
        }
    }};
}

macro_rules! upg_from_account_e {
    ($value:expr, $groups:expr) => {{
        // Setup the user private group
        let spn = $value.get_ava_single_proto_string(Attribute::Spn).ok_or(
            OperationError::InvalidAccountState(format!("Missing attribute: {}", Attribute::Spn)),
        )?;

        let uuid = $value.get_uuid();

        // We could allow ui hints on the user direct in the future?
        let ui_hints = BTreeSet::default();

        let upg = Group {
            spn,
            uuid,
            ui_hints,
        };

        // Now convert the group entries to groups.
        let groups: Result<Vec<_>, _> = $groups
            .iter()
            .map(|e| Group::try_from_entry(e.as_ref()))
            .chain(std::iter::once(Ok(upg)))
            .collect();

        groups.map_err(|e| {
            error!(?e, "failed to transform group entries to groups");
            e
        })
    }};
}

impl Group {
    pub(crate) fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn try_from_account_entry_reduced<'a, TXN>(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Self>, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let groups = entry_groups!(value, qs);
        upg_from_account_e!(value, groups)
    }

    pub fn try_from_account_entry<'a, TXN>(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Self>, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let groups = entry_groups!(value, qs);
        upg_from_account_e!(value, groups)
    }

    pub(crate) fn try_from_account_entry_with_policy<'b, 'a, TXN>(
        value: &'b Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<(Vec<Self>, ResolvedAccountPolicy), OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let groups = entry_groups!(value, qs);
        // Get the account policy here.

        let rap = ResolvedAccountPolicy::fold_from(groups.iter().filter_map(|entry| {
            let acc_pol: Option<AccountPolicy> = entry.as_ref().into();
            acc_pol
        }));

        let r_groups = upg_from_account_e!(value, groups)?;

        Ok((r_groups, rap))
    }

    pub fn try_from_entry(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: group".to_string(),
            ));
        }

        // Now extract our needed attributes
        /*
        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;
        */
        let spn = value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: spn".to_string())
            })?;

        let uuid = value.get_uuid();

        let ui_hints = value
            .get_ava_uihint(Attribute::GrantUiHint)
            .cloned()
            .unwrap_or_default();

        Ok(Group {
            spn,
            uuid,
            ui_hints,
        })
    }

    pub fn to_proto(&self) -> ProtoGroup {
        ProtoGroup {
            spn: self.spn.clone(),
            uuid: self.uuid.as_hyphenated().to_string(),
        }
    }
}

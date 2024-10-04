use std::collections::BTreeSet;

use kanidm_proto::internal::{Group as ProtoGroup, UiHint};
use kanidm_proto::v1::UnixGroupToken;
use uuid::Uuid;

use crate::entry::{Committed, Entry, EntryCommitted, EntrySealed, GetUuid};
use crate::prelude::*;
use crate::value::PartialValue;

use super::accountpolicy::{AccountPolicy, ResolvedAccountPolicy};

// I hate that rust is forcing this to be public
pub trait GroupType {}

#[derive(Debug, Clone)]
pub(crate) struct Unix {
    name: String,
    gidnumber: u32,
}

impl GroupType for Unix {}

impl GroupType for () {}

#[derive(Debug, Clone)]
pub struct Group<T>
where
    T: GroupType,
{
    inner: T,
    spn: String,
    uuid: Uuid,
    // We'll probably add policy and claims later to this
    ui_hints: BTreeSet<UiHint>,
}

macro_rules! try_from_entry {
    ($value:expr, $inner:expr) => {{
        if !$value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
            return Err(OperationError::MissingAttribute(Attribute::Group));
        }

        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Spn))?;

        let uuid = $value.get_uuid();

        let ui_hints = $value
            .get_ava_uihint(Attribute::GrantUiHint)
            .cloned()
            .unwrap_or_default();

        Ok(Self {
            inner: $inner,
            spn,
            uuid,
            ui_hints,
        })
    }};
}

impl<T: GroupType> Group<T> {
    pub fn spn(&self) -> &String {
        &self.spn
    }
    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }
    pub fn ui_hints(&self) -> &BTreeSet<UiHint> {
        &self.ui_hints
    }
    pub fn to_proto(&self) -> ProtoGroup {
        ProtoGroup {
            spn: self.spn.clone(),
            uuid: self.uuid.as_hyphenated().to_string(),
        }
    }
}

macro_rules! try_from_account {
    ($value:expr, $qs:expr) => {{
        let Some(iter) = $value.get_ava_as_refuuid(Attribute::MemberOf) else {
            return Ok(vec![]);
        };

        // given a list of uuid, make a filter: even if this is empty, the be will
        // just give and empty result set.
        let f = filter!(f_or(
            iter.map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                .collect()
        ));

        let entries = $qs.internal_search(f).map_err(|e| {
            admin_error!(?e, "internal search failed");
            e
        })?;

        Ok(entries
            .iter()
            .map(|entry| Self::try_from_entry(&entry))
            .filter_map(|v| v.ok())
            .collect())
    }};
}

impl Group<()> {
    pub fn try_from_account<'a, TXN>(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<()>>, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let user_group = Group::<()>::try_from_entry(value)?;
        Ok(Self::try_from_account_reduced(value, qs)?
            .into_iter()
            .chain(std::iter::once(user_group))
            .collect())
    }

    pub fn try_from_account_reduced<'a, E, TXN>(
        value: &Entry<E, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<()>>, OperationError>
    where
        E: Committed,
        TXN: QueryServerTransaction<'a>,
    {
        try_from_account!(value, qs)
    }

    pub fn try_from_entry<E>(value: &Entry<E, EntryCommitted>) -> Result<Self, OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        try_from_entry!(value, ())
    }
}

impl Group<Unix> {
    pub fn try_from_account<'a, TXN>(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<Unix>>, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let user_group = Group::<Unix>::try_from_entry(value)?;
        Ok(Self::try_from_account_reduced(value, qs)?
            .into_iter()
            .chain(std::iter::once(user_group))
            .collect())
    }

    pub fn try_from_account_reduced<'a, E, TXN>(
        value: &Entry<E, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<Unix>>, OperationError>
    where
        E: Committed,
        TXN: QueryServerTransaction<'a>,
    {
        try_from_account!(value, qs)
    }

    pub fn try_from_entry<E>(value: &Entry<E, EntryCommitted>) -> Result<Self, OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        if !value.attribute_equality(Attribute::Class, &EntryClass::PosixGroup.into()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_POSIX_GROUP.into()));
        }

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

        let gidnumber = value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

        try_from_entry!(value, Unix { name, gidnumber })
    }

    pub(crate) fn to_unixgrouptoken(&self) -> UnixGroupToken {
        UnixGroupToken {
            name: self.inner.name.clone(),
            spn: self.spn.clone(),
            uuid: self.uuid,
            gidnumber: self.inner.gidnumber,
        }
    }
}

pub(crate) fn load_account_policy<'a, T>(
    value: &Entry<EntrySealed, EntryCommitted>,
    qs: &mut T,
) -> Result<ResolvedAccountPolicy, OperationError>
where
    T: QueryServerTransaction<'a>,
{
    let iter = match value.get_ava_as_refuuid(Attribute::MemberOf) {
        Some(v) => v,
        None => Box::new(Vec::<Uuid>::new().into_iter()),
    };

    // given a list of uuid, make a filter: even if this is empty, the be will
    // just give and empty result set.
    let f = filter!(f_or(
        iter.map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
            .collect()
    ));

    let entries = qs.internal_search(f).map_err(|e| {
        admin_error!(?e, "internal search failed");
        e
    })?;

    Ok(ResolvedAccountPolicy::fold_from(entries.iter().filter_map(
        |entry| {
            let acc_pol: Option<AccountPolicy> = entry.as_ref().into();
            acc_pol
        },
    )))
}

// trait LoadGroupsFromAccount<T>
// where
//     T: GroupType,
// {
//     fn try_from_account<'a, TXN>(
//         value: &Entry<EntrySealed, EntryCommitted>,
//         qs: &mut TXN,
//     ) -> Result<Vec<Group<T>>, OperationError>
//     where
//         TXN: QueryServerTransaction<'a>,
//     {
//         // Setup the user private group
//         let spn = value
//             .get_ava_single_proto_string(Attribute::Spn)
//             .ok_or(OperationError::MissingAttribute(Attribute::Spn))?;

//         let uuid = value.get_uuid();

//         // We could allow ui hints on the user direct in the future?
//         let ui_hints = BTreeSet::default();

//         Self::try_from_account_reduced()?.extend(Group::<()> {
//             inner: (),
//             spn: spn.clone(),
//             uuid: uuid.clone(),
//             ui_hints,
//         })
//     }

//     fn try_from_account_reduced<'a, E, TXN>(
//         value: &Entry<E, EntryCommitted>,
//         qs: &mut TXN,
//     ) -> Result<Vec<Group<T>>, OperationError>
//     where
//         E: Committed,
//         TXN: QueryServerTransaction<'a>,
//     {
//         let Some(iter) = value.get_ava_as_refuuid(Attribute::MemberOf) else {
//             return Ok(vec![]);
//         };

//         // given a list of uuid, make a filter: even if this is empty, the be will
//         // just give and empty result set.
//         let f = filter!(f_or(
//             iter
//                 .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
//                 .collect()
//         ));

//         let entries = qs.internal_search(f).map_err(|e| {
//             admin_error!(?e, "internal search failed");
//             e
//         })?;

//         Ok(entries.iter().map(|entry| Group::<T>::try_from_entry).filter_map(|v| v.ok()).collect())
//     }
// }

// impl LoadGroupsFromAccount<()> for () {}

// impl LoadGroupsFromAccount<Unix> for Unix {}

// macro_rules! entry_groups {
//     ($value:expr, $qs:expr) => {{
//         match $value.get_ava_as_refuuid(Attribute::MemberOf) {
//             Some(riter) => {
//                 // given a list of uuid, make a filter: even if this is empty, the be will
//                 // just give and empty result set.
//                 let f = filter!(f_or(
//                     riter
//                         .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
//                         .collect()
//                 ));
//                 $qs.internal_search(f).map_err(|e| {
//                     admin_error!(?e, "internal search failed");
//                     e
//                 })?
//             }
//             None => {
//                 // No memberof, no groups!
//                 vec![]
//             }
//         }
//     }};
// }

// macro_rules! load_all_groups_from_iter {
//     ($value:expr, $group_iter:expr) => {{
//         let mut groups: Vec<Group> = vec![];
//         let mut unix_groups: Vec<UnixGroup> = vec![];

//         let is_unix_account = $value.attribute_equality(
//             Attribute::Class,
//             &EntryClass::PosixAccount.to_partialvalue(),
//         );

//         // Setup the user private group
//         let spn = $value
//             .get_ava_single_proto_string(Attribute::Spn)
//             .ok_or(OperationError::MissingAttribute(Attribute::Spn))?;

//         let uuid = $value.get_uuid();

//         // We could allow ui hints on the user direct in the future?
//         let ui_hints = BTreeSet::default();

//         groups.push(Group {
//             spn: spn.clone(),
//             uuid: uuid.clone(),
//             ui_hints,
//         });

//         if is_unix_account {
//             let name = $value
//                 .get_ava_single_proto_string(Attribute::Name)
//                 .ok_or(OperationError::MissingAttribute(Attribute::Name))?;

//             let gidnumber = $value
//                 .get_ava_single_uint32(Attribute::GidNumber)
//                 .ok_or(OperationError::MissingAttribute(Attribute::GidNumber))?;

//             unix_groups.push(UnixGroup {
//                 name,
//                 spn,
//                 gidnumber,
//                 uuid,
//             });
//         }

//         for group_entry in $group_iter {
//             let group = Group::try_from_entry(group_entry.as_ref())?;
//             groups.push(group);

//             if is_unix_account
//                 && group_entry
//                     .attribute_equality(Attribute::Class, &EntryClass::PosixGroup.to_partialvalue())
//             {
//                 let unix_group = UnixGroup::try_from_entry(group_entry.as_ref())?;
//                 unix_groups.push(unix_group);
//             }
//         }

//         (groups, unix_groups)
//     }};
// }

// pub(crate) fn load_all_groups_from_account_entry<'a, T>(
//     value: &Entry<EntrySealed, EntryCommitted>,
//     qs: &mut T,
// ) -> Result<(Vec<Group>, Vec<UnixGroup>), OperationError>
// where
//     T: QueryServerTransaction<'a>,
// {
//     let group_iter = entry_groups!(value, qs);
//     Ok(load_all_groups_from_iter!(value, group_iter))
// }

// pub(crate) fn load_all_groups_from_account_entry_with_policy<'a, T>(
//     value: &Entry<EntrySealed, EntryCommitted>,
//     qs: &mut T,
// ) -> Result<((Vec<Group>, Vec<UnixGroup>), ResolvedAccountPolicy), OperationError>
// where
//     T: QueryServerTransaction<'a>,
// {
//     let group_iter = entry_groups!(value, qs);

//     let rap = ResolvedAccountPolicy::fold_from(group_iter.iter().filter_map(|entry| {
//         let acc_pol: Option<AccountPolicy> = entry.as_ref().into();
//         acc_pol
//     }));

//     Ok((load_all_groups_from_iter!(value, group_iter), rap))
// }

// pub(crate) fn load_all_groups_from_account_entry_reduced<'a, T>(
//     value: &Entry<EntryReduced, EntryCommitted>,
//     qs: &mut T,
// ) -> Result<(Vec<Group>, Vec<UnixGroup>), OperationError>
// where
//     T: QueryServerTransaction<'a>,
// {
//     let group_iter = entry_groups!(value, qs);
//     Ok(load_all_groups_from_iter!(value, group_iter))
// }

// macro_rules! upg_from_account_e {
//     ($value:expr, $groups:expr) => {{
//         // Setup the user private group
//         let spn = $value
//             .get_ava_single_proto_string(Attribute::Spn)
//             .ok_or(OperationError::MissingAttribute(Attribute::Spn))?;

//         let uuid = $value.get_uuid();

//         // We could allow ui hints on the user direct in the future?
//         let ui_hints = BTreeSet::default();

//         let upg = Group {
//             spn,
//             uuid,
//             ui_hints,
//         };

//         // Now convert the group entries to groups.
//         let groups: Result<Vec<_>, _> = $groups
//             .iter()
//             .map(|e| Group::try_from_entry(e.as_ref()))
//             .chain(std::iter::once(Ok(upg)))
//             .collect();

//         groups.map_err(|e| {
//             error!(?e, "failed to transform group entries to groups");
//             e
//         })
//     }};
// }

// impl Group {
//     pub(crate) fn uuid(&self) -> Uuid {
//         self.uuid
//     }

//     pub fn try_from_account_entry_reduced<'a, TXN>(
//         value: &Entry<EntryReduced, EntryCommitted>,
//         qs: &mut TXN,
//     ) -> Result<Vec<Self>, OperationError>
//     where
//         TXN: QueryServerTransaction<'a>,
//     {
//         let groups = entry_groups!(value, qs);
//         upg_from_account_e!(value, groups)
//     }

//     pub fn try_from_account_entry<'a, TXN>(
//         value: &Entry<EntrySealed, EntryCommitted>,
//         qs: &mut TXN,
//     ) -> Result<Vec<Self>, OperationError>
//     where
//         TXN: QueryServerTransaction<'a>,
//     {
//         let groups = entry_groups!(value, qs);
//         upg_from_account_e!(value, groups)
//     }

//     pub fn try_from_entry(
//         value: &Entry<EntrySealed, EntryCommitted>,
//     ) -> Result<Self, OperationError> {
//         if !value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
//             return Err(OperationError::MissingAttribute(Attribute::Group));
//         }

//         // Now extract our needed attributes
//         /*
//         let name = value
//             .get_ava_single_iname(Attribute::Name)
//             .map(|s| s.to_string())
//             .ok_or_else(|| {
//                 OperationError::MissingAttribute(Attribute::Name)
//             })?;
//         */
//         let spn = value
//             .get_ava_single_proto_string(Attribute::Spn)
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::Spn))?;

//         let uuid = value.get_uuid();

//         let ui_hints = value
//             .get_ava_uihint(Attribute::GrantUiHint)
//             .cloned()
//             .unwrap_or_default();

//         Ok(Group {
//             spn,
//             uuid,
//             ui_hints,
//         })
//     }

//     pub fn to_proto(&self) -> ProtoGroup {
//         ProtoGroup {
//             spn: self.spn.clone(),
//             uuid: self.uuid.as_hyphenated().to_string(),
//         }
//     }
// }

// #[derive(Debug, Clone)]
// pub(crate) struct UnixGroup {
//     pub name: String,
//     pub spn: String,
//     pub gidnumber: u32,
//     pub uuid: Uuid,
// }

// macro_rules! try_from_group_e {
//     ($value:expr) => {{
//         // We could be looking at a user for their UPG, OR a true group.

//         if !(($value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue())
//             && $value.attribute_equality(
//                 Attribute::Class,
//                 &EntryClass::PosixAccount.to_partialvalue(),
//             ))
//             || ($value.attribute_equality(Attribute::Class, &EntryClass::Group.to_partialvalue())
//                 && $value.attribute_equality(
//                     Attribute::Class,
//                     &EntryClass::PosixGroup.to_partialvalue(),
//                 )))
//         {
//             return Err(OperationError::InvalidAccountState(format!(
//                 "Missing {}: {} && {} OR {} && {}",
//                 Attribute::Class,
//                 Attribute::Account,
//                 EntryClass::PosixAccount,
//                 Attribute::Group,
//                 EntryClass::PosixGroup,
//             )));
//         }

//         let name = $value
//             .get_ava_single_iname(Attribute::Name)
//             .map(|s| s.to_string())
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

//         let spn = $value
//             .get_ava_single_proto_string(Attribute::Spn)
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::Spn))?;

//         let uuid = $value.get_uuid();

//         let gidnumber = $value
//             .get_ava_single_uint32(Attribute::GidNumber)
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

//         Ok(UnixGroup {
//             name,
//             spn,
//             gidnumber,
//             uuid,
//         })
//     }};
// }

// macro_rules! try_from_account_group_e {
//     ($value:expr, $qs:expr) => {{
//         // First synthesise the self-group from the account.
//         // We have already checked these, but paranoia is better than
//         // complacency.
//         if !$value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue()) {
//             return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
//         }

//         if !$value.attribute_equality(
//             Attribute::Class,
//             &EntryClass::PosixAccount.to_partialvalue(),
//         ) {
//             return Err(OperationError::MissingClass(
//                 ENTRYCLASS_POSIX_ACCOUNT.into(),
//             ));
//         }

//         let name = $value
//             .get_ava_single_iname(Attribute::Name)
//             .map(|s| s.to_string())
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

//         let spn = $value
//             .get_ava_single_proto_string(Attribute::Spn)
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::Spn))?;

//         let uuid = $value.get_uuid();

//         let gidnumber = $value
//             .get_ava_single_uint32(Attribute::GidNumber)
//             .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

//         // This is the user private group.
//         let upg = UnixGroup {
//             name,
//             spn,
//             gidnumber,
//             uuid,
//         };

//         match $value.get_ava_as_refuuid(Attribute::MemberOf) {
//             Some(riter) => {
//                 let f = filter!(f_and!([
//                     f_eq(Attribute::Class, EntryClass::PosixGroup.into()),
//                     f_eq(Attribute::Class, EntryClass::Group.into()),
//                     f_or(
//                         riter
//                             .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
//                             .collect()
//                     )
//                 ]));
//                 let group_entries: Vec<_> = $qs.internal_search(f)?;
//                 let groups: Result<Vec<_>, _> = iter::once(Ok(upg))
//                     .chain(
//                         group_entries
//                             .iter()
//                             .map(|e| UnixGroup::try_from_entry(e.as_ref())),
//                     )
//                     .collect();
//                 groups
//             }
//             None => {
//                 // No memberof, no groups!
//                 Ok(vec![upg])
//             }
//         }
//     }};
// }

// impl UnixGroup {
//     #[allow(dead_code)]
//     pub(crate) fn try_from_account_entry_rw(
//         value: &Entry<EntrySealed, EntryCommitted>,
//         qs: &mut QueryServerWriteTransaction,
//     ) -> Result<Vec<Self>, OperationError> {
//         try_from_account_group_e!(value, qs)
//     }

//     pub(crate) fn try_from_entry_reduced(
//         value: &Entry<EntryReduced, EntryCommitted>,
//     ) -> Result<Self, OperationError> {
//         try_from_group_e!(value)
//     }

//     pub(crate) fn try_from_entry(
//         value: &Entry<EntrySealed, EntryCommitted>,
//     ) -> Result<Self, OperationError> {
//         try_from_group_e!(value)
//     }

//     pub(crate) fn to_unixgrouptoken(&self) -> UnixGroupToken {
//         UnixGroupToken {
//             name: self.name.clone(),
//             spn: self.spn.clone(),
//             uuid: self.uuid,
//             gidnumber: self.gidnumber,
//         }
//     }
// }

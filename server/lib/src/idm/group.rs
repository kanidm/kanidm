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
        if !value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
        }

        let user_group = try_from_entry!(value, ())?;
        Ok(std::iter::once(user_group)
            .chain(Self::try_from_account_reduced(value, qs)?)
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
        if !value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
            return Err(OperationError::MissingAttribute(Attribute::Group));
        }

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
        if !value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
        }

        if !value.attribute_equality(Attribute::Class, &EntryClass::PosixAccount.into()) {
            return Err(OperationError::MissingClass(
                ENTRYCLASS_POSIX_ACCOUNT.into(),
            ));
        }

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

        let gidnumber = value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

        let user_group = try_from_entry!(value, Unix { name, gidnumber })?;

        Ok(std::iter::once(user_group)
            .chain(Self::try_from_account_reduced(value, qs)?)
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

    fn check_entry_classes<E>(value: &Entry<E, EntryCommitted>) -> Result<(), OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        // If its an account, it must be a posix account
        if value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            if !value.attribute_equality(Attribute::Class, &EntryClass::PosixAccount.into()) {
                return Err(OperationError::MissingClass(
                    ENTRYCLASS_POSIX_ACCOUNT.into(),
                ));
            }
        } else {
            // Otherwise it must be both a group and a posix group
            if !value.attribute_equality(Attribute::Class, &EntryClass::PosixGroup.into()) {
                return Err(OperationError::MissingClass(ENTRYCLASS_POSIX_GROUP.into()));
            }

            if !value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                return Err(OperationError::MissingAttribute(Attribute::Group));
            }
        }
        Ok(())
    }

    pub fn try_from_entry<E>(value: &Entry<E, EntryCommitted>) -> Result<Self, OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        Self::check_entry_classes(value)?;

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

//! Modification expressions and validation. This is how `ModifyEvents` store and
//! express the series of Modifications that should be applied. These are expressed
//! as "states" on what attribute-values should appear as within the `Entry`

use std::slice;

use kanidm_proto::internal::{
    Modify as ProtoModify, ModifyList as ProtoModifyList, OperationError, SchemaError,
};
use kanidm_proto::v1::Entry as ProtoEntry;
// Should this be std?
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::value::{PartialValue, Value};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModifyValid;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModifyInvalid;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Modify {
    // This value *should* exist.
    // Clippy doesn't like value here, as value > pv. It could be an improvement to
    // box here, but not sure. ... TODO and thought needed.
    Present(Attribute, Value),
    // This value *should not* exist.
    Removed(Attribute, PartialValue),
    // This attr *should not* exist.
    Purged(Attribute),
    // This attr and value must exist *in this state* for this change to proceed.
    Assert(Attribute, PartialValue),
}

pub fn m_pres(attr: Attribute, v: &Value) -> Modify {
    Modify::Present(attr.into(), v.clone())
}

pub fn m_remove(attr: Attribute, v: &PartialValue) -> Modify {
    Modify::Removed(attr.into(), v.clone())
}

pub fn m_purge(attr: Attribute) -> Modify {
    Modify::Purged(attr.into())
}

pub fn m_assert(attr: Attribute, v: &PartialValue) -> Modify {
    Modify::Assert(attr, v.clone())
}

impl Modify {
    pub fn from(
        m: &ProtoModify,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(match m {
            ProtoModify::Present(a, v) => {
                let a = Attribute::from(a.as_str());
                let v = qs.clone_value(&a, v)?;
                Modify::Present(a, v)
            }
            ProtoModify::Removed(a, v) => {
                let a = Attribute::from(a.as_str());
                let v = qs.clone_partialvalue(&a, v)?;
                Modify::Removed(a, v)
            }
            ProtoModify::Purged(a) => Modify::Purged(Attribute::from(a.as_str())),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModifyList<VALID> {
    // This is never read, it's just used for state machine enforcement.
    #[allow(dead_code)]
    valid: VALID,
    // The order of this list matters. Each change must be done in order.
    mods: Vec<Modify>,
}

impl<'a> IntoIterator for &'a ModifyList<ModifyValid> {
    type IntoIter = slice::Iter<'a, Modify>;
    type Item = &'a Modify;

    fn into_iter(self) -> Self::IntoIter {
        self.mods.iter()
    }
}

impl ModifyList<ModifyInvalid> {
    pub fn new() -> Self {
        ModifyList {
            valid: ModifyInvalid,
            mods: Vec::with_capacity(0),
        }
    }

    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList {
            valid: ModifyInvalid,
            mods,
        }
    }

    pub fn new_purge_and_set(attr: Attribute, v: Value) -> Self {
        Self::new_list(vec![m_purge(attr.clone()), Modify::Present(attr, v)])
    }

    pub fn new_append(attr: Attribute, v: Value) -> Self {
        Self::new_list(vec![Modify::Present(attr, v)])
    }

    pub fn new_remove(attr: Attribute, pv: PartialValue) -> Self {
        Self::new_list(vec![Modify::Removed(attr, pv)])
    }

    pub fn new_purge(attr: Attribute) -> Self {
        Self::new_list(vec![m_purge(attr)])
    }

    pub fn push_mod(&mut self, modify: Modify) {
        self.mods.push(modify)
    }

    pub fn from(
        ml: &ProtoModifyList,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        // For each ProtoModify, do a from.
        let inner: Result<Vec<_>, _> = ml.mods.iter().map(|pm| Modify::from(pm, qs)).collect();
        match inner {
            Ok(m) => Ok(ModifyList {
                valid: ModifyInvalid,
                mods: m,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn from_patch(
        pe: &ProtoEntry,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let mut mods = Vec::with_capacity(0);

        pe.attrs.iter().try_for_each(|(attr, vals)| {
            // Issue a purge to the attr.
            let attr: Attribute = attr.as_str().into();
            mods.push(m_purge(attr.clone()));
            // Now if there are vals, push those too.
            // For each value we want to now be present.
            vals.iter().try_for_each(|val| {
                qs.clone_value(&attr, val).map(|resolved_v| {
                    mods.push(Modify::Present(attr.clone(), resolved_v));
                })
            })
        })?;
        Ok(ModifyList {
            valid: ModifyInvalid,
            mods,
        })
    }

    pub fn validate(
        &self,
        schema: &dyn SchemaTransaction,
    ) -> Result<ModifyList<ModifyValid>, SchemaError> {
        let schema_attributes = schema.get_attributes();
        /*
        let schema_name = schema_attributes
            .get(Attribute::Name.as_ref()")
            .expect("Critical: Core schema corrupt or missing. To initiate a core transfer, please deposit substitute core in receptacle.");
        */

        let res: Result<Vec<Modify>, _> = self
            .mods
            .iter()
            .map(|m| match m {
                Modify::Present(attr, value) => match schema_attributes.get(attr) {
                    Some(schema_a) => schema_a
                        .validate_value(attr, value)
                        .map(|_| Modify::Present(attr.clone(), value.clone())),
                    None => Err(SchemaError::InvalidAttribute(attr.to_string())),
                },
                Modify::Removed(attr, value) => match schema_attributes.get(attr) {
                    Some(schema_a) => schema_a
                        .validate_partialvalue(attr, value)
                        .map(|_| Modify::Removed(attr.clone(), value.clone())),
                    None => Err(SchemaError::InvalidAttribute(attr.to_string())),
                },
                Modify::Assert(attr, value) => match schema_attributes.get(attr) {
                    // TODO: given attr is an enum... you can't get this wrong anymore?
                    Some(schema_a) => schema_a
                        .validate_partialvalue(attr, value)
                        .map(|_| Modify::Assert(attr.clone(), value.clone())),
                    None => Err(SchemaError::InvalidAttribute(attr.to_string())),
                },
                Modify::Purged(attr) => match schema_attributes.get(attr) {
                    Some(_attr_name) => Ok(Modify::Purged(attr.clone())),
                    None => Err(SchemaError::InvalidAttribute(attr.to_string())),
                },
            })
            .collect();

        let valid_mods = match res {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        // Return new ModifyList!
        Ok(ModifyList {
            valid: ModifyValid,
            mods: valid_mods,
        })
    }

    /// ⚠️  - Convert a modlist to be considered valid, bypassing schema.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(crate) fn into_valid(self) -> ModifyList<ModifyValid> {
        ModifyList {
            valid: ModifyValid,
            mods: self.mods,
        }
    }
}

impl ModifyList<ModifyValid> {
    /// ⚠️  - Create a new modlist that is considered valid, bypassing schema.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_valid_list(mods: Vec<Modify>) -> Self {
        ModifyList {
            valid: ModifyValid,
            mods,
        }
    }

    pub fn iter(&self) -> slice::Iter<Modify> {
        self.mods.iter()
    }
}

impl<VALID> ModifyList<VALID> {
    pub fn len(&self) -> usize {
        self.mods.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

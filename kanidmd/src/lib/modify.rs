//! Modification expressions and validation. This is how `ModifyEvents` store and
//! express the series of Modifications that should be applied. These are expressed
//! as "states" on what attribute-values should appear as within the `Entry`

use crate::prelude::*;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::Modify as ProtoModify;
use kanidm_proto::v1::ModifyList as ProtoModifyList;

use crate::schema::SchemaTransaction;
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::{OperationError, SchemaError};

// Should this be std?
use smartstring::alias::String as AttrString;
use std::slice;

#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyValid;
#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyInvalid;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Modify {
    // This value *should* exist.
    // Clippy doesn't like value here, as value > pv. It could be an improvement to
    // box here, but not sure. ... TODO and thought needed.
    Present(AttrString, Value),
    // This value *should not* exist.
    Removed(AttrString, PartialValue),
    // This attr *should not* exist.
    Purged(AttrString),
}

#[allow(dead_code)]
pub fn m_pres(a: &str, v: &Value) -> Modify {
    Modify::Present(a.into(), v.clone())
}

#[allow(dead_code)]
pub fn m_remove(a: &str, v: &PartialValue) -> Modify {
    Modify::Removed(a.into(), v.clone())
}

#[allow(dead_code)]
pub fn m_purge(a: &str) -> Modify {
    Modify::Purged(AttrString::from(a))
}

impl Modify {
    pub fn from(m: &ProtoModify, qs: &QueryServerWriteTransaction) -> Result<Self, OperationError> {
        Ok(match m {
            ProtoModify::Present(a, v) => Modify::Present(a.into(), qs.clone_value(a, v)?),
            ProtoModify::Removed(a, v) => Modify::Removed(a.into(), qs.clone_partialvalue(a, v)?),
            ProtoModify::Purged(a) => Modify::Purged(a.into()),
        })
    }
}

#[derive(Debug, Default)]
pub struct ModifyList<VALID> {
    valid: VALID,
    // The order of this list matters. Each change must be done in order.
    mods: Vec<Modify>,
}

impl<'a> IntoIterator for &'a ModifyList<ModifyValid> {
    type Item = &'a Modify;
    type IntoIter = slice::Iter<'a, Modify>;

    fn into_iter(self) -> Self::IntoIter {
        self.mods.iter()
    }
}

impl ModifyList<ModifyInvalid> {
    pub fn new() -> Self {
        ModifyList {
            valid: ModifyInvalid,
            mods: Vec::new(),
        }
    }

    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList {
            valid: ModifyInvalid,
            mods,
        }
    }

    pub fn new_purge_and_set(attr: &str, v: Value) -> Self {
        Self::new_list(vec![
            m_purge(attr),
            Modify::Present(AttrString::from(attr), v),
        ])
    }

    pub fn new_append(attr: &str, v: Value) -> Self {
        Self::new_list(vec![Modify::Present(AttrString::from(attr), v)])
    }

    pub fn new_remove(attr: &str, pv: PartialValue) -> Self {
        Self::new_list(vec![Modify::Removed(AttrString::from(attr), pv)])
    }

    pub fn new_purge(attr: &str) -> Self {
        Self::new_list(vec![m_purge(attr)])
    }

    pub fn push_mod(&mut self, modify: Modify) {
        self.mods.push(modify)
    }

    pub fn from(
        ml: &ProtoModifyList,
        qs: &QueryServerWriteTransaction,
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
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let mut mods = Vec::new();

        pe.attrs.iter().try_for_each(|(attr, vals)| {
            // Issue a purge to the attr.
            mods.push(m_purge(attr));
            // Now if there are vals, push those too.
            // For each value we want to now be present.
            vals.iter().try_for_each(|val| {
                qs.clone_value(attr, val).map(|resolved_v| {
                    mods.push(Modify::Present(attr.as_str().into(), resolved_v));
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
            .get("name")
            .expect("Critical: Core schema corrupt or missing. To initiate a core transfer, please deposit substitute core in receptacle.");
        */

        let res: Result<Vec<Modify>, _> = (&self.mods)
            .iter()
            .map(|m| match m {
                Modify::Present(attr, value) => {
                    let attr_norm = schema.normalise_attr_name(attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(schema_a) => schema_a
                            .validate_value(attr_norm.as_str(), value)
                            .map(|_| Modify::Present(attr_norm, value.clone())),
                        None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                    }
                }
                Modify::Removed(attr, value) => {
                    let attr_norm = schema.normalise_attr_name(attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(schema_a) => schema_a
                            .validate_partialvalue(attr_norm.as_str(), value)
                            .map(|_| Modify::Removed(attr_norm, value.clone())),
                        None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                    }
                }
                Modify::Purged(attr) => {
                    let attr_norm = schema.normalise_attr_name(attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(_attr_name) => Ok(Modify::Purged(attr_norm)),
                        None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                    }
                }
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

    #[cfg(test)]
    pub unsafe fn into_valid(self) -> ModifyList<ModifyValid> {
        ModifyList {
            valid: ModifyValid,
            mods: self.mods,
        }
    }
}

impl ModifyList<ModifyValid> {
    #[cfg(test)]
    pub unsafe fn new_valid_list(mods: Vec<Modify>) -> Self {
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
}

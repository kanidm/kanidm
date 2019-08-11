use crate::audit::AuditScope;
use crate::proto::v1::Modify as ProtoModify;
use crate::proto::v1::ModifyList as ProtoModifyList;

use crate::error::{OperationError, SchemaError};
use crate::schema::SchemaTransaction;
use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
use crate::value::{PartialValue, Value};

// Should this be std?
use std::slice;

#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyValid;
#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyInvalid;

#[derive(Serialize, Deserialize, Debug)]
pub enum Modify {
    // This value *should* exist.
    Present(String, Value),
    // This value *should not* exist.
    Removed(String, PartialValue),
    // This attr *should not* exist.
    Purged(String),
}

#[allow(dead_code)]
pub fn m_pres(a: &str, v: &Value) -> Modify {
    Modify::Present(a.to_string(), v.clone())
}

#[allow(dead_code)]
pub fn m_remove(a: &str, v: &PartialValue) -> Modify {
    Modify::Removed(a.to_string(), v.clone())
}

#[allow(dead_code)]
pub fn m_purge(a: &str) -> Modify {
    Modify::Purged(a.to_string())
}

impl Modify {
    pub fn from(
        audit: &mut AuditScope,
        m: &ProtoModify,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(match m {
            ProtoModify::Present(a, v) => Modify::Present(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoModify::Removed(a, v) => Modify::Removed(a.clone(), qs.clone_partialvalue(audit, a, v)?),
            ProtoModify::Purged(a) => Modify::Purged(a.clone()),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
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
            mods: mods,
        }
    }

    pub fn push_mod(&mut self, modify: Modify) {
        self.mods.push(modify)
    }

    pub fn from(
        audit: &mut AuditScope,
        ml: &ProtoModifyList,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        // For each ProtoModify, do a from.
        let inner: Result<Vec<_>, _> = ml
            .mods
            .iter()
            .map(|pm| Modify::from(audit, pm, qs))
            .collect();
        match inner {
            Ok(m) => Ok(ModifyList {
                valid: ModifyInvalid,
                mods: m,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn validate(
        &self,
        schema: &SchemaTransaction,
    ) -> Result<ModifyList<ModifyValid>, SchemaError> {
        let schema_attributes = schema.get_attributes();
        /*
        let schema_name = schema_attributes
            .get("name")
            .expect("Critical: Core schema corrupt or missing. To initiate a core transfer, please deposit substitute core in receptacle.");
        */

        let res: Result<Vec<Modify>, _> = (&self.mods)
            .into_iter()
            .map(|m| match m {
                Modify::Present(attr, value) => {
                    let attr_norm = schema.normalise_attr_name(attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(schema_a) => {
                            schema_a
                                .validate_value(&value)
                                .map(|_| Modify::Present(attr_norm, value.clone()))
                        }
                        None => Err(SchemaError::InvalidAttribute),
                    }
                }
                // TODO: Should this be a partial value type?
                Modify::Removed(attr, value) => {
                    let attr_norm = schema.normalise_attr_name(attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(schema_a) => {
                            schema_a
                                .validate_partialvalue(&value)
                                .map(|_| Modify::Removed(attr_norm, value.clone()))
                        }
                        None => Err(SchemaError::InvalidAttribute),
                    }
                }
                Modify::Purged(attr) => {
                    let attr_norm = schema.normalise_attr_name(attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(_attr_name) => Ok(Modify::Purged(attr_norm)),
                        None => Err(SchemaError::InvalidAttribute),
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
    pub unsafe fn to_valid(self) -> ModifyList<ModifyValid> {
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
            mods: mods,
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

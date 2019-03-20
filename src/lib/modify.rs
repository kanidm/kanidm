use audit::AuditScope;
use proto_v1::Modify as ProtoModify;
use proto_v1::ModifyList as ProtoModifyList;

use error::{OperationError, SchemaError};
use schema::{SchemaAttribute, SchemaReadTransaction};
use server::{QueryServerReadTransaction, QueryServerWriteTransaction};

// Should this be std?
use std::slice;

#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyValid;
#[derive(Serialize, Deserialize, Debug)]
pub struct ModifyInvalid;

#[derive(Serialize, Deserialize, Debug)]
pub enum Modify {
    // This value *should* exist.
    Present(String, String),
    // This value *should not* exist.
    Removed(String, String),
    // This attr *should not* exist.
    Purged(String),
}

impl Modify {
    pub fn from(
        audit: &mut AuditScope,
        m: &ProtoModify,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(match m {
            ProtoModify::Present(a, v) => Modify::Present(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoModify::Removed(a, v) => Modify::Removed(a.clone(), qs.clone_value(audit, a, v)?),
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

// TODO: ModifyList should be like filter and have valid/invalid to schema.
// Or do we not care because the entry will be invalid at the end?

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
        schema: &SchemaReadTransaction,
    ) -> Result<ModifyList<ModifyValid>, SchemaError> {
        let schema_attributes = schema.get_attributes();
        let schema_name = schema_attributes
            .get("name")
            .expect("Critical: Core schema corrupt or missing. To initiate a core transfer, please deposit substitute core in receptacle.");

        let res: Result<Vec<Modify>, _> = (&self.mods)
            .into_iter()
            .map(|m| match m {
                Modify::Present(attr, value) => {
                    let attr_norm = schema_name.normalise_value(&attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(schema_a) => {
                            let value_norm = schema_a.normalise_value(&value);
                            schema_a
                                .validate_value(&value_norm)
                                .map(|_| Modify::Present(attr_norm, value_norm))
                        }
                        None => Err(SchemaError::InvalidAttribute),
                    }
                }
                Modify::Removed(attr, value) => {
                    let attr_norm = schema_name.normalise_value(&attr);
                    match schema_attributes.get(&attr_norm) {
                        Some(schema_a) => {
                            let value_norm = schema_a.normalise_value(&value);
                            schema_a
                                .validate_value(&value_norm)
                                .map(|_| Modify::Removed(attr_norm, value_norm))
                        }
                        None => Err(SchemaError::InvalidAttribute),
                    }
                }
                Modify::Purged(attr) => {
                    let attr_norm = schema_name.normalise_value(&attr);
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
}

impl ModifyList<ModifyValid> {
    #[cfg(test)]
    pub unsafe fn new_valid_list(mods: Vec<Modify>) -> Self {
        ModifyList {
            valid: ModifyValid,
            mods: mods,
        }
    }
}

impl<VALID> ModifyList<VALID> {
    pub fn len(&self) -> usize {
        self.mods.len()
    }
}

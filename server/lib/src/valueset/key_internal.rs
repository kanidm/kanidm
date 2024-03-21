use crate::prelude::*;

use crate::repl::proto::ReplAttrV1;
use crate::server::keys::KeyId;
use crate::value::{KeyInternalStatus, KeyUsage};

use crate::be::dbvalue::{DbValueKeyInternal, DbValueKeyInternalStatus, DbValueKeyUsage};
use crate::valueset::{DbValueSetV2, ValueSet};

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInternalData {
    pub usage: KeyUsage,
    pub valid_from: u64,
    pub status: KeyInternalStatus,
    pub der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ValueSetKeyInternal {
    map: BTreeMap<KeyId, KeyInternalData>,
}

impl ValueSetKeyInternal {
    pub fn new(
        id: KeyId,
        usage: KeyUsage,
        valid_from: u64,
        status: KeyInternalStatus,
        der: Vec<u8>,
    ) -> Box<Self> {
        let map = BTreeMap::from([(
            id,
            KeyInternalData {
                usage,
                valid_from,
                status,
                der,
            },
        )]);

        Box::new(ValueSetKeyInternal { map })
    }

    fn push(
        &mut self,
        id: KeyId,
        usage: KeyUsage,
        valid_from: u64,
        status: KeyInternalStatus,
        der: Vec<u8>,
    ) -> bool {
        self.map
            .insert(
                id,
                KeyInternalData {
                    usage,
                    valid_from,
                    status,
                    der,
                },
            )
            .is_none()
    }

    pub fn from_key_iter(
        keys: impl Iterator<Item = (KeyId, KeyInternalData)>,
    ) -> Result<ValueSet, OperationError> {
        let map = keys.collect();

        Ok(Box::new(ValueSetKeyInternal { map }))
    }

    fn from_dbv_iter(
        keys: impl Iterator<Item = DbValueKeyInternal>,
    ) -> Result<ValueSet, OperationError> {
        let map = keys
            .map(|dbv_key| {
                match dbv_key {
                    DbValueKeyInternal::V1 {
                        id,
                        usage,
                        valid_from,
                        status,
                        der,
                    } => {
                        // Type cast, for now, these are both Vec<u8>
                        let id: KeyId = id;
                        let usage = match usage {
                            DbValueKeyUsage::JwtEs256 => KeyUsage::JwtEs256,
                        };
                        let status = match status {
                            DbValueKeyInternalStatus::Valid => KeyInternalStatus::Valid,
                            DbValueKeyInternalStatus::Retained => KeyInternalStatus::Retained,
                            DbValueKeyInternalStatus::Revoked => KeyInternalStatus::Revoked,
                        };

                        Ok((
                            id,
                            KeyInternalData {
                                usage,
                                valid_from,
                                status,
                                der,
                            },
                        ))
                    }
                }
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Box::new(ValueSetKeyInternal { map }))
    }

    pub fn from_dbvs2(keys: Vec<DbValueKeyInternal>) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(keys.into_iter())
    }

    pub fn from_repl_v1(keys: &[DbValueKeyInternal]) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(keys.iter().cloned())
    }

    fn to_vec_dbvs(&self) -> Vec<DbValueKeyInternal> {
        self.map
            .iter()
            .map(
                |(
                    id,
                    KeyInternalData {
                        usage,
                        status,
                        valid_from,
                        der,
                    },
                )| {
                    let id: String = id.clone();
                    let usage = match usage {
                        KeyUsage::JwtEs256 => DbValueKeyUsage::JwtEs256,
                    };
                    let status = match status {
                        KeyInternalStatus::Valid => DbValueKeyInternalStatus::Valid,
                        KeyInternalStatus::Retained => DbValueKeyInternalStatus::Retained,
                        KeyInternalStatus::Revoked => DbValueKeyInternalStatus::Revoked,
                    };

                    DbValueKeyInternal::V1 {
                        id,
                        usage,
                        status,
                        der: der.clone(),
                        valid_from: *valid_from,
                    }
                },
            )
            .collect()
    }
}

impl ValueSetT for ValueSetKeyInternal {
    fn insert_checked(&mut self, value: crate::value::Value) -> Result<bool, OperationError> {
        match value {
            Value::KeyInternal {
                id,
                usage,
                valid_from,
                status,
                der,
            } => {
                todo!();
                // Ok(self.push(&k))
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        // When is this called?
        debug_assert!(false);
        self.map.clear();
    }

    fn remove(&mut self, pv: &crate::value::PartialValue, cid: &Cid) -> bool {
        match pv {
            PartialValue::Iname(kid) => {
                if let Some(key_object) = self.map.get_mut(kid) {
                    if !matches!(key_object.status, KeyInternalStatus::Revoked) {
                        // Do we need to track the Cid like sessions?
                        key_object.status = KeyInternalStatus::Revoked;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn purge(&mut self, cid: &Cid) -> bool {
        for key_object in self.map.values_mut() {
            if !matches!(key_object.status, KeyInternalStatus::Revoked) {
                key_object.status = KeyInternalStatus::Revoked
            }
        }
        // Can't be purged since we need the keys to persist for auditing.
        false
    }

    fn trim(&mut self, _trim_cid: &Cid) {
        // Should we impl trim here for expired keys?
    }

    fn contains(&self, pv: &crate::value::PartialValue) -> bool {
        match pv {
            PartialValue::Iname(kid) => self.map.contains_key(kid),
            _ => false,
        }
    }

    fn substring(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map.keys().map(|kid| hex::encode(kid)).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::KeyInternal
    }

    fn validate(&self, _schema_attr: &crate::schema::SchemaAttribute) -> bool {
        // Validate that every key id is a valid iname.
        self.map.keys().all(|s| {
            // We validate these two first to prevent injection attacks.
            Value::validate_str_escapes(s)
                && Value::validate_singleline(s)
                && Value::validate_hexstr(s.as_str())
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().map(|(kid, key_object)| {
            let kid_hex = hex::encode(kid);

            format!(
                "{}: {} {} {}",
                kid_hex, key_object.status, key_object.usage, key_object.valid_from
            )
        }))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        let keys = self.to_vec_dbvs();
        DbValueSetV2::KeyInternal(keys)
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        let set = self.to_vec_dbvs();
        ReplAttrV1::KeyInternal { set }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = crate::value::PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Iname))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = crate::value::Value> + '_> {
        debug_assert!(false);
        Box::new(self.map.iter().map(
            |(
                id,
                KeyInternalData {
                    usage,
                    status,
                    der,
                    valid_from,
                },
            )| {
                Value::KeyInternal {
                    id: id.clone(),
                    usage: usage.clone(),
                    status: status.clone(),
                    der: der.clone(),
                    valid_from: *valid_from,
                }
            },
        ))
    }

    fn equal(&self, other: &super::ValueSet) -> bool {
        if let Some(other) = other.as_key_internal_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &super::ValueSet) -> Result<(), OperationError> {
        let Some(b) = other.as_key_internal_map() else {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        };

        for (k_other, v_other) in b.iter() {
            if let Some(v_self) = self.map.get_mut(k_other) {
                // We only update if lower. This is where RevokedAt
                // always proceeds other states, and lower revoked
                // cids will always take effect.
                if v_other.status > v_self.status {
                    *v_self = v_other.clone();
                }
            } else {
                // Not present, just insert.
                self.map.insert(k_other.clone(), v_other.clone());
            }
        }

        Ok(())
    }

    fn as_key_internal_map(&self) -> Option<&BTreeMap<KeyId, KeyInternalData>> {
        Some(&self.map)
    }

    fn repl_merge_valueset(&self, older: &ValueSet, _trim_cid: &Cid) -> Option<ValueSet> {
        let Some(b) = older.as_key_internal_map() else {
            return None;
        };

        todo!();
    }
}

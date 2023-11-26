use base64urlsafedata::Base64UrlSafeData;
use compact_jwt::{crypto::JwsRs256Signer, JwsEs256Signer, JwsSigner};
use hashbrown::HashSet;

use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetJwsKeyEs256 {
    set: HashSet<JwsEs256Signer>,
}

impl ValueSetJwsKeyEs256 {
    pub fn new(k: JwsEs256Signer) -> Box<Self> {
        let mut set = HashSet::new();
        set.insert(k);
        Box::new(ValueSetJwsKeyEs256 { set })
    }

    pub fn push(&mut self, k: JwsEs256Signer) -> bool {
        self.set.insert(k)
    }

    pub fn from_dbvs2(data: &[Vec<u8>]) -> Result<ValueSet, OperationError> {
        let set = data
            .iter()
            .map(|b| {
                JwsEs256Signer::from_es256_der(b).map_err(|e| {
                    debug!(?e, "Error occurred parsing ES256 DER");
                    OperationError::InvalidValueState
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Box::new(ValueSetJwsKeyEs256 { set }))
    }

    pub fn from_repl_v1(data: &[Base64UrlSafeData]) -> Result<ValueSet, OperationError> {
        let set = data
            .iter()
            .map(|b| {
                JwsEs256Signer::from_es256_der(b.0.as_slice()).map_err(|e| {
                    debug!(?e, "Error occurred parsing ES256 DER");
                    OperationError::InvalidValueState
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Box::new(ValueSetJwsKeyEs256 { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and jwssigner is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetJwsKeyEs256>>
    where
        T: IntoIterator<Item = JwsEs256Signer>,
    {
        let set: HashSet<JwsEs256Signer> = iter.into_iter().collect();
        Some(Box::new(ValueSetJwsKeyEs256 { set }))
    }
}

impl ValueSetT for ValueSetJwsKeyEs256 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::JwsKeyEs256(k) => Ok(self.set.insert(k)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Iutf8(kid) => {
                let x = self.set.len();
                self.set.retain(|k| k.get_kid() != kid);
                x != self.set.len()
            }
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iutf8(kid) => self.set.iter().any(|k| k.get_kid() == kid),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(|k| k.get_kid().to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::JwsKeyEs256
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|k| k.get_kid().to_string()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::JwsKeyEs256(self.set.iter()
            .map(|k| {
                #[allow(clippy::expect_used)]
                k.private_key_to_der()
                    .expect("Unable to process private key to der, likely corrupted. You must restore from backup.")
            })
            .collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::JwsKeyEs256 { set: self.set.iter()
            .map(|k| {
                #[allow(clippy::expect_used)]
                k.private_key_to_der()
                    .expect("Unable to process private key to der, likely corrupted. You must restore from backup.")
            })
            .map(|b| b.into())
            .collect()
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .cloned()
                .map(|k| PartialValue::new_iutf8(k.get_kid())),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::JwsKeyEs256))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_jws_key_es256_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_jws_key_es256_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_jws_key_es256_single(&self) -> Option<&JwsEs256Signer> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next()
        } else {
            None
        }
    }

    fn as_jws_key_es256_set(&self) -> Option<&HashSet<JwsEs256Signer>> {
        Some(&self.set)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetJwsKeyRs256 {
    set: HashSet<JwsRs256Signer>,
}

impl ValueSetJwsKeyRs256 {
    pub fn new(k: JwsRs256Signer) -> Box<Self> {
        let mut set = HashSet::new();
        set.insert(k);
        Box::new(ValueSetJwsKeyRs256 { set })
    }

    pub fn push(&mut self, k: JwsRs256Signer) -> bool {
        self.set.insert(k)
    }

    pub fn from_dbvs2(data: &[Vec<u8>]) -> Result<ValueSet, OperationError> {
        let set = data
            .iter()
            .map(|b| {
                JwsRs256Signer::from_rs256_der(b).map_err(|e| {
                    debug!(?e, "Error occurred parsing RS256 DER");
                    OperationError::InvalidValueState
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Box::new(ValueSetJwsKeyRs256 { set }))
    }

    pub fn from_repl_v1(data: &[Base64UrlSafeData]) -> Result<ValueSet, OperationError> {
        let set = data
            .iter()
            .map(|b| {
                JwsRs256Signer::from_rs256_der(b.0.as_slice()).map_err(|e| {
                    debug!(?e, "Error occurred parsing RS256 DER");
                    OperationError::InvalidValueState
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Box::new(ValueSetJwsKeyRs256 { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and jwssigner is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetJwsKeyRs256>>
    where
        T: IntoIterator<Item = JwsRs256Signer>,
    {
        let set: HashSet<JwsRs256Signer> = iter.into_iter().collect();
        Some(Box::new(ValueSetJwsKeyRs256 { set }))
    }
}

impl ValueSetT for ValueSetJwsKeyRs256 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::JwsKeyRs256(k) => Ok(self.set.insert(k)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Iutf8(kid) => {
                let x = self.set.len();
                self.set.retain(|k| k.get_kid() != kid);
                x != self.set.len()
            }
            _ => false,
        }
    }

    fn contains(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(|k| k.get_kid().to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::JwsKeyRs256
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|k| k.get_kid().to_string()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::JwsKeyRs256(self.set.iter()
            .map(|k| {
                #[allow(clippy::expect_used)]
                k.private_key_to_der()
                    .expect("Unable to process private key to der, likely corrupted. You must restore from backup.")
            })
            .collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::JwsKeyRs256 { set: self.set.iter()
            .map(|k| {
                #[allow(clippy::expect_used)]
                k.private_key_to_der()
                    .expect("Unable to process private key to der, likely corrupted. You must restore from backup.")
            })
            .map(|b| b.into())
            .collect()
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .cloned()
                .map(|k| PartialValue::new_iutf8(k.get_kid())),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::JwsKeyRs256))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_jws_key_rs256_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_jws_key_rs256_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_jws_key_rs256_single(&self) -> Option<&JwsRs256Signer> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next()
        } else {
            None
        }
    }

    fn as_jws_key_rs256_set(&self) -> Option<&HashSet<JwsRs256Signer>> {
        Some(&self.set)
    }
}

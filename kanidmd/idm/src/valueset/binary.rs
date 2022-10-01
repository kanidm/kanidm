use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use smolset::SmolSet;

use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetPrivateBinary {
    set: SmolSet<[Vec<u8>; 1]>,
}

impl ValueSetPrivateBinary {
    pub fn new(b: Vec<u8>) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetPrivateBinary { set })
    }

    pub fn push(&mut self, b: Vec<u8>) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<Vec<u8>>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetPrivateBinary { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and vec is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetPrivateBinary>>
    where
        T: IntoIterator<Item = Vec<u8>>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetPrivateBinary { set }))
    }
}

impl ValueSetT for ValueSetPrivateBinary {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::PrivateBinary(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, _pv: &PartialValue) -> bool {
        true
    }

    fn contains(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::PrivateBinary
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|_| "private_binary".to_string()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::PrivateBinary(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .cloned()
                .map(|_| PartialValue::PrivateBinary),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::PrivateBinary))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_private_binary_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_private_binary_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_private_binary_single(&self) -> Option<&[u8]> {
        if self.set.len() == 1 {
            self.set.iter().map(|b| b.as_slice()).take(1).next()
        } else {
            None
        }
    }

    fn as_private_binary_set(&self) -> Option<&SmolSet<[Vec<u8>; 1]>> {
        Some(&self.set)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetPublicBinary {
    map: BTreeMap<String, Vec<u8>>,
}

impl ValueSetPublicBinary {
    pub fn new(t: String, b: Vec<u8>) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, b);
        Box::new(ValueSetPublicBinary { map })
    }

    pub fn push(&mut self, t: String, b: Vec<u8>) -> bool {
        self.map.insert(t, b).is_none()
    }

    pub fn from_dbvs2(data: Vec<(String, Vec<u8>)>) -> Result<ValueSet, OperationError> {
        let map = data.into_iter().collect();
        Ok(Box::new(ValueSetPublicBinary { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetPublicBinary>>
    where
        T: IntoIterator<Item = (String, Vec<u8>)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetPublicBinary { map }))
    }
}

impl ValueSetT for ValueSetPublicBinary {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::PublicBinary(t, b) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(t) {
                    e.insert(b);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::PublicBinary(t) => self.map.remove(t.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::PublicBinary(t) => self.map.contains_key(t.as_str()),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        unreachable!();
        // SyntaxType::PublicBinary
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::PublicBinary(
            self.map
                .iter()
                .map(|(tag, bin)| (tag.clone(), bin.clone()))
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::PublicBinary))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(t, b)| Value::PublicBinary(t.clone(), b.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_publicbinary_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_publicbinary_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_publicbinary_map(&self) -> Option<&BTreeMap<String, Vec<u8>>> {
        Some(&self.map)
    }
}

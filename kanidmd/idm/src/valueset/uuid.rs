use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::uuid_to_proto_string;
use crate::valueset::DbValueSetV2;
use crate::valueset::ValueSet;
use std::collections::BTreeSet;

use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetUuid {
    set: SmolSet<[Uuid; 1]>,
}

impl ValueSetUuid {
    pub fn new(u: Uuid) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(u);
        Box::new(ValueSetUuid { set })
    }

    pub fn push(&mut self, u: Uuid) -> bool {
        self.set.insert(u)
    }

    pub fn from_dbvs2(data: Vec<Uuid>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetUuid { set }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Uuid>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetUuid { set }))
    }
}

impl ValueSetT for ValueSetUuid {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Uuid(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.set.contains(u),
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
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set
            .iter()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Uuid
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().copied().map(uuid_to_proto_string))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Uuid(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(|u| PartialValue::new_uuid(u)))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(|u| Value::new_uuid(u)))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_uuid_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_uuid_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_uuid_single(&self) -> Option<Uuid> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_uuid_set(&self) -> Option<&SmolSet<[Uuid; 1]>> {
        Some(&self.set)
    }

    /*
    fn as_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
    */
}

#[derive(Debug, Clone)]
pub struct ValueSetRefer {
    set: BTreeSet<Uuid>,
}

impl ValueSetRefer {
    pub fn new(u: Uuid) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(u);
        Box::new(ValueSetRefer { set })
    }

    pub fn push(&mut self, u: Uuid) -> bool {
        self.set.insert(u)
    }

    pub fn from_dbvs2(data: Vec<Uuid>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetRefer { set }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Uuid>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetRefer { set }))
    }
}

impl ValueSetT for ValueSetRefer {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Refer(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.set.contains(u),
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
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set
            .iter()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::REFERENCE_UUID
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().copied().map(uuid_to_proto_string))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Reference(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(|u| PartialValue::new_refer(u)))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(|u| Value::new_refer(u)))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_refer_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_refer_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_refer_single(&self) -> Option<Uuid> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_refer_set(&self) -> Option<&BTreeSet<Uuid>> {
        Some(&self.set)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
}

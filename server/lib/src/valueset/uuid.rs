use std::collections::BTreeSet;

use smolset::SmolSet;

use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{uuid_to_proto_string, DbValueSetV2, ValueSet};

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

    pub fn from_repl_v1(data: &[Uuid]) -> Result<ValueSet, OperationError> {
        let set = data.iter().copied().collect();
        Ok(Box::new(ValueSetUuid { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and uuid is foreign.
    #[allow(clippy::should_implement_trait)]
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.set.iter().any(|v| v < u),
            _ => false,
        }
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

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Uuid {
            set: self.set.iter().cloned().collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Uuid))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Uuid))
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

    pub fn from_repl_v1(data: &[Uuid]) -> Result<ValueSet, OperationError> {
        let set = data.iter().copied().collect();
        Ok(Box::new(ValueSetRefer { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and uuid is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Uuid>,
    {
        let set: BTreeSet<_> = iter.into_iter().collect();
        if set.is_empty() {
            None
        } else {
            Some(Box::new(ValueSetRefer { set }))
        }
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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
        self.set
            .iter()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::ReferenceUuid
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

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Reference {
            set: self.set.iter().cloned().collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Refer))
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

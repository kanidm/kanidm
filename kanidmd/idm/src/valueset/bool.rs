use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::DbValueSetV2;
use crate::valueset::ValueSet;
use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetBool {
    set: SmolSet<[bool; 1]>,
}

impl ValueSetBool {
    pub fn new(b: bool) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetBool { set })
    }

    pub fn push(&mut self, b: bool) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<bool>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetBool { set }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = bool>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetBool { set }))
    }
}

impl ValueSetT for ValueSetBool {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Bool(u) => Ok(self.set.insert(u)),
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
            PartialValue::Bool(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Bool(u) => self.set.contains(u),
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
        self.set.iter().map(|b| b.to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Boolean
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|b| b.to_string()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Bool(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(|b| PartialValue::new_bool(b)))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(|b| Value::new_bool(b)))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_bool_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_bool_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_bool_single(&self) -> Option<bool> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_bool_set(&self) -> Option<&SmolSet<[bool; 1]>> {
        Some(&self.set)
    }
}

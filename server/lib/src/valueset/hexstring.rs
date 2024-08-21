use std::collections::BTreeSet;

use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetHexString {
    set: BTreeSet<String>,
}

impl ValueSetHexString {
    pub fn new(s: String) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s);
        Box::new(ValueSetHexString { set })
    }

    pub fn push(&mut self, s: &str) -> bool {
        self.set.insert(s.to_lowercase())
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetHexString { set }))
    }

    pub fn from_repl_v1(data: &[String]) -> Result<ValueSet, OperationError> {
        let set = data.iter().cloned().collect();
        Ok(Box::new(ValueSetHexString { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and str is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<'a, T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = &'a str>,
    {
        let set = iter.into_iter().map(str::to_string).collect();
        Some(Box::new(ValueSetHexString { set }))
    }
}

impl ValueSetT for ValueSetHexString {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::HexString(s) => Ok(self.set.insert(s)),
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
            PartialValue::HexString(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s) => self.set.contains(s.as_str()),
            _ => false,
        }
    }

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s2) => self.set.iter().any(|s1| s1.contains(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s2) => self.set.iter().any(|s1| s1.starts_with(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s2) => self.set.iter().any(|s1| s1.ends_with(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::HexString
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.iter().all(|s| {
            Value::validate_str_escapes(s.as_str())
                && Value::validate_singleline(s.as_str())
                && Value::validate_hexstr(s.as_str())
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().cloned())
    }

    fn to_scim_value_iter(&self) -> Box<dyn Iterator<Item = ScimValue> + '_>{
        todo!();
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::HexString(self.set.iter().cloned().collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::HexString {
            set: self.set.iter().cloned().collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::HexString))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::HexString))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_hexstring_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_hexstring_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_hexstring_set(&self) -> Option<&BTreeSet<String>> {
        Some(&self.set)
    }
}

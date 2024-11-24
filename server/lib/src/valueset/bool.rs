use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::ScimResolveStatus;
use crate::valueset::{DbValueSetV2, ValueSet, ValueSetResolveStatus, ValueSetScimPut};
use kanidm_proto::scim_v1::JsonValue;
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

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and bool is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = bool>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetBool { set }))
    }
}

impl ValueSetScimPut for ValueSetBool {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        todo!();
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        if self.len() == 1 {
            // Because self.len == 1 we know this has to yield a value.
            let b = self.set.iter().copied().next().unwrap_or_default();

            Some(b.into())
        } else {
            // Makes no sense for more than 1 value.
            None
        }
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Bool(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::new_bool))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::new_bool))
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

#[cfg(test)]
mod tests {
    use super::ValueSetBool;
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_boolean() {
        let vs: ValueSet = ValueSetBool::new(true);
        crate::valueset::scim_json_reflexive(vs.clone(), "true");

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetBool>(vs, &[])
    }
}

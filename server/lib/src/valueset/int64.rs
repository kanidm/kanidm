use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{
    DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut,
};
use kanidm_proto::scim_v1::JsonValue;
use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetInt64 {
    set: SmolSet<[i64; 1]>,
}

impl ValueSetInt64 {
    pub fn new(b: i64) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetInt64 { set })
    }

    pub fn push(&mut self, b: i64) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<i64>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetInt64 { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and i64 is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = i64>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetInt64 { set }))
    }
}

impl ValueSetScimPut for ValueSetInt64 {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value: i64 = serde_json::from_value(value).map_err(|err| {
            error!(?err, "SCIM int64 syntax invalid");
            OperationError::SC0031Int64SyntaxInvalid
        })?;

        let mut set = SmolSet::new();
        set.insert(value);

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetInt64 {
            set,
        })))
    }
}

impl ValueSetT for ValueSetInt64 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Int64(u) => Ok(self.set.insert(u)),
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
            PartialValue::Int64(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Int64(u) => self.set.contains(u),
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
            PartialValue::Int64(u) => self.set.iter().any(|i| i < u),
            _ => false,
        }
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(|b| b.to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Int64
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
            // Nothing is MV for this today
            None
        }
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Int64(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Int64))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Int64))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_int64_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_int64_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_int64_single(&self) -> Option<i64> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_int64_set(&self) -> Option<&SmolSet<[i64; 1]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetInt64;
    use crate::prelude::*;

    #[test]
    fn test_valueset_basic() {
        let mut vs = ValueSetInt64::new(0);
        assert_eq!(vs.insert_checked(Value::Int64(0)), Ok(false));
        assert_eq!(vs.insert_checked(Value::Int64(1)), Ok(true));
        assert_eq!(vs.insert_checked(Value::Int64(1)), Ok(false));
    }

    #[test]
    fn test_scim_int64() {
        let vs: ValueSet = ValueSetInt64::new(69);
        crate::valueset::scim_json_reflexive(&vs, "69");

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetInt64>(&vs, &[])
    }
}

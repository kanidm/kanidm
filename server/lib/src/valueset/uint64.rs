use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{
    DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut,
};
use kanidm_proto::scim_v1::JsonValue;
use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetUint64 {
    set: SmolSet<[u64; 1]>,
}

impl ValueSetUint64 {
    pub fn new(b: u64) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetUint64 { set })
    }

    pub fn push(&mut self, b: u64) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<u64>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetUint64 { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and u64 is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = u64>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetUint64 { set }))
    }
}

impl ValueSetScimPut for ValueSetUint64 {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value: u64 = serde_json::from_value(value).map_err(|err| {
            error!(?err, "SCIM uint64 syntax invalid");
            OperationError::SC0032Uint64SyntaxInvalid
        })?;

        let mut set = SmolSet::new();
        set.insert(value);

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetUint64 {
            set,
        })))
    }
}

impl ValueSetT for ValueSetUint64 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Uint64(u) => Ok(self.set.insert(u)),
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
            PartialValue::Uint64(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uint64(u) => self.set.contains(u),
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
            PartialValue::Uint64(u) => self.set.iter().any(|i| i < u),
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
        SyntaxType::Uint64
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
        DbValueSetV2::Uint64(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Uint64))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Uint64))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_uint64_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_uint64_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_uint64_single(&self) -> Option<u64> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_uint64_set(&self) -> Option<&SmolSet<[u64; 1]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetUint64;
    use crate::prelude::*;

    #[test]
    fn test_valueset_basic() {
        let mut vs = ValueSetUint64::new(0);
        assert_eq!(vs.insert_checked(Value::Uint64(0)), Ok(false));
        assert_eq!(vs.insert_checked(Value::Uint64(1)), Ok(true));
        assert_eq!(vs.insert_checked(Value::Uint64(1)), Ok(false));
    }

    #[test]
    fn test_scim_uint64() {
        let vs: ValueSet = ValueSetUint64::new(69);
        crate::valueset::scim_json_reflexive(&vs, "69");

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetUint64>(&vs, &[])
    }
}

use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::value::NSUNIQUEID_RE;
use crate::valueset::ScimResolveStatus;
use crate::valueset::{DbValueSetV2, ValueSet, ValueSetResolveStatus, ValueSetScimPut};
use kanidm_proto::scim_v1::JsonValue;

use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetNsUniqueId {
    set: SmolSet<[String; 1]>,
}

impl ValueSetNsUniqueId {
    pub fn new(b: String) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetNsUniqueId { set })
    }

    pub fn push(&mut self, b: String) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetNsUniqueId { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and String is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = String>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetNsUniqueId { set }))
    }
}

impl ValueSetScimPut for ValueSetNsUniqueId {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value = serde_json::from_value::<String>(value).map_err(|err| {
            error!(?err, "SCIM NsUniqueId Syntax Invalid");
            OperationError::SC0018NsUniqueIdSyntaxInvalid
        })?;

        let mut set = SmolSet::new();
        set.insert(value.to_lowercase());

        Ok(ValueSetResolveStatus::Resolved(Box::new(
            ValueSetNsUniqueId { set },
        )))
    }
}

impl ValueSetT for ValueSetNsUniqueId {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Nsuniqueid(u) => Ok(self.set.insert(u)),
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
            PartialValue::Nsuniqueid(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Nsuniqueid(u) => self.set.contains(u),
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
        self.set.iter().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::NsUniqueId
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.iter().all(|s| NSUNIQUEID_RE.is_match(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().cloned())
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        let mut iter = self.set.iter().cloned();
        if self.len() == 1 {
            let v = iter.next().unwrap_or_default();
            Some(v.into())
        } else {
            let arr = iter.collect::<Vec<_>>();
            Some(arr.into())
        }
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::NsUniqueId(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::Nsuniqueid))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::Nsuniqueid))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_nsuniqueid_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_nsuniqueid_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    /*
    fn to_nsuniqueid_single(&self) -> Option<&String> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next()
        } else {
            None
        }
    }
    */

    fn as_nsuniqueid_set(&self) -> Option<&SmolSet<[String; 1]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetNsUniqueId;
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_nsuniqueid() {
        let vs: ValueSet =
            ValueSetNsUniqueId::new("3a163ca0-47624620-a18806b7-50c84c86".to_string());
        crate::valueset::scim_json_reflexive(&vs, r#""3a163ca0-47624620-a18806b7-50c84c86""#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetNsUniqueId>(&vs, &[])
    }
}

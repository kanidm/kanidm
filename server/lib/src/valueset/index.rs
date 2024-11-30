use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::ScimResolveStatus;
use crate::valueset::{DbValueSetV2, ValueSet, ValueSetResolveStatus, ValueSetScimPut};
use kanidm_proto::scim_v1::JsonValue;

use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetIndex {
    set: SmolSet<[IndexType; 3]>,
}

impl ValueSetIndex {
    pub fn new(s: IndexType) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(s);
        Box::new(ValueSetIndex { set })
    }

    pub fn push(&mut self, s: IndexType) -> bool {
        self.set.insert(s)
    }

    pub fn from_dbvs2(data: Vec<u16>) -> Result<ValueSet, OperationError> {
        let set: Result<_, _> = data.into_iter().map(IndexType::try_from).collect();
        let set = set.map_err(|_| OperationError::InvalidValueState)?;
        Ok(Box::new(ValueSetIndex { set }))
    }

    // We need to allow this, because there seems to be a bug using it fromiterator in entry.rs
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetIndex>>
    where
        T: IntoIterator<Item = IndexType>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetIndex { set }))
    }
}

impl ValueSetScimPut for ValueSetIndex {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value = serde_json::from_value::<Vec<String>>(value).map_err(|err| {
            error!(?err, "SCIM IndexType syntax invalid");
            OperationError::SC0009IndexTypeSyntaxInvalid
        })?;

        let set = value
            .into_iter()
            .map(|s| {
                IndexType::try_from(s.as_str()).map_err(|_| {
                    error!("SCIM IndexType syntax invalid value");
                    OperationError::SC0009IndexTypeSyntaxInvalid
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetIndex {
            set,
        })))
    }
}

impl ValueSetT for ValueSetIndex {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Index(u) => Ok(self.set.insert(u)),
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
            PartialValue::Index(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Index(u) => self.set.contains(u),
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
        SyntaxType::IndexId
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|b| b.to_string()))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.set.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::IndexType(self.set.iter().map(|s| *s as u16).collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Index))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Index))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_index_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_index_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_indextype_iter(&self) -> Option<Box<dyn Iterator<Item = IndexType> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }

    fn as_index_set(&self) -> Option<&SmolSet<[IndexType; 3]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetIndex;
    use crate::prelude::{IndexType, ValueSet};

    #[test]
    fn test_scim_index() {
        let vs: ValueSet = ValueSetIndex::new(IndexType::Equality);
        crate::valueset::scim_json_reflexive(vs.clone(), r#"["EQUALITY"]"#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetIndex>(vs, &[])
    }
}

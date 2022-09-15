use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::DbValueSetV2;
use crate::valueset::ValueSet;
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

    pub fn from_dbvs2(data: Vec<usize>) -> Result<ValueSet, OperationError> {
        let set: Result<_, _> = data.into_iter().map(IndexType::try_from).collect();
        let set = set.map_err(|()| OperationError::InvalidValueState)?;
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

    fn remove(&mut self, pv: &PartialValue) -> bool {
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

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::IndexType(self.set.iter().map(|s| s.to_usize()).collect())
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

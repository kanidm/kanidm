use kanidm_proto::v1::Filter as ProtoFilter;
use smolset::SmolSet;

use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetJsonFilter {
    set: SmolSet<[ProtoFilter; 1]>,
}

impl ValueSetJsonFilter {
    pub fn new(b: ProtoFilter) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetJsonFilter { set })
    }

    pub fn push(&mut self, b: ProtoFilter) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: &[String]) -> Result<ValueSet, OperationError> {
        let set = data
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(|_| OperationError::SerdeJsonError))
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetJsonFilter { set }))
    }

    pub fn from_repl_v1(data: &[String]) -> Result<ValueSet, OperationError> {
        let set = data
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(|_| OperationError::SerdeJsonError))
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetJsonFilter { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and protofilter is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = ProtoFilter>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetJsonFilter { set }))
    }
}

impl ValueSetT for ValueSetJsonFilter {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::JsonFilt(u) => Ok(self.set.insert(u)),
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
            PartialValue::JsonFilt(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::JsonFilt(u) => self.set.contains(u),
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
            .map(|s| {
                #[allow(clippy::expect_used)]
                serde_json::to_string(s).expect("A json filter value was corrupted during run-time")
            })
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::JsonFilter
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|i| {
            #[allow(clippy::expect_used)]
            serde_json::to_string(i).expect("A json filter value was corrupted during run-time")
        }))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::JsonFilter(
            self.set
                .iter()
                .map(|s| {
                    #[allow(clippy::expect_used)]
                    serde_json::to_string(s)
                        .expect("A json filter value was corrupted during run-time")
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::JsonFilter {
            set: self
                .set
                .iter()
                .map(|s| {
                    #[allow(clippy::expect_used)]
                    serde_json::to_string(s)
                        .expect("A json filter value was corrupted during run-time")
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::JsonFilt))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::JsonFilt))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_json_filter_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_json_filter_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_json_filter_single(&self) -> Option<&ProtoFilter> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next()
        } else {
            None
        }
    }

    fn as_json_filter_set(&self) -> Option<&SmolSet<[ProtoFilter; 1]>> {
        Some(&self.set)
    }
}

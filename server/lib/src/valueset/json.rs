use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};
use kanidm_proto::internal::Filter as ProtoFilter;
use kanidm_proto::scim_v1::server::ScimResolveStatus;
use smolset::SmolSet;

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
            .iter()
            .map(|s| serde_json::from_str(s).map_err(|_| OperationError::SerdeJsonError))
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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
        Box::new(self.set.iter().filter_map(|i| {
            serde_json::to_string(i)
                .inspect_err(|err| {
                    error!(?err, "A json filter value was corrupted during run-time")
                })
                .ok()
        }))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.set
                .iter()
                .filter_map(|s| {
                    serde_json::to_string(s)
                        .inspect_err(|err| {
                            error!(?err, "A json filter value was corrupted during run-time")
                        })
                        .ok()
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::JsonFilter(
            self.set
                .iter()
                .filter_map(|s| {
                    serde_json::to_string(s)
                        .inspect_err(|err| {
                            error!(?err, "A json filter value was corrupted during run-time")
                        })
                        .ok()
                })
                .collect(),
        )
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

#[cfg(test)]
mod tests {
    use super::{ProtoFilter, ValueSetJsonFilter};
    use crate::prelude::{Attribute, ValueSet};

    #[test]
    fn test_scim_json_filter() {
        let filter = ProtoFilter::Pres(Attribute::Class.to_string());
        let vs: ValueSet = ValueSetJsonFilter::new(filter);

        let data = r#"
[
  "{\"pres\":\"class\"}"
]
        "#;
        crate::valueset::scim_json_reflexive(vs, data);
    }
}

use super::iname::ValueSetIname;
use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::utils::trigraph_iter;
use crate::valueset::ScimResolveStatus;
use crate::valueset::{DbValueSetV2, ValueSet, ValueSetResolveStatus, ValueSetScimPut};
use kanidm_proto::scim_v1::client::ScimStrings;
use kanidm_proto::scim_v1::JsonValue;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetIutf8 {
    set: BTreeSet<String>,
}

impl ValueSetIutf8 {
    pub fn new(s: &str) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s.to_lowercase());
        Box::new(ValueSetIutf8 { set })
    }

    pub fn push(&mut self, s: &str) -> bool {
        self.set.insert(s.to_lowercase())
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetIutf8 { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and str is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<'a, T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = &'a str>,
    {
        let set = iter.into_iter().map(str::to_string).collect();
        Some(Box::new(ValueSetIutf8 { set }))
    }
}

impl ValueSetScimPut for ValueSetIutf8 {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let ScimStrings(values) = serde_json::from_value(value).map_err(|_| todo!())?;

        let set = values.iter().map(|s| s.to_lowercase()).collect();

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetIutf8 {
            set,
        })))
    }
}

impl ValueSetT for ValueSetIutf8 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Iutf8(s) => Ok(self.set.insert(s)),
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
            PartialValue::Iutf8(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iutf8(s) => self.set.contains(s.as_str()),
            _ => false,
        }
    }

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iutf8(s2) => self.set.iter().any(|s1| s1.contains(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iutf8(s2) => self.set.iter().any(|s1| s1.starts_with(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iutf8(s2) => self.set.iter().any(|s1| s1.ends_with(s2)),
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

    fn generate_idx_sub_keys(&self) -> Vec<String> {
        let mut trigraphs: Vec<_> = self.set.iter().flat_map(|v| trigraph_iter(v)).collect();

        trigraphs.sort_unstable();
        trigraphs.dedup();

        trigraphs.into_iter().map(String::from).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Utf8StringInsensitive
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set
            .iter()
            .all(|s| Value::validate_str_escapes(s) && Value::validate_singleline(s))
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
        DbValueSetV2::Iutf8(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().map(|i| PartialValue::new_iutf8(i.as_str())))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().map(|i| Value::new_iutf8(i.as_str())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_iutf8_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_iutf8_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_iutf8_single(&self) -> Option<&str> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next().map(|s| s.as_str())
        } else {
            None
        }
    }

    fn as_iutf8_set(&self) -> Option<&BTreeSet<String>> {
        Some(&self.set)
    }

    fn as_iutf8_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        Some(Box::new(self.set.iter().map(|s| s.as_str())))
    }

    fn migrate_iutf8_iname(&self) -> Result<Option<ValueSet>, OperationError> {
        let vsi: Option<ValueSet> =
            ValueSetIname::from_iter(self.set.iter().map(|s| s.as_str())).map(|vs| vs as _);
        Ok(vsi)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetIutf8;
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_iutf8() {
        let vs: ValueSet = ValueSetIutf8::new("lowercase string");
        crate::valueset::scim_json_reflexive(vs.clone(), r#""lowercase string""#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetIutf8>(vs, &[])
    }
}

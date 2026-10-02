use crate::{
    prelude::*,
    schema::SchemaAttribute,
    utils::trigraph_iter,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut},
};
use kanidm_proto::scim_v1::JsonValue;
use std::cmp::Ordering;

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetIname {
    value: String,
}

impl ValueSetIname {
    pub fn new(s: &str) -> Box<Self> {
        Box::new(ValueSetIname { value: s.to_lowercase() })
    }

    pub fn from_dbvs2(value: String) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetIname { value }))
    }
}

impl ValueSetScimPut for ValueSetIname {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value = serde_json::from_value::<String>(value).map_err(|err| {
            error!(?err, "SCIM Iname Syntax Invalid");
            OperationError::SC0016InameSyntaxInvalid
        })?;

        let value = value.to_lowercase();

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetIname {
            value
        })))
    }
}

impl ValueSetT for ValueSetIname {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Iname(s) => {
                if s != self.value {
                    self.value = s;
                    true
                } else {
                    false
                }
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Iname(s) => s == self.value,
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s) => s == self.value,
            _ => false,
        }
    }

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s2) => self.value.contains(s2),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s2) => self.value.starts_with(s2),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s2) => self.value.ends_with(s2),
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
        1
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        std::iter::once(self.value.clone()).collect()
    }

    fn generate_idx_sub_keys(&self) -> Vec<String> {
        debug_assert!(self.value == s.to_lowercase());

        let lower: Vec<_> = self.set.iter().map(|s| s.to_lowercase()).collect();
        let mut trigraphs: Vec<_> = trigraph_iter(v).collect();

        trigraphs.sort_unstable();
        trigraphs.dedup();

        trigraphs.into_iter().map(String::from).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Utf8StringIname
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
            Value::validate_str_escapes(self.value)
                && Value::validate_singleline(self.value)
                && Value::validate_iname(self.value.as_str())
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(std::iter::once(self.value.cloned()))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(self.value.into())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::InameSingle(self.value.clone())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(std::iter::once( PartialValue::Iname(self.value.clone())))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(std::iter::once( Value::Iname(self.value.clone())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.to_iname_single() {
            &self.value == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn cmp(&self, other: &ValueSet) -> Ordering {
        if let Some(other) = other.to_iname_single() {
            self.value.cmp(other)
        } else {
            debug_assert!(false);
            Ordering::Equal
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn to_iname_single(&self) -> Option<&str> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next().map(|s| s.as_str())
        } else {
            None
        }
    }

    /*
    fn migrate_iutf8_iname(&self) -> Result<Option<ValueSet>, OperationError> {
        Ok(None)
    }
    */
}

#[derive(Debug, Clone)]
pub struct ValueSetInameN {
    set: BTreeSet<String>,
}

impl ValueSetInameN {
    pub fn new(s: &str) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s.to_lowercase());
        Box::new(ValueSetIname { set })
    }

    pub fn push(&mut self, s: &str) -> bool {
        self.set.insert(s.to_lowercase())
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetIname { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and str is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<'a, T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = &'a str>,
    {
        let set = iter.into_iter().map(str::to_string).collect();
        Some(Box::new(ValueSetIname { set }))
    }
}

impl ValueSetScimPut for ValueSetInameN {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let set: Vec<String> = serde_json::from_value(value).map_err(|err| {
            error!(?err, "SCIM Iname Syntax Invalid");
            OperationError::SC0016InameSyntaxInvalid
        })?;

        let set = set.into_iter()
            .map(|value| value.to_lowercase())
            .collect();

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetIname {
            set,
        })))
    }
}

impl ValueSetT for ValueSetInameN {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Iname(s) => Ok(self.set.insert(s)),
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
            PartialValue::Iname(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s) => self.set.contains(s.as_str()),
            _ => false,
        }
    }

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s2) => self.set.iter().any(|s1| s1.contains(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s2) => self.set.iter().any(|s1| s1.starts_with(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iname(s2) => self.set.iter().any(|s1| s1.ends_with(s2)),
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
        let lower: Vec<_> = self.set.iter().map(|s| s.to_lowercase()).collect();
        let mut trigraphs: Vec<_> = lower.iter().flat_map(|v| trigraph_iter(v)).collect();

        trigraphs.sort_unstable();
        trigraphs.dedup();

        trigraphs.into_iter().map(String::from).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Utf8StringInameN
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.iter().all(|s| {
            Value::validate_str_escapes(s)
                && Value::validate_singleline(s)
                && Value::validate_iname(s.as_str())
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().cloned())
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        let arr = self.set.iter().cloned().collect::<Vec<_>>();
        Some(arr.into())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Iname(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().map(|i| PartialValue::new_iname(i.as_str())))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().map(|i| Value::new_iname(i.as_str())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_iname_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn cmp(&self, other: &ValueSet) -> Ordering {
        if let Some(other) = other.as_iname_set() {
            self.set.cmp(other)
        } else {
            debug_assert!(false);
            Ordering::Equal
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_iname_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_iname_single(&self) -> Option<&str> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next().map(|s| s.as_str())
        } else {
            None
        }
    }

    fn as_iname_set(&self) -> Option<&BTreeSet<String>> {
        Some(&self.set)
    }

    fn as_iname_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        Some(Box::new(self.set.iter().map(|s| s.as_str())))
    }

    /*
    fn migrate_iutf8_iname(&self) -> Result<Option<ValueSet>, OperationError> {
        Ok(None)
    }
    */
}

#[cfg(test)]
mod tests {
    use super::{ValueSetIname, ValueSetInameN};
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_iname_single() {
        let vs: ValueSet = ValueSetIname::new("stevo");
        crate::valueset::scim_json_reflexive(&vs, r#""stevo""#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetIname>(&vs, &[])
    }

    #[test]
    fn test_scim_iname_multi() {
        let vs: ValueSet = ValueSetInameN::new("stevo");
        crate::valueset::scim_json_reflexive(&vs, r#"["stevo"]"#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetInameN>(&vs, &[])
    }
}

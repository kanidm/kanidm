use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::utils::trigraph_iter;
use crate::valueset::{DbValueSetV2, ValueSet};
use kanidm_proto::scim_v1::server::ScimResolveStatus;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetUtf8 {
    set: BTreeSet<String>,
}

impl ValueSetUtf8 {
    pub fn new(s: String) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s);
        Box::new(ValueSetUtf8 { set })
    }

    pub fn push(&mut self, s: String) -> bool {
        self.set.insert(s)
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetUtf8 { set }))
    }
}

impl ValueSetT for ValueSetUtf8 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Utf8(s) => Ok(self.set.insert(s)),
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Utf8(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(s) => self.set.contains(s.as_str()),
            _ => false,
        }
    }

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(s2) => {
                // We lowercase as LDAP and similar expect case insensitive searches here.
                let s2_lower = s2.to_lowercase();
                self.set
                    .iter()
                    .any(|s1| s1.to_lowercase().contains(&s2_lower))
            }
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(s2) => {
                // We lowercase as LDAP and similar expect case insensitive searches here.
                let s2_lower = s2.to_lowercase();
                self.set
                    .iter()
                    .any(|s1| s1.to_lowercase().starts_with(&s2_lower))
            }
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(s2) => {
                // We lowercase as LDAP and similar expect case insensitive searches here.
                let s2_lower = s2.to_lowercase();
                self.set
                    .iter()
                    .any(|s1| s1.to_lowercase().ends_with(&s2_lower))
            }
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
        SyntaxType::Utf8String
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
        DbValueSetV2::Utf8(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().map(|i| PartialValue::new_utf8s(i.as_str())))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().map(|i| Value::new_utf8s(i.as_str())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_utf8_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_utf8_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_utf8_single(&self) -> Option<&str> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next().map(|s| s.as_str())
        } else {
            None
        }
    }

    fn as_utf8_set(&self) -> Option<&BTreeSet<String>> {
        Some(&self.set)
    }

    fn as_utf8_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        Some(Box::new(self.set.iter().map(|s| s.as_str())))
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetUtf8;
    use crate::prelude::{PartialValue, ValueSet, ValueSetT};

    #[test]
    fn test_utf8_substring_insensitive() {
        let vs = ValueSetUtf8::new("Test User".to_string());

        let pv_xx = PartialValue::Utf8("xx".to_string());
        let pv_test = PartialValue::Utf8("test".to_string());
        let pv_user = PartialValue::Utf8("usEr".to_string());

        assert!(!vs.substring(&pv_xx));
        assert!(vs.substring(&pv_test));
        assert!(vs.substring(&pv_user));

        assert!(!vs.startswith(&pv_xx));
        assert!(vs.startswith(&pv_test));
        assert!(!vs.startswith(&pv_user));

        assert!(!vs.endswith(&pv_xx));
        assert!(!vs.endswith(&pv_test));
        assert!(vs.endswith(&pv_user));
    }

    #[test]
    fn test_scim_utf8() {
        let vs: ValueSet = ValueSetUtf8::new("Test".to_string());
        crate::valueset::scim_json_reflexive(vs, r#""Test""#);
    }
}

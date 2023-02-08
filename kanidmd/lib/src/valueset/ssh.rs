use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use crate::be::dbvalue::DbValueTaggedStringV1;
use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetSshKey {
    map: BTreeMap<String, String>,
}

impl ValueSetSshKey {
    pub fn new(t: String, k: String) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, k);
        Box::new(ValueSetSshKey { map })
    }

    pub fn push(&mut self, t: String, k: String) -> bool {
        self.map.insert(t, k).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueTaggedStringV1>) -> Result<ValueSet, OperationError> {
        let map = data.into_iter().map(|dbv| (dbv.tag, dbv.data)).collect();
        Ok(Box::new(ValueSetSshKey { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, String)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetSshKey { map }))
    }
}

impl ValueSetT for ValueSetSshKey {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::SshKey(t, k) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(t) {
                    e.insert(k);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::SshKey(t) => self.map.remove(t.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::SshKey(t) => self.map.contains_key(t.as_str()),
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
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::SshKey
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::SshKey(
            self.map
                .iter()
                .map(|(tag, key)| DbValueTaggedStringV1 {
                    tag: tag.clone(),
                    data: key.clone(),
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::SshKey {
            set: self
                .map
                .iter()
                .map(|(tag, key)| (tag.clone(), key.clone()))
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::SshKey))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(t, k)| Value::SshKey(t.clone(), k.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_sshkey_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_sshkey_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_sshkey_map(&self) -> Option<&BTreeMap<String, String>> {
        Some(&self.map)
    }

    fn get_ssh_tag(&self, tag: &str) -> Option<&str> {
        self.map.get(tag).map(|s| s.as_str())
    }

    fn as_sshpubkey_str_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        Some(Box::new(self.map.values().map(|s| s.as_str())))
    }
}

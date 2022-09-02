use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::DbValueSetV2;
use crate::valueset::ValueSet;
use std::collections::BTreeSet;

use crate::be::dbvalue::DbValueOauthScopeMapV1;
use crate::valueset::uuid_to_proto_string;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use crate::value::OAUTHSCOPE_RE;

#[derive(Debug, Clone)]
pub struct ValueSetOauthScope {
    set: BTreeSet<String>,
}

impl ValueSetOauthScope {
    pub fn new(s: String) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s);
        Box::new(ValueSetOauthScope { set })
    }

    pub fn push(&mut self, s: String) -> bool {
        self.set.insert(s)
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetOauthScope { set }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = String>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetOauthScope { set }))
    }
}

impl ValueSetT for ValueSetOauthScope {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::OauthScope(s) => Ok(self.set.insert(s)),
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
            PartialValue::OauthScope(s) => self.set.remove(s.as_str()),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::OauthScope(s) => self.set.contains(s.as_str()),
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
        self.set.iter().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::OauthScope
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.iter().all(|s| OAUTHSCOPE_RE.is_match(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().cloned())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::OauthScope(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::OauthScope))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::OauthScope))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_oauthscope_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_oauthscope_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    /*
    fn to_oauthscope_single(&self) -> Option<&str> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next().map(|s| s.as_str())
        } else {
            None
        }
    }
    */

    fn as_oauthscope_set(&self) -> Option<&BTreeSet<String>> {
        Some(&self.set)
    }

    fn as_oauthscope_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        Some(Box::new(self.set.iter().map(|s| s.as_str())))
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetOauthScopeMap {
    map: BTreeMap<Uuid, BTreeSet<String>>,
}

impl ValueSetOauthScopeMap {
    pub fn new(u: Uuid, m: BTreeSet<String>) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, m);
        Box::new(ValueSetOauthScopeMap { map })
    }

    pub fn push(&mut self, u: Uuid, m: BTreeSet<String>) -> bool {
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueOauthScopeMapV1>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|dbv| {
                let u = dbv.refer;
                let m = dbv.data.into_iter().collect();
                (u, m)
            })
            .collect();
        Ok(Box::new(ValueSetOauthScopeMap { map }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, BTreeSet<String>)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetOauthScopeMap { map }))
    }
}

impl ValueSetT for ValueSetOauthScopeMap {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::OauthScopeMap(u, m) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(m);
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
            PartialValue::OauthScopeMap(u) | PartialValue::Refer(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::OauthScopeMap(u) | PartialValue::Refer(u) => self.map.contains_key(u),
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
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::OauthScopeMap
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .values()
            .flat_map(|set| set.iter())
            .all(|s| OAUTHSCOPE_RE.is_match(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| format!("{}: {:?}", uuid_to_proto_string(*u), m)),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::OauthScopeMap(
            self.map
                .iter()
                .map(|(u, m)| DbValueOauthScopeMapV1 {
                    refer: *u,
                    data: m.iter().cloned().collect(),
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::OauthScopeMap))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| Value::OauthScopeMap(*u, m.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_oauthscopemap() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_oauthscopemap() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_oauthscopemap(&self) -> Option<&BTreeMap<Uuid, BTreeSet<String>>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(self.map.keys().copied()))
    }
}

use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet};

use crate::be::dbvalue::DbValueOauthScopeMapV1;
use crate::prelude::*;
use crate::repl::proto::{ReplAttrV1, ReplOauthScopeMapV1};
use crate::schema::SchemaAttribute;
use crate::value::OAUTHSCOPE_RE;
use crate::valueset::{uuid_to_proto_string, DbValueSetV2, ValueSet};

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

    pub fn from_repl_v1(data: &[String]) -> Result<ValueSet, OperationError> {
        let set = data.iter().cloned().collect();
        Ok(Box::new(ValueSetOauthScope { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and String is foreign.
    #[allow(clippy::should_implement_trait)]
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::OauthScope {
            set: self.set.iter().cloned().collect(),
        }
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
            .map(|DbValueOauthScopeMapV1 { refer, data }| (refer, data.into_iter().collect()))
            .collect();
        Ok(Box::new(ValueSetOauthScopeMap { map }))
    }

    pub fn from_repl_v1(data: &[ReplOauthScopeMapV1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .map(|ReplOauthScopeMapV1 { refer, data }| (*refer, data.clone()))
            .collect();
        Ok(Box::new(ValueSetOauthScopeMap { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
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
                match self.map.entry(u) {
                    BTreeEntry::Vacant(e) => {
                        e.insert(m);
                        Ok(true)
                    }
                    // In the case that the value already exists, we update it. This is a quirk
                    // of the oauth2 scope map type where add_ava assumes that a value's entire state
                    // will be reflected, but we were only checking the *uuid* existed, not it's
                    // associated map state. So by always replacing on a present, we are true to
                    // the intent of the api.
                    BTreeEntry::Occupied(mut e) => {
                        e.insert(m);
                        Ok(true)
                    }
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.contains_key(u),
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

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::OauthScopeMap {
            set: self
                .map
                .iter()
                .map(|(u, m)| ReplOauthScopeMapV1 {
                    refer: *u,
                    data: m.iter().cloned().collect(),
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
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

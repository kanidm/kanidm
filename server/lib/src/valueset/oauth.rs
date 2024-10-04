use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet};

use crate::be::dbvalue::{DbValueOauthClaimMap, DbValueOauthScopeMapV1};
use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::utils::str_join;
use crate::value::{OauthClaimMapJoin, OAUTHSCOPE_RE};
use crate::valueset::{uuid_to_proto_string, DbValueSetV2, ValueSet};

use kanidm_proto::scim_v1::server::ScimOAuth2ClaimMap;
use kanidm_proto::scim_v1::server::ScimOAuth2ScopeMap;

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

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        Some(str_join(&self.set).into())
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
            .map(|DbValueOauthScopeMapV1 { refer, data }| (refer, data.into_iter().collect()))
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

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        Some(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(uuid, scopes)| {
                    ScimOAuth2ScopeMap {
                        uuid: *uuid,
                        // Flattened to a space separated list.
                        scopes: scopes.clone(),
                    }
                })
                .collect::<Vec<_>>(),
        ))
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

#[derive(Debug, Clone, PartialEq)]
pub struct OauthClaimMapping {
    join: OauthClaimMapJoin,
    values: BTreeMap<Uuid, BTreeSet<String>>,
}

impl OauthClaimMapping {
    pub(crate) fn join(&self) -> OauthClaimMapJoin {
        self.join
    }

    pub(crate) fn values(&self) -> &BTreeMap<Uuid, BTreeSet<String>> {
        &self.values
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetOauthClaimMap {
    //            Claim Name
    map: BTreeMap<String, OauthClaimMapping>,
}

impl ValueSetOauthClaimMap {
    pub(crate) fn new(claim: String, join: OauthClaimMapJoin) -> Box<Self> {
        let mapping = OauthClaimMapping {
            join,
            values: BTreeMap::default(),
        };
        let mut map = BTreeMap::new();
        map.insert(claim, mapping);
        Box::new(ValueSetOauthClaimMap { map })
    }

    pub(crate) fn new_value(claim: String, group: Uuid, claims: BTreeSet<String>) -> Box<Self> {
        let mut values = BTreeMap::default();
        values.insert(group, claims);

        let mapping = OauthClaimMapping {
            join: OauthClaimMapJoin::default(),
            values,
        };

        let mut map = BTreeMap::new();
        map.insert(claim, mapping);
        Box::new(ValueSetOauthClaimMap { map })
    }

    pub(crate) fn from_dbvs2(data: Vec<DbValueOauthClaimMap>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|db_claim_map| match db_claim_map {
                DbValueOauthClaimMap::V1 { name, join, values } => (
                    name.clone(),
                    OauthClaimMapping {
                        join: join.into(),
                        values: values.clone(),
                    },
                ),
            })
            .collect();
        Ok(Box::new(ValueSetOauthClaimMap { map }))
    }

    fn trim(&mut self) {
        self.map
            .values_mut()
            .for_each(|mapping_mut| mapping_mut.values.retain(|_k, v| !v.is_empty()));

        self.map.retain(|_k, v| !v.values.is_empty());
    }
}

impl ValueSetT for ValueSetOauthClaimMap {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::OauthClaimValue(name, uuid, claims) => {
                // Add a value to this group associated to this claim.
                match self.map.entry(name) {
                    BTreeEntry::Vacant(e) => {
                        // New map/value. Use a default joiner.
                        let mut values = BTreeMap::default();
                        values.insert(uuid, claims);

                        let claim_map = OauthClaimMapping {
                            join: OauthClaimMapJoin::default(),
                            values,
                        };
                        e.insert(claim_map);
                        Ok(true)
                    }
                    BTreeEntry::Occupied(mut e) => {
                        // Just add the uuid/value, this claim name already exists.
                        let mapping_mut = e.get_mut();
                        match mapping_mut.values.entry(uuid) {
                            BTreeEntry::Vacant(e) => {
                                e.insert(claims);
                                Ok(true)
                            }
                            BTreeEntry::Occupied(mut e) => {
                                e.insert(claims);
                                Ok(true)
                            }
                        }
                    }
                }
            }
            Value::OauthClaimMap(name, join) => {
                match self.map.entry(name) {
                    BTreeEntry::Vacant(e) => {
                        // Create a new empty claim mapping.
                        let claim_map = OauthClaimMapping {
                            join,
                            values: BTreeMap::default(),
                        };
                        e.insert(claim_map);
                        Ok(true)
                    }
                    BTreeEntry::Occupied(mut e) => {
                        // Just update the join strategy.
                        e.get_mut().join = join;
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
        let res = match pv {
            // Remove this claim as a whole
            PartialValue::Iutf8(s) => self.map.remove(s).is_some(),
            // Remove all references to this group from this claim map.
            PartialValue::Refer(u) => {
                let mut contained = false;
                for mapping_mut in self.map.values_mut() {
                    contained |= mapping_mut.values.remove(u).is_some();
                }
                contained
            }
            PartialValue::OauthClaim(s, u) => {
                // Remove a uuid from this claim type.
                if let Some(mapping_mut) = self.map.get_mut(s) {
                    mapping_mut.values.remove(u).is_some()
                } else {
                    false
                }
            }
            PartialValue::OauthClaimValue(s, u, v) => {
                // Remove a value from this uuid, associated to this claim name.
                if let Some(mapping_mut) = self.map.get_mut(s) {
                    if let Some(claim_mut) = mapping_mut.values.get_mut(u) {
                        claim_mut.remove(v)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        // Trim anything that is now empty.
        self.trim();

        res
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Iutf8(s) => self.map.contains_key(s),
            PartialValue::Refer(u) => {
                let mut contained = false;
                for mapping in self.map.values() {
                    contained |= mapping.values.contains_key(u);
                }
                contained
            }
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
            .cloned()
            .chain(
                self.map.values().flat_map(|mapping| {
                    mapping.values.keys().map(|u| u.as_hyphenated().to_string())
                }),
            )
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::OauthClaimMap
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map.keys().all(|s| OAUTHSCOPE_RE.is_match(s))
            && self
                .map
                .values()
                .flat_map(|mapping| {
                    mapping
                        .values
                        .values()
                        .map(|claim_values| claim_values.is_empty())
                })
                .all(|is_empty| !is_empty)
            && self
                .map
                .values()
                .flat_map(|mapping| {
                    mapping
                        .values
                        .values()
                        .flat_map(|claim_values| claim_values.iter())
                })
                .all(|s| OAUTHSCOPE_RE.is_match(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().flat_map(|(name, mapping)| {
            mapping.values.iter().map(move |(group, claims)| {
                let join_str = mapping.join.to_str();

                let joined = str_concat!(claims, join_str);

                format!(
                    "{}: {} \"{:?}\"",
                    name,
                    uuid_to_proto_string(*group),
                    joined
                )
            })
        }))
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        Some(ScimValueKanidm::from(
            self.map
                .iter()
                .flat_map(|(claim_name, mappings)| {
                    mappings
                        .values
                        .iter()
                        .map(|(group_uuid, claim_values)| ScimOAuth2ClaimMap {
                            group: *group_uuid,
                            claim: claim_name.to_string(),
                            join_char: mappings.join.to_str().to_string(),
                            values: claim_values.clone(),
                        })
                })
                .collect::<Vec<_>>(),
        ))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::OauthClaimMap(
            self.map
                .iter()
                .map(|(name, mapping)| DbValueOauthClaimMap::V1 {
                    name: name.clone(),
                    join: mapping.join.into(),
                    values: mapping.values.clone(),
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Iutf8))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        debug_assert!(false);
        Box::new(
            std::iter::empty(), /*
                                self.map
                                    .iter()
                                    .map(|(u, m)| Value::OauthScopeMap(*u, m.clone())),
                                */
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_oauthclaim_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_oauthclaim_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_oauthclaim_map(&self) -> Option<&BTreeMap<String, OauthClaimMapping>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(
            self.map
                .values()
                .flat_map(|mapping| mapping.values.keys())
                .copied(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueSetOauthClaimMap, ValueSetOauthScope, ValueSetOauthScopeMap};
    use crate::prelude::ValueSet;
    use crate::valueset::ValueSetT;
    use std::collections::BTreeSet;

    #[test]
    fn test_oauth_claim_invalid_str_concat_when_empty() {
        let group_uuid = uuid::uuid!("5a6b8783-3f67-4ebb-b6aa-77fd6e66589f");
        let vs =
            ValueSetOauthClaimMap::new_value("claim".to_string(), group_uuid, BTreeSet::default());

        // Invalid handling of an empty claim map would cause a crash.
        let proto_value = vs.to_proto_string_clone_iter().next().unwrap();

        assert_eq!(
            &proto_value,
            "claim: 5a6b8783-3f67-4ebb-b6aa-77fd6e66589f \"\"\"\""
        );
    }

    #[test]
    fn test_scim_oauth2_scope() {
        let vs: ValueSet = ValueSetOauthScope::new("fully_sick_scope_m8".to_string());
        let data = r#""fully_sick_scope_m8""#;
        crate::valueset::scim_json_reflexive(vs, data);
    }

    #[test]
    fn test_scim_oauth2_scope_map() {
        let u = uuid::uuid!("3a163ca0-4762-4620-a188-06b750c84c86");
        let set = ["read".to_string(), "write".to_string()].into();
        let vs: ValueSet = ValueSetOauthScopeMap::new(u, set);

        let data = r#"
[
  {
    "scopes": "read write",
    "uuid": "3a163ca0-4762-4620-a188-06b750c84c86"
  }
]
        "#;
        crate::valueset::scim_json_reflexive(vs, data);
    }

    #[test]
    fn test_scim_oauth2_claim_map() {
        let u = uuid::uuid!("3a163ca0-4762-4620-a188-06b750c84c86");
        let set = ["read".to_string(), "write".to_string()].into();
        let vs: ValueSet = ValueSetOauthClaimMap::new_value("claim".to_string(), u, set);

        let data = r#"
[
  {
    "claim": "claim",
    "group": "3a163ca0-4762-4620-a188-06b750c84c86",
    "joinChar": ";",
    "values": "read write"
  }
]
        "#;
        crate::valueset::scim_json_reflexive(vs, data);
    }
}

use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::uuid_to_proto_string;
use crate::valueset::DbValueSetV2;
use crate::valueset::ValueSet;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use crate::be::dbvalue::{DbValueCredV1, DbValueIntentTokenStateV1};
use crate::credential::Credential;
use crate::valueset::IntentTokenState;

#[derive(Debug, Clone)]
pub struct ValueSetCredential {
    map: BTreeMap<String, Credential>,
}

impl ValueSetCredential {
    pub fn new(t: String, c: Credential) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, c);
        Box::new(ValueSetCredential { map })
    }

    pub fn push(&mut self, t: String, c: Credential) -> bool {
        self.map.insert(t, c).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueCredV1>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|dc| {
                let t = dc.tag.clone();
                Credential::try_from(dc.data)
                    .map_err(|()| OperationError::InvalidValueState)
                    .map(|c| (t, c))
            })
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetCredential { map }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, Credential)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetCredential { map }))
    }
}

impl ValueSetT for ValueSetCredential {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Cred(t, c) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(t) {
                    e.insert(c);
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
            PartialValue::Cred(t) => self.map.remove(t.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Cred(t) => self.map.contains_key(t.as_str()),
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
        SyntaxType::Credential
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Credential(
            self.map
                .iter()
                .map(|(tag, cred)| DbValueCredV1 {
                    tag: tag.clone(),
                    data: cred.to_db_valuev1(),
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Cred))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(t, c)| Value::Cred(t.clone(), c.clone())),
        )
    }

    fn equal(&self, _other: &ValueSet) -> bool {
        // Looks like we may not need this?
        false
        /*
        if let Some(other) = other.as_credential_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
        */
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_credential_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_credential_single(&self) -> Option<&Credential> {
        if self.map.len() == 1 {
            self.map.values().take(1).next()
        } else {
            None
        }
    }

    fn as_credential_map(&self) -> Option<&BTreeMap<String, Credential>> {
        Some(&self.map)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetIntentToken {
    map: BTreeMap<Uuid, IntentTokenState>,
}

impl ValueSetIntentToken {
    pub fn new(t: Uuid, s: IntentTokenState) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, s);
        Box::new(ValueSetIntentToken { map })
    }

    pub fn push(&mut self, t: Uuid, s: IntentTokenState) -> bool {
        self.map.insert(t, s).is_none()
    }

    pub fn from_dbvs2(
        data: Vec<(Uuid, DbValueIntentTokenStateV1)>,
    ) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|(u, dits)| {
                let ts = match dits {
                    DbValueIntentTokenStateV1::Valid => IntentTokenState::Valid,
                    DbValueIntentTokenStateV1::InProgress(pu, pd) => {
                        IntentTokenState::InProgress(pu, pd)
                    }
                    DbValueIntentTokenStateV1::Consumed => IntentTokenState::Consumed,
                };
                (u, ts)
            })
            .collect();
        Ok(Box::new(ValueSetIntentToken { map }))
    }

    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, IntentTokenState)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetIntentToken { map }))
    }
}

impl ValueSetT for ValueSetIntentToken {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::IntentToken(u, s) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(s);
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
            PartialValue::IntentToken(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::IntentToken(u) => self.map.contains_key(u),
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
        SyntaxType::IntentToken
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| format!("{}: {:?}", uuid_to_proto_string(*u), m)),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::IntentToken(
            self.map
                .iter()
                .map(|(u, s)| {
                    (
                        *u,
                        match s {
                            IntentTokenState::Valid => DbValueIntentTokenStateV1::Valid,
                            IntentTokenState::InProgress(i, d) => {
                                DbValueIntentTokenStateV1::InProgress(*i, *d)
                            }
                            IntentTokenState::Consumed => DbValueIntentTokenStateV1::Consumed,
                        },
                    )
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::IntentToken))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, s)| Value::IntentToken(u.clone(), s.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_intenttoken_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_intenttoken_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_intenttoken_map(&self) -> Option<&BTreeMap<Uuid, IntentTokenState>> {
        Some(&self.map)
    }
}

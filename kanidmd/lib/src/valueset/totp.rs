use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use crate::credential::totp::Totp;
use crate::prelude::*;

use crate::be::dbvalue::DbTotpV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetTotpSecret {
    map: BTreeMap<String, Totp>,
}

impl ValueSetTotpSecret {
    pub fn new(l: String, t: Totp) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(l, t);
        Box::new(ValueSetTotpSecret { map })
    }

    pub fn push(&mut self, l: String, t: Totp) -> bool {
        self.map.insert(l, t).is_none()
    }

    pub fn from_dbvs2(data: Vec<(String, DbTotpV1)>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|(l, data)| {
                Totp::try_from(data)
                    .map_err(|()| OperationError::InvalidValueState)
                    .map(|t| (l, t))
            })
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetTotpSecret { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, Totp)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetTotpSecret { map }))
    }
}

impl ValueSetT for ValueSetTotpSecret {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::TotpSecret(l, t) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(l) {
                    e.insert(t);
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
            PartialValue::Utf8(l) => self.map.remove(l.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(l) => self.map.contains_key(l.as_str()),
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
        SyntaxType::TotpSecret
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::TotpSecret(
            self.map
                .iter()
                .map(|(label, totp)| (label.clone(), totp.to_dbtotpv1()))
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Utf8))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(l, t)| Value::TotpSecret(l.clone(), t.clone())),
        )
    }

    fn equal(&self, _other: &ValueSet) -> bool {
        // Looks like we may not need this?
        /*
        if let Some(other) = other.as_credential_map() {
            &self.map == other
        } else {
            // debug_assert!(false);
            false
        }
        */
        debug_assert!(false);
        false
    }

    fn merge(&mut self, _other: &ValueSet) -> Result<(), OperationError> {
        /*
        if let Some(b) = other.as_credential_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
        */

        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn as_totp_map(&self) -> Option<&BTreeMap<String, Totp>> {
        Some(&self.map)
    }
}

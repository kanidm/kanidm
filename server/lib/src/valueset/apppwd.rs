use crate::be::dbvalue::{DbValueApplicationPassword, DbValueSetV2};
use crate::credential::{apppwd::ApplicationPassword, Password};
use crate::prelude::*;
use crate::repl::proto::{ReplApplicationPassword, ReplAttrV1};
use crate::schema::SchemaAttribute;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ValueSetApplicationPassword {
    map: BTreeMap<Uuid, ApplicationPassword>,
}

impl ValueSetApplicationPassword {
    pub fn new(u: Uuid, ap: ApplicationPassword) -> Box<Self> {
        let mut map: BTreeMap<Uuid, ApplicationPassword> = BTreeMap::new();
        map.insert(u, ap);
        Box::new(ValueSetApplicationPassword { map })
    }

    pub fn from_repl_v1(data: &[ReplApplicationPassword]) -> Result<ValueSet, OperationError> {
        let mut map: BTreeMap<Uuid, ApplicationPassword> = BTreeMap::new();
        for ap in data {
            let ap = match ap {
                ReplApplicationPassword::V1 {
                    refer,
                    application_refer,
                    label,
                    password,
                } => ApplicationPassword {
                    uuid: *refer,
                    application: *application_refer,
                    label: label.to_string(),
                    password: Password::try_from(password).expect("Failed to parse"),
                },
            };
            map.insert(ap.uuid, ap);
        }
        Ok(Box::new(ValueSetApplicationPassword { map }))
    }
}

impl ValueSetT for ValueSetApplicationPassword {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::ApplicationPassword(u, ap) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(ap);
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::ApplicationPassword(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::ApplicationPassword(u) => self.map.contains_key(u),
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
        SyntaxType::ApplicationPassword
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map.iter().all(|(_, ap)| {
            Value::validate_str_escapes(ap.label.as_str())
                && Value::validate_singleline(ap.label.as_str())
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .values()
                .map(|ap| format!("App: {} Label: {}", ap.application, ap.label)),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::ApplicationPassword(
            self.map
                .iter()
                .map(|(u, ap)| DbValueApplicationPassword::V1 {
                    refer: *u,
                    application_refer: ap.application,
                    label: ap.label.clone(),
                    password: ap.password.to_dbpasswordv1(),
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::ApplicationPassword {
            set: self
                .map
                .iter()
                .map(|(u, ap)| ReplApplicationPassword::V1 {
                    refer: *u,
                    application_refer: ap.application,
                    label: ap.label.clone(),
                    password: ap.password.to_repl_v1(),
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.map
                .keys()
                .cloned()
                .map(PartialValue::ApplicationPassword),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, ap)| Value::ApplicationPassword(*u, ap.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_application_password_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_application_password_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_application_password_map(&self) -> Option<&BTreeMap<Uuid, ApplicationPassword>> {
        Some(&self.map)
    }
}

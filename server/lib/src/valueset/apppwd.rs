use crate::be::dbvalue::{DbValueApplicationPassword, DbValueSetV2};
use crate::credential::{apppwd::ApplicationPassword, Password};
use crate::prelude::*;
use crate::repl::proto::{ReplApplicationPassword, ReplAttrV1};
use crate::schema::SchemaAttribute;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ValueSetApplicationPassword {
    // The map key is application's UUID
    // The value is a vector instead of BTreeSet to use
    // PartialValue::Refer instead of having to implement
    // PartialValue::ApplicationPassword. For example
    // btreeset.remove takes a full ApplicationPassword
    // struct.
    map: BTreeMap<Uuid, Vec<ApplicationPassword>>,
}

impl ValueSetApplicationPassword {
    pub fn new(ap: ApplicationPassword) -> Box<Self> {
        let mut map: BTreeMap<Uuid, Vec<ApplicationPassword>> = BTreeMap::new();
        map.entry(ap.application).or_default().push(ap);
        Box::new(ValueSetApplicationPassword { map })
    }

    pub fn from_dbvs2(data: Vec<DbValueApplicationPassword>) -> Result<ValueSet, OperationError> {
        let mut map: BTreeMap<Uuid, Vec<ApplicationPassword>> = BTreeMap::new();
        for ap in data {
            let ap = match ap {
                DbValueApplicationPassword::V1 {
                    refer,
                    application_refer,
                    label,
                    password,
                } => ApplicationPassword {
                    uuid: refer,
                    application: application_refer,
                    label,
                    password: Password::try_from(password).expect("Failed to parse"),
                },
            };
            map.entry(ap.application).or_default().push(ap);
        }
        Ok(Box::new(ValueSetApplicationPassword { map }))
    }

    pub fn from_repl_v1(data: &[ReplApplicationPassword]) -> Result<ValueSet, OperationError> {
        let mut map: BTreeMap<Uuid, Vec<ApplicationPassword>> = BTreeMap::new();
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
            map.entry(ap.application).or_default().push(ap);
        }
        Ok(Box::new(ValueSetApplicationPassword { map }))
    }
}

impl ValueSetT for ValueSetApplicationPassword {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::ApplicationPassword(_, ap) => {
                if self.map.values().any(|x| x.into_iter().any(|x| *x == ap)) {
                    // Don't allow duplicated labels for the same application.
                    // ApplicationPassword implements PartialEq to compare on
                    // uuid, label and application uuid.
                    Ok(false)
                } else {
                    let v = self.map.entry(ap.application);
                    v.or_default().push(ap);
                    Ok(true)
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
            PartialValue::Refer(u) => {
                // TODO Migrate to extract_if when available
                self.map.values_mut().any(|x| {
                    let prev = x.into_iter().count();
                    x.retain(|y| y.uuid != *u);
                    let post = x.into_iter().count();
                    post < prev
                    // TODO Drop KV pair if vec empty
                })
            }
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self
                .map
                .values()
                .any(|x| x.into_iter().any(|y| y.uuid == *u)),
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
        self.map.iter().all(|(_, v)| {
            v.into_iter().all(|ap| {
                Value::validate_str_escapes(ap.label.as_str())
                    && Value::validate_singleline(ap.label.as_str())
            })
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().flat_map(|(_, v)| {
            v.into_iter()
                .map(|ap| format!("App: {} Label: {}", ap.application, ap.label))
        }))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::ApplicationPassword(
            self.map
                .iter()
                .flat_map(|(_, v)| {
                    v.into_iter().map(|ap| DbValueApplicationPassword::V1 {
                        refer: ap.uuid,
                        application_refer: ap.application,
                        label: ap.label.clone(),
                        password: ap.password.to_dbpasswordv1(),
                    })
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::ApplicationPassword {
            set: self
                .map
                .iter()
                .flat_map(|(_, v)| {
                    v.into_iter().map(|ap| ReplApplicationPassword::V1 {
                        refer: ap.uuid,
                        application_refer: ap.application,
                        label: ap.label.clone(),
                        password: ap.password.to_repl_v1(),
                    })
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.map
                .iter()
                .flat_map(|(_, v)| v.into_iter().map(|ap| ap.uuid))
                .map(PartialValue::Refer),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.iter().flat_map(|(_, v)| {
            v.into_iter()
                .map(|ap| Value::ApplicationPassword(ap.uuid, ap.clone()))
        }))
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

    fn as_application_password_map(&self) -> Option<&BTreeMap<Uuid, Vec<ApplicationPassword>>> {
        Some(&self.map)
    }
}

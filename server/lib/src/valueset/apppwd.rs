use crate::be::dbvalue::{DbValueApplicationPassword, DbValueSetV2};
use crate::credential::{apppwd::ApplicationPassword, Password};
use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
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

    fn from_dbv_iter(
        data: impl Iterator<Item = DbValueApplicationPassword>,
    ) -> Result<ValueSet, OperationError> {
        let mut map: BTreeMap<Uuid, Vec<ApplicationPassword>> = BTreeMap::new();
        for ap in data {
            let ap = match ap {
                DbValueApplicationPassword::V1 {
                    refer,
                    application_refer,
                    label,
                    password,
                } => {
                    let password = Password::try_from(password)
                        .map_err(|()| OperationError::InvalidValueState)?;
                    ApplicationPassword {
                        uuid: refer,
                        application: application_refer,
                        label,
                        password,
                    }
                }
            };
            map.entry(ap.application).or_default().push(ap);
        }
        Ok(Box::new(ValueSetApplicationPassword { map }))
    }

    pub fn from_dbvs2(data: Vec<DbValueApplicationPassword>) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(data.into_iter())
    }

    pub fn from_repl_v1(data: &[DbValueApplicationPassword]) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(data.iter().cloned())
    }

    fn to_vec_dbvs(&self) -> Vec<DbValueApplicationPassword> {
        self.map
            .iter()
            .flat_map(|(_, v)| {
                v.iter().map(|ap| DbValueApplicationPassword::V1 {
                    refer: ap.uuid,
                    application_refer: ap.application,
                    label: ap.label.clone(),
                    password: ap.password.to_dbpasswordv1(),
                })
            })
            .collect()
    }
}

impl ValueSetT for ValueSetApplicationPassword {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::ApplicationPassword(ap) => {
                let application_entries = self.map.entry(ap.application).or_default();

                if let Some(application_entry) = application_entries
                    .iter_mut()
                    .find(|entry_app_password| *entry_app_password == &ap)
                {
                    // Overwrite on duplicated labels for the same application.
                    application_entry.password = ap.password;
                } else {
                    // Or just add it.
                    application_entries.push(ap);
                }
                Ok(true)
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
                // Deletes all passwords for the referred application
                self.map.remove(u).is_some()
            }
            PartialValue::Uuid(u) => {
                // Delete specific application password
                // TODO Migrate to extract_if when available
                let mut removed = false;
                self.map.retain(|_, v| {
                    let prev = v.len();
                    // Check the innel vec of passwords related to this application.
                    v.retain(|y| y.uuid != *u);
                    let post = v.len();
                    removed |= post < prev;
                    // Is the apppwd set for this application id now empty?
                    !v.is_empty()
                });
                removed
            }
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.map.values().any(|v| v.iter().any(|ap| ap.uuid == *u)),
            PartialValue::Refer(u) => self
                .map
                .values()
                .any(|v| v.iter().any(|ap| ap.application == *u)),
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
        let mut count = 0;
        for v in self.map.values() {
            count += v.len();
        }
        count
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
            v.iter().all(|ap| {
                Value::validate_str_escapes(ap.label.as_str())
                    && Value::validate_singleline(ap.label.as_str())
            })
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().flat_map(|(_, v)| {
            v.iter()
                .map(|ap| format!("App: {} Label: {}", ap.application, ap.label))
        }))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        let data = self.to_vec_dbvs();
        DbValueSetV2::ApplicationPassword(data)
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        let set = self.to_vec_dbvs();
        ReplAttrV1::ApplicationPassword { set }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.map
                .iter()
                .flat_map(|(_, v)| v.iter().map(|ap| ap.uuid))
                .map(PartialValue::Refer),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .flat_map(|(_, v)| v.iter().map(|ap| Value::ApplicationPassword(ap.clone()))),
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

    fn as_application_password_map(&self) -> Option<&BTreeMap<Uuid, Vec<ApplicationPassword>>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(self.map.keys().copied()))
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::{apppwd::ApplicationPassword, Password};
    use crate::prelude::*;
    use crate::valueset::ValueSetApplicationPassword;
    use kanidm_lib_crypto::CryptoPolicy;

    // Test the remove operation, removing all application passwords for an
    // applicaiton should also remove the KV pair.
    #[test]
    fn test_valueset_application_password_remove() {
        let app1_uuid = Uuid::new_v4();
        let app2_uuid = Uuid::new_v4();
        let ap1_uuid = Uuid::new_v4();
        let ap2_uuid = Uuid::new_v4();
        let ap3_uuid = Uuid::new_v4();

        let ap1: ApplicationPassword = ApplicationPassword {
            uuid: ap1_uuid,
            application: app1_uuid,
            label: "apppwd1".to_string(),
            password: Password::new_pbkdf2(&CryptoPolicy::minimum(), "apppwd1")
                .expect("Failed to create password"),
        };

        let ap2: ApplicationPassword = ApplicationPassword {
            uuid: ap2_uuid,
            application: app1_uuid,
            label: "apppwd2".to_string(),
            password: Password::new_pbkdf2(&CryptoPolicy::minimum(), "apppwd2")
                .expect("Failed to create password"),
        };

        let ap3: ApplicationPassword = ApplicationPassword {
            uuid: ap3_uuid,
            application: app2_uuid,
            label: "apppwd3".to_string(),
            password: Password::new_pbkdf2(&CryptoPolicy::minimum(), "apppwd3")
                .expect("Failed to create password"),
        };

        let mut vs: ValueSet = ValueSetApplicationPassword::new(ap1);
        assert_eq!(vs.len(), 1);

        let res = vs
            .insert_checked(Value::ApplicationPassword(ap2))
            .expect("Failed to insert");
        assert!(res);
        assert_eq!(vs.len(), 2);

        let res = vs
            .insert_checked(Value::ApplicationPassword(ap3))
            .expect("Failed to insert");
        assert!(res);
        assert_eq!(vs.len(), 3);

        let res = vs.remove(&PartialValue::Uuid(Uuid::new_v4()), &Cid::new_zero());
        assert!(!res);
        assert_eq!(vs.len(), 3);

        let res = vs.remove(&PartialValue::Uuid(ap1_uuid), &Cid::new_zero());
        assert!(res);
        assert_eq!(vs.len(), 2);

        let res = vs.remove(&PartialValue::Uuid(ap3_uuid), &Cid::new_zero());
        assert!(res);
        assert_eq!(vs.len(), 1);

        let res = vs.remove(&PartialValue::Uuid(ap2_uuid), &Cid::new_zero());
        assert!(res);
        assert_eq!(vs.len(), 0);

        let res = vs.as_application_password_map().unwrap();
        assert_eq!(res.keys().len(), 0);
    }
}

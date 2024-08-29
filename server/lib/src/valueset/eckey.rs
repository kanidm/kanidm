use std::iter::{self};

use crate::be::dbvalue::DbValueSetV2;
use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::value::{PartialValue, SyntaxType, Value};
use openssl::ec::EcKey;
use openssl::pkey::{Private, Public};

use super::ValueSet;

#[derive(Debug, Clone)]
struct EcKeyPrivate {
    priv_key: EcKey<Private>,
    pub_key: EcKey<Public>,
}

#[derive(Debug, Clone)]
pub struct ValueSetEcKeyPrivate {
    set: Option<EcKeyPrivate>,
}

impl ValueSetEcKeyPrivate {
    pub fn new(key: &EcKey<Private>) -> Box<Self> {
        #[allow(clippy::expect_used)]
        let pub_key = Self::private_key_to_public_key(key).expect(
            "Unable to retrieve public key from private key, likely corrupted. You must restore from backup.",
        );

        Box::new(ValueSetEcKeyPrivate {
            set: Some(EcKeyPrivate {
                priv_key: key.clone(),
                pub_key,
            }),
        })
    }

    fn push(&mut self, key: &EcKey<Private>) -> bool {
        #[allow(clippy::expect_used)]
        let pub_key = Self::private_key_to_public_key(key).expect(
            "Unable to retrieve public key from private key, likely corrupted. You must restore from backup.",
        );
        self.set = Some(EcKeyPrivate {
            priv_key: key.clone(),
            pub_key,
        });
        true
    }

    fn valueset_from_key_der(key_der: &[u8]) -> Result<ValueSet, OperationError> {
        let option_key = EcKey::private_key_from_der(key_der);
        if let Ok(key) = option_key {
            Ok(Self::new(&key))
        } else {
            Err(OperationError::InvalidDbState)
        }
    }

    fn private_key_to_public_key(private_key: &EcKey<Private>) -> Option<EcKey<Public>> {
        let public_key = private_key.public_key();
        let group = private_key.group();
        EcKey::from_public_key(group, public_key).ok()
    }

    pub fn from_dbvs2(key_der: &[u8]) -> Result<ValueSet, OperationError> {
        Self::valueset_from_key_der(key_der)
    }

    pub fn from_repl_v1(key_der: &[u8]) -> Result<ValueSet, OperationError> {
        Self::valueset_from_key_der(key_der)
    }
}

impl ValueSetT for ValueSetEcKeyPrivate {
    fn insert_checked(&mut self, value: crate::value::Value) -> Result<bool, OperationError> {
        match value {
            Value::EcKeyPrivate(k) => Ok(self.push(&k)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set = None;
    }

    fn remove(&mut self, _pv: &crate::value::PartialValue, _cid: &Cid) -> bool {
        false
    }

    fn contains(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn substring(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        1
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::EcKeyPrivate
    }

    fn validate(&self, _schema_attr: &crate::schema::SchemaAttribute) -> bool {
        match self.set.as_ref() {
            Some(key) => key.priv_key.check_key().is_ok() && key.pub_key.check_key().is_ok(),
            None => false,
        }
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(iter::once(String::from("hidden")))
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        None
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        #[allow(clippy::expect_used)]
        let key_der = self
            .set
            .as_ref()
            .map(|key| {
                key.priv_key.private_key_to_der().expect(
        "Unable to process eckey to der, likely corrupted. You must restore from backup.",
    )
            })
            .unwrap_or_default();
        DbValueSetV2::EcKeyPrivate(key_der)
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        #[allow(clippy::expect_used)]
        let key_der = self
            .set
            .as_ref()
            .map(|key| {
                key.priv_key.private_key_to_der().expect(
        "Unable to process eckey to der, likely corrupted. You must restore from backup.",
    )
            })
            .unwrap_or_default();
        ReplAttrV1::EcKeyPrivate { key: key_der }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = crate::value::PartialValue> + '_> {
        Box::new(iter::once(PartialValue::SecretValue))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = crate::value::Value> + '_> {
        match &self.set {
            Some(key) => Box::new(iter::once(Value::EcKeyPrivate(key.priv_key.clone()))),
            None => Box::new(iter::empty::<Value>()),
        }
    }

    fn equal(&self, other: &super::ValueSet) -> bool {
        #[allow(clippy::expect_used)]
        other.as_ec_key_private().map_or(false, |other_key| {
            self.set.as_ref().map_or(false, |key| {
                key.priv_key
                    .private_key_to_der()
                    .expect("Failed to retrieve key der")
                    == other_key
                        .private_key_to_der()
                        .expect("Failed to retrieve key der")
            })
        })
    }

    fn merge(&mut self, other: &super::ValueSet) -> Result<(), OperationError> {
        if let Some(other_key) = other.as_ec_key_private() {
            let priv_key = other_key.clone();
            let pub_key = Self::private_key_to_public_key(&priv_key)
                .ok_or(OperationError::CryptographyError)?;
            self.set = Some(EcKeyPrivate { pub_key, priv_key });
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_ec_key_private(&self) -> Option<&EcKey<Private>> {
        match self.set.as_ref() {
            Some(key) => Some(&key.priv_key),
            None => None,
        }
    }

    fn to_eckey_private_single(&self) -> Option<&EcKey<Private>> {
        match self.set.as_ref() {
            Some(key) => Some(&key.priv_key),
            None => None,
        }
    }

    fn to_eckey_public_single(&self) -> Option<&EcKey<Public>> {
        match self.set.as_ref() {
            Some(key) => Some(&key.pub_key),
            None => None,
        }
    }
}

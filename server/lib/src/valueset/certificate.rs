use crate::be::dbvalue::DbValueCertificate;
use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};
use std::collections::BTreeMap;

use kanidm_lib_crypto::{
    x509_cert::{
        der::{Decode, Encode, EncodePem},
        pem::LineEnding,
        x509_public_key_s256, Certificate,
    },
    Sha256Digest,
};

#[derive(Debug, Clone)]
pub struct ValueSetCertificate {
    map: BTreeMap<Sha256Digest, Box<Certificate>>,
}

impl ValueSetCertificate {
    pub fn new(certificate: Box<Certificate>) -> Result<Box<Self>, OperationError> {
        let mut map = BTreeMap::new();

        let pk_s256 = x509_public_key_s256(&certificate).ok_or_else(|| {
            error!("Unable to digest public key");
            OperationError::VS0002CertificatePublicKeyDigest
        })?;
        map.insert(pk_s256, certificate);

        Ok(Box::new(ValueSetCertificate { map }))
    }

    pub fn from_dbvs2(data: Vec<DbValueCertificate>) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(data.into_iter())
    }

    pub fn from_repl_v1(data: &[DbValueCertificate]) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(data.iter().cloned())
    }

    fn from_dbv_iter(
        certs: impl Iterator<Item = DbValueCertificate>,
    ) -> Result<ValueSet, OperationError> {
        let mut map = BTreeMap::new();

        for db_cert in certs {
            match db_cert {
                DbValueCertificate::V1 { certificate_der } => {
                    // Parse the DER
                    let certificate = Certificate::from_der(&certificate_der)
                        .map(Box::new)
                        .map_err(|x509_err| {
                            error!(?x509_err, "Unable to restore certificate from DER");
                            OperationError::VS0003CertificateDerDecode
                        })?;

                    // sha256 the public key
                    let pk_s256 = x509_public_key_s256(&certificate).ok_or_else(|| {
                        error!("Unable to digest public key");
                        OperationError::VS0004CertificatePublicKeyDigest
                    })?;

                    map.insert(pk_s256, certificate);
                }
            }
        }

        Ok(Box::new(ValueSetCertificate { map }))
    }

    fn to_vec_dbvs(&self) -> Vec<DbValueCertificate> {
        self.map
            .iter()
            .filter_map(|(pk_s256, cert)| {
                cert.to_der()
                    .map_err(|der_err| {
                        error!(
                            ?pk_s256,
                            ?der_err,
                            "Failed to serialise certificate to der. This value will be dropped!"
                        );
                    })
                    .ok()
            })
            .map(|certificate_der| DbValueCertificate::V1 { certificate_der })
            .collect()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Box<Certificate>>,
    {
        let mut map = BTreeMap::new();

        for certificate in iter {
            let pk_s256 = x509_public_key_s256(&certificate)?;
            map.insert(pk_s256, certificate);
        }

        Some(Box::new(ValueSetCertificate { map }))
    }
}

impl ValueSetT for ValueSetCertificate {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Certificate(certificate) => {
                let pk_s256 = x509_public_key_s256(&certificate).ok_or_else(|| {
                    error!("Unable to digest public key");
                    OperationError::VS0005CertificatePublicKeyDigest
                })?;

                // bool -> true if the insert did not trigger a duplicate.
                Ok(self.map.insert(pk_s256, certificate).is_none())
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::HexString(hs) => {
                let mut buf = Sha256Digest::default();
                if hex::decode_to_slice(hs, &mut buf).is_ok() {
                    self.map.remove(&buf).is_some()
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(hs) => {
                let mut buf = Sha256Digest::default();
                if hex::decode_to_slice(hs, &mut buf).is_ok() {
                    self.map.contains_key(&buf)
                } else {
                    false
                }
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
        self.map.keys().map(hex::encode).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Certificate
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().filter_map(|(pk_s256, cert)| {
            cert.to_pem(LineEnding::LF)
                .ok()
                .map(|pem| format!("{}\n{}", hex::encode(pk_s256), pem))
        }))
    }

    fn to_scim_value(&self) -> ScimValue {
        todo!();
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        let data = self.to_vec_dbvs();
        DbValueSetV2::Certificate(data)
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        let set = self.to_vec_dbvs();
        ReplAttrV1::Certificate { set }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.map
                .keys()
                .map(hex::encode)
                .map(PartialValue::HexString),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.values().cloned().map(Value::Certificate))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_certificate_set() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_certificate_set() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_certificate_single(&self) -> Option<&Certificate> {
        if self.map.len() == 1 {
            self.map.values().take(1).map(|b| b.as_ref()).next()
        } else {
            None
        }
    }

    fn as_certificate_set(&self) -> Option<&BTreeMap<Sha256Digest, Box<Certificate>>> {
        Some(&self.map)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetCertificate;
    use crate::prelude::{ScimValue, ValueSet};

    #[test]
    fn test_scim_certificate() {
        let vs: ValueSet = ValueSetCertificate::new(true);

        let scim_value = vs.to_scim_value();

        let strout = serde_json::to_string_pretty(&scim_value).unwrap();
        eprintln!("{}", strout);

        let expect: ScimValue = serde_json::from_str("true").unwrap();
        assert_eq!(scim_value, expect);
    }
}

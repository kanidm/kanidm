use crate::prelude::*;
use compact_jwt::{compact::JweCompact, jwe::Jwe};
use compact_jwt::{Jwk, Jws, JwsCompact};
use smolset::SmolSet;
use std::collections::BTreeSet;
use uuid::Uuid;

pub type KeyObject = Box<dyn KeyObjectT + Send + Sync + 'static>;

// currently only used in testing, so no need to to exist until then
#[cfg(test)]
pub type KeyObjectRef<'a> = &'a (dyn KeyObjectT + Send + Sync + 'static);

pub trait KeyObjectT {
    fn uuid(&self) -> Uuid;

    fn jws_es256_import(
        &mut self,
        import_keys: &SmolSet<[Vec<u8>; 1]>,
        valid_from: Duration,
        cid: &Cid,
    ) -> Result<(), OperationError>;

    fn jws_es256_assert(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError>;

    fn jws_es256_sign(
        &self,
        jws: &Jws,
        current_time: Duration,
    ) -> Result<JwsCompact, OperationError>;

    fn jws_verify(&self, jwsc: &JwsCompact) -> Result<Jws, OperationError>;

    fn jws_public_jwk(&self, kid: &str) -> Result<Option<Jwk>, OperationError>;

    fn jwe_a128gcm_assert(&mut self, valid_from: Duration, cid: &Cid)
        -> Result<(), OperationError>;

    fn jwe_a128gcm_encrypt(
        &self,
        jwe: &Jwe,
        current_time: Duration,
    ) -> Result<JweCompact, OperationError>;

    fn jwe_decrypt(&self, jwec: &JweCompact) -> Result<Jwe, OperationError>;

    fn into_valuesets(&self) -> Result<Vec<(Attribute, ValueSet)>, OperationError>;

    fn duplicate(&self) -> KeyObject;

    fn rotate_keys(&mut self, current_time: Duration, cid: &Cid) -> Result<(), OperationError>;

    fn revoke_keys(
        &mut self,
        revoke_set: &BTreeSet<String>,
        cid: &Cid,
    ) -> Result<(), OperationError>;

    #[cfg(test)]
    fn kid_status(
        &self,
        kid: &super::KeyId,
    ) -> Result<Option<crate::value::KeyStatus>, OperationError>;
}

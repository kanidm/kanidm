use crate::prelude::*;
use compact_jwt::{Jws, JwsCompact};
use std::collections::BTreeSet;
use uuid::Uuid;

pub type KeyObject = Box<dyn KeyObjectT + Send + Sync + 'static>;
pub type KeyObjectRef<'a> = &'a (dyn KeyObjectT + Send + Sync + 'static);

pub trait KeyObjectT {
    fn uuid(&self) -> Uuid;

    fn jws_es256_assert(&mut self, valid_from: Duration) -> Result<(), OperationError>;

    fn jws_es256_sign(
        &self,
        jws: &Jws,
        current_time: Duration,
    ) -> Result<JwsCompact, OperationError>;

    fn jws_verify(&self, jwsc: &JwsCompact) -> Result<Jws, OperationError>;

    fn into_valuesets(&self) -> Result<Vec<(Attribute, ValueSet)>, OperationError>;

    fn duplicate(&self) -> KeyObject;

    fn rotate_keys(&mut self, current_time: Duration) -> Result<(), OperationError>;

    fn revoke_keys(&mut self, revoke_set: &BTreeSet<String>) -> Result<(), OperationError>;

    #[cfg(test)]
    fn kid_status(
        &self,
        kid: &super::KeyId,
    ) -> Result<Option<crate::value::KeyStatus>, OperationError>;
}

use crate::prelude::*;
use compact_jwt::traits::*;
use compact_jwt::{Jws, JwsCompact};
use uuid::Uuid;

pub trait KeyObject {
    fn uuid(&self) -> Uuid;

    fn jws_es256_generate(&mut self, valid_from: Duration) -> Result<(), OperationError>;

    fn jws_es256_sign(
        &self,
        jws: &Jws,
        current_time: Duration,
    ) -> Result<JwsCompact, OperationError>;

    fn jws_verify(&self, jwsc: &JwsCompact) -> Result<Jws, OperationError>;

    fn into_valuesets(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(Attribute, ValueSet), OperationError>> + '_>;
}

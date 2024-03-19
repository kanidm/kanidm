use crate::prelude::*;
use uuid::Uuid;

pub trait KeyObject {
    fn uuid(&self) -> Uuid;

    fn jwt_es256_generate(&mut self, valid_from: Duration) -> Result<(), OperationError>;

    fn into_entry_new(&self) -> Result<EntryInitNew, OperationError>;
}

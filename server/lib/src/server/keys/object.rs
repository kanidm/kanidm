use crate::prelude::*;
use uuid::Uuid;

pub trait KeyObject {
    fn uuid(&self) -> Uuid;

    fn jwt_es256_generate(&mut self, valid_from: Duration) -> Result<(), OperationError>;

    fn update_entry_invalid_new(&self, entry: &mut EntryInvalidNew) -> Result<(), OperationError>;
}

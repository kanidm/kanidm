use crate::prelude::*;
use crate::credential::Password;

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationPassword {
    uuid: Uuid,
    pub application: Uuid,
    pub label: String,
    pub(crate) password: Password,
}

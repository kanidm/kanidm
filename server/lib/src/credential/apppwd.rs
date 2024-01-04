use crate::prelude::*;
use crate::credential::Password;

#[derive(Debug, Clone)]
pub struct ApplicationPassword {
    uuid: Uuid,
    application: Uuid,
    pub label: String,
    password: Password,
}

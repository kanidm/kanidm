use crate::credential::Password;
use crate::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationPassword {
    pub(crate) uuid: Uuid,
    pub(crate) application: Uuid,
    pub(crate) label: String,
    pub(crate) password: Password,
}

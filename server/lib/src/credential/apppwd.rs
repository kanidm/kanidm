use crate::credential::Password;
use crate::prelude::*;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct ApplicationPassword {
    pub(crate) uuid: Uuid,
    pub(crate) application: Uuid,
    pub(crate) label: String,
    pub(crate) password: Password,
}

impl PartialEq for ApplicationPassword {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
            || (self.application == other.application && self.label == other.label)
    }
}

impl Eq for ApplicationPassword {}

impl PartialOrd for ApplicationPassword {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uuid.partial_cmp(&other.uuid)
    }
}

impl Ord for ApplicationPassword {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

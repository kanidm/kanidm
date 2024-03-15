use crate::credential::{CryptoPolicy, Password};
use crate::prelude::*;
use std::cmp::Ordering;
use kanidm_proto::internal::OperationError;

#[derive(Debug, Clone)]
pub struct ApplicationPassword {
    pub uuid: Uuid,
    pub(crate) application: Uuid,
    pub(crate) label: String,
    pub(crate) password: Password,
}

impl ApplicationPassword {
    pub fn new(
        application: Uuid,
        label: &str,
        cleartext: &str,
        policy: &CryptoPolicy,
    ) -> Result<ApplicationPassword, OperationError> {
        let pw = Password::new(policy, cleartext).map_err(|e| {
            error!(crypto_err = ?e);
            e.into()
        })?;
        let ap = ApplicationPassword {
            uuid: Uuid::new_v4(),
            application,
            label: label.to_string(),
            password: pw,
        };
        Ok(ap)
    }
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

#[derive(Debug)]
pub struct GenerateApplicationPasswordEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub application: Uuid,
    pub label: String,
}

impl GenerateApplicationPasswordEvent {
    pub fn from_parts(
        ident: Identity,
        target: Uuid,
        application: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        Ok(GenerateApplicationPasswordEvent {
            ident,
            target,
            application,
            label,
        })
    }

    pub fn new_internal(target: Uuid, application: Uuid, label: String) -> Self {
        GenerateApplicationPasswordEvent {
            ident: Identity::from_internal(),
            target,
            application,
            label,
        }
    }
}

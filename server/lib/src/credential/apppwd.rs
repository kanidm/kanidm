use crate::credential::{CryptoPolicy, Password};
use crate::prelude::*;
use kanidm_proto::v1::OperationError;

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
    ) -> Result<ApplicationPassword, OperationError> {
        let p = CryptoPolicy::minimum();
        let pw = Password::new(&p, cleartext).map_err(|e| e.into())?;

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
        self.application == other.application && self.label == other.label
    }
}

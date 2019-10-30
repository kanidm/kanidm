use crate::actors::v1_write::IdmAccountSetPasswordMessage;
use crate::audit::AuditScope;
use crate::event::Event;
use crate::server::{QueryServerWriteTransaction, QueryServerReadTransaction};

use uuid::Uuid;

use kanidm_proto::v1::{OperationError, UserAuthToken};

#[derive(Debug)]
pub struct PasswordChangeEvent {
    pub event: Event,
    pub target: Uuid,
    pub cleartext: String,
    pub appid: Option<String>,
}

impl PasswordChangeEvent {
    pub fn new_internal(target: &Uuid, cleartext: &str, appid: Option<&str>) -> Self {
        PasswordChangeEvent {
            event: Event::from_internal(),
            target: target.clone(),
            cleartext: cleartext.to_string(),
            appid: appid.map(|v| v.to_string()),
        }
    }

    pub fn from_idm_account_set_password(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        msg: IdmAccountSetPasswordMessage,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, msg.uat)?;
        let u = e.get_uuid().ok_or(OperationError::InvalidState)?.clone();

        Ok(PasswordChangeEvent {
            event: e,
            target: u,
            cleartext: msg.cleartext,
            appid: None,
        })
    }

    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<UserAuthToken>,
        target: Uuid,
        cleartext: String,
        appid: Option<String>,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(PasswordChangeEvent {
            event: e,
            target: target,
            cleartext: cleartext,
            appid: appid,
        })
    }
}

#[derive(Debug)]
pub struct GeneratePasswordEvent {
    pub event: Event,
    pub target: Uuid,
    pub appid: Option<String>,
}

impl GeneratePasswordEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<UserAuthToken>,
        target: Uuid,
        appid: Option<String>,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(GeneratePasswordEvent {
            event: e,
            target: target,
            appid: appid,
        })
    }
}

#[derive(Debug)]
pub struct RegenerateRadiusSecretEvent {
    pub event: Event,
    pub target: Uuid,
}

impl RegenerateRadiusSecretEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<UserAuthToken>,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(RegenerateRadiusSecretEvent {
            event: e,
            target: target,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        RegenerateRadiusSecretEvent {
            event: e,
            target: target,
        }
    }
}

#[derive(Debug)]
pub struct RadiusAuthTokenEvent {
    pub event: Event,
    pub target: Uuid,
}

impl RadiusAuthTokenEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<UserAuthToken>,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        let e = Event::from_ro_uat(audit, qs, uat)?;

        Ok(RadiusAuthTokenEvent {
            event: e,
            target: target,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        RadiusAuthTokenEvent {
            event: e,
            target: target,
        }
    }
}


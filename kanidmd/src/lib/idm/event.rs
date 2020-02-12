use crate::actors::v1_write::IdmAccountSetPasswordMessage;
use crate::audit::AuditScope;
use crate::event::Event;
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};

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
            target: *target,
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
        let u = *e.get_uuid().ok_or(OperationError::InvalidState)?;

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
            target,
            cleartext,
            appid,
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
            target,
            appid,
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

        Ok(RegenerateRadiusSecretEvent { event: e, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        RegenerateRadiusSecretEvent { event: e, target }
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

        Ok(RadiusAuthTokenEvent { event: e, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        RadiusAuthTokenEvent { event: e, target }
    }
}

#[derive(Debug)]
pub struct UnixUserTokenEvent {
    pub event: Event,
    pub target: Uuid,
}

impl UnixUserTokenEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<UserAuthToken>,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        let e = Event::from_ro_uat(audit, qs, uat)?;

        Ok(UnixUserTokenEvent { event: e, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        UnixUserTokenEvent { event: e, target }
    }
}

#[derive(Debug)]
pub struct UnixGroupTokenEvent {
    pub event: Event,
    pub target: Uuid,
}

impl UnixGroupTokenEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<UserAuthToken>,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        let e = Event::from_ro_uat(audit, qs, uat)?;

        Ok(UnixGroupTokenEvent { event: e, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        UnixGroupTokenEvent { event: e, target }
    }
}

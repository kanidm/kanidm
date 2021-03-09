use crate::actors::v1_write::IdmAccountSetPasswordMessage;
use crate::audit::AuditScope;
use crate::event::Event;
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};

use uuid::Uuid;

use kanidm_proto::v1::{OperationError, UserAuthToken};
use webauthn_rs::proto::RegisterPublicKeyCredential;

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
        let e = Event::from_rw_uat(audit, qs, msg.uat.as_ref())?;
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
        uat: Option<&UserAuthToken>,
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

pub struct UnixPasswordChangeEvent {
    pub event: Event,
    pub target: Uuid,
    pub cleartext: String,
}

impl UnixPasswordChangeEvent {
    #[cfg(test)]
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        UnixPasswordChangeEvent {
            event: Event::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
    }

    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        cleartext: String,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(UnixPasswordChangeEvent {
            event: e,
            target,
            cleartext,
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
        uat: Option<&UserAuthToken>,
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
        uat: Option<&UserAuthToken>,
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
        uat: Option<&UserAuthToken>,
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
        uat: Option<&UserAuthToken>,
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
        uat: Option<&UserAuthToken>,
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

pub struct UnixUserAuthEvent {
    pub event: Event,
    pub target: Uuid,
    pub cleartext: String,
}

impl std::fmt::Debug for UnixUserAuthEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("UnixUserAuthEvent")
            .field("event", &self.event)
            .field("target", &self.target)
            .finish()
    }
}

impl UnixUserAuthEvent {
    #[cfg(test)]
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        UnixUserAuthEvent {
            event: Event::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
    }

    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        cleartext: String,
    ) -> Result<Self, OperationError> {
        let e = Event::from_ro_uat(audit, qs, uat)?;

        Ok(UnixUserAuthEvent {
            event: e,
            target,
            cleartext,
        })
    }
}

#[derive(Debug)]
pub struct GenerateTOTPEvent {
    pub event: Event,
    pub target: Uuid,
    pub label: String,
}

impl GenerateTOTPEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(GenerateTOTPEvent {
            event: e,
            target,
            label,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        GenerateTOTPEvent {
            event: e,
            target,
            label: "internal_token".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct VerifyTOTPEvent {
    pub event: Event,
    pub target: Uuid,
    pub session: Uuid,
    pub chal: u32,
}

impl VerifyTOTPEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        session: Uuid,
        chal: u32,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(VerifyTOTPEvent {
            event: e,
            target,
            session,
            chal,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, session: Uuid, chal: u32) -> Self {
        let e = Event::from_internal();

        VerifyTOTPEvent {
            event: e,
            target,
            session,
            chal,
        }
    }
}

#[derive(Debug)]
pub struct RemoveTOTPEvent {
    pub event: Event,
    pub target: Uuid,
}

impl RemoveTOTPEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(RemoveTOTPEvent { event: e, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        RemoveTOTPEvent { event: e, target }
    }
}

#[derive(Debug)]
pub struct WebauthnInitRegisterEvent {
    pub event: Event,
    pub target: Uuid,
    pub label: String,
}

impl WebauthnInitRegisterEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(WebauthnInitRegisterEvent {
            event: e,
            target,
            label,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: String) -> Self {
        let e = Event::from_internal();
        WebauthnInitRegisterEvent {
            event: e,
            target,
            label,
        }
    }
}

#[derive(Debug)]
pub struct WebauthnDoRegisterEvent {
    pub event: Event,
    pub target: Uuid,
    pub session: Uuid,
    pub chal: RegisterPublicKeyCredential,
}

impl WebauthnDoRegisterEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        session: Uuid,
        chal: RegisterPublicKeyCredential,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(WebauthnDoRegisterEvent {
            event: e,
            target,
            session,
            chal,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, session: Uuid, chal: RegisterPublicKeyCredential) -> Self {
        let e = Event::from_internal();
        WebauthnDoRegisterEvent {
            event: e,
            target,
            session,
            chal,
        }
    }
}

#[derive(Debug)]
pub struct RemoveWebauthnEvent {
    pub event: Event,
    pub target: Uuid,
    pub label: String,
}

impl RemoveWebauthnEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        let e = Event::from_rw_uat(audit, qs, uat)?;

        Ok(RemoveWebauthnEvent {
            event: e,
            target,
            label,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: String) -> Self {
        let e = Event::from_internal();

        RemoveWebauthnEvent {
            event: e,
            target,
            label,
        }
    }
}

#[derive(Debug)]
pub struct CredentialStatusEvent {
    pub event: Event,
    pub target: Uuid,
}

impl CredentialStatusEvent {
    pub fn from_parts(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<&UserAuthToken>,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        let e = Event::from_ro_uat(audit, qs, uat)?;

        Ok(CredentialStatusEvent { event: e, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let e = Event::from_internal();

        CredentialStatusEvent { event: e, target }
    }
}

pub struct LdapAuthEvent {
    // pub event: Event,
    pub target: Uuid,
    pub cleartext: String,
}

impl LdapAuthEvent {
    /*
    #[cfg(test)]
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        LdapAuthEvent {
            // event: Event::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
    }
    */

    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &mut QueryServerReadTransaction,
        // uat: Option<UserAuthToken>,
        target: Uuid,
        cleartext: String,
    ) -> Result<Self, OperationError> {
        // let e = Event::from_ro_uat(audit, qs, uat)?;

        Ok(LdapAuthEvent {
            // event: e,
            target,
            cleartext,
        })
    }
}

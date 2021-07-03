use crate::prelude::*;

use uuid::Uuid;

use kanidm_proto::v1::OperationError;
use webauthn_rs::proto::RegisterPublicKeyCredential;

pub struct PasswordChangeEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub cleartext: String,
}

impl PasswordChangeEvent {
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        PasswordChangeEvent {
            ident: Identity::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
    }

    pub fn from_idm_account_set_password(
        _audit: &mut AuditScope,
        ident: Identity,
        cleartext: String,
        // qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let u = ident.get_uuid().ok_or(OperationError::InvalidState)?;

        Ok(PasswordChangeEvent {
            ident,
            target: u,
            cleartext,
        })
    }

    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        cleartext: String,
    ) -> Result<Self, OperationError> {
        Ok(PasswordChangeEvent {
            ident,
            target,
            cleartext,
        })
    }
}

pub struct UnixPasswordChangeEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub cleartext: String,
}

impl UnixPasswordChangeEvent {
    #[cfg(test)]
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        UnixPasswordChangeEvent {
            ident: Identity::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
    }

    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        cleartext: String,
    ) -> Result<Self, OperationError> {
        Ok(UnixPasswordChangeEvent {
            ident,
            target,
            cleartext,
        })
    }
}

#[derive(Debug)]
pub struct GeneratePasswordEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl GeneratePasswordEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(GeneratePasswordEvent { ident, target })
    }
}

#[derive(Debug)]
pub struct GenerateBackupCodeEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl GenerateBackupCodeEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(GenerateBackupCodeEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        GenerateBackupCodeEvent { ident, target }
    }
}

pub struct RemoveBackupCodeEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl RemoveBackupCodeEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(RemoveBackupCodeEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        RemoveBackupCodeEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct RegenerateRadiusSecretEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl RegenerateRadiusSecretEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(RegenerateRadiusSecretEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        RegenerateRadiusSecretEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct RadiusAuthTokenEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl RadiusAuthTokenEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerReadTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(RadiusAuthTokenEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        RadiusAuthTokenEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct UnixUserTokenEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl UnixUserTokenEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerReadTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(UnixUserTokenEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        UnixUserTokenEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct UnixGroupTokenEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl UnixGroupTokenEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerReadTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(UnixGroupTokenEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        UnixGroupTokenEvent { ident, target }
    }
}

pub struct UnixUserAuthEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub cleartext: String,
}

impl std::fmt::Debug for UnixUserAuthEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("UnixUserAuthEvent")
            .field("ident", &self.ident)
            .field("target", &self.target)
            .finish()
    }
}

impl UnixUserAuthEvent {
    #[cfg(test)]
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        UnixUserAuthEvent {
            ident: Identity::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
    }

    pub fn from_parts(
        _audit: &mut AuditScope,
        ident: Identity,
        target: Uuid,
        cleartext: String,
    ) -> Result<Self, OperationError> {
        Ok(UnixUserAuthEvent {
            ident,
            target,
            cleartext,
        })
    }
}

#[derive(Debug)]
pub struct GenerateTotpEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl GenerateTotpEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(GenerateTotpEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        GenerateTotpEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct VerifyTotpEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub session: Uuid,
    pub chal: u32,
}

impl VerifyTotpEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        session: Uuid,
        chal: u32,
    ) -> Result<Self, OperationError> {
        Ok(VerifyTotpEvent {
            ident,
            target,
            session,
            chal,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, session: Uuid, chal: u32) -> Self {
        let ident = Identity::from_internal();

        VerifyTotpEvent {
            ident,
            target,
            session,
            chal,
        }
    }
}

#[derive(Debug)]
pub struct AcceptSha1TotpEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub session: Uuid,
}

impl AcceptSha1TotpEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        session: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(AcceptSha1TotpEvent {
            ident,
            target,
            session,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, session: Uuid) -> Self {
        let ident = Identity::from_internal();

        AcceptSha1TotpEvent {
            ident,
            target,
            session,
        }
    }
}

#[derive(Debug)]
pub struct RemoveTotpEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl RemoveTotpEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(RemoveTotpEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        RemoveTotpEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct WebauthnInitRegisterEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub label: String,
}

impl WebauthnInitRegisterEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        Ok(WebauthnInitRegisterEvent {
            ident,
            target,
            label,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: String) -> Self {
        let ident = Identity::from_internal();
        WebauthnInitRegisterEvent {
            ident,
            target,
            label,
        }
    }
}

#[derive(Debug)]
pub struct WebauthnDoRegisterEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub session: Uuid,
    pub chal: RegisterPublicKeyCredential,
}

impl WebauthnDoRegisterEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        session: Uuid,
        chal: RegisterPublicKeyCredential,
    ) -> Result<Self, OperationError> {
        Ok(WebauthnDoRegisterEvent {
            ident,
            target,
            session,
            chal,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, session: Uuid, chal: RegisterPublicKeyCredential) -> Self {
        let ident = Identity::from_internal();
        WebauthnDoRegisterEvent {
            ident,
            target,
            session,
            chal,
        }
    }
}

#[derive(Debug)]
pub struct RemoveWebauthnEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub label: String,
}

impl RemoveWebauthnEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        Ok(RemoveWebauthnEvent {
            ident,
            target,
            label,
        })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: String) -> Self {
        let ident = Identity::from_internal();

        RemoveWebauthnEvent {
            ident,
            target,
            label,
        }
    }
}

#[derive(Debug)]
pub struct CredentialStatusEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl CredentialStatusEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerReadTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(CredentialStatusEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        CredentialStatusEvent { ident, target }
    }
}

#[derive(Debug)]
pub struct ReadBackupCodeEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl ReadBackupCodeEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        // qs: &QueryServerReadTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(ReadBackupCodeEvent { ident, target })
    }

    #[cfg(test)]
    pub fn new_internal(target: Uuid) -> Self {
        let ident = Identity::from_internal();

        ReadBackupCodeEvent { ident, target }
    }
}

pub struct LdapAuthEvent {
    // pub ident: Identity,
    pub target: Uuid,
    pub cleartext: String,
}

impl LdapAuthEvent {
    /*
    #[cfg(test)]
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        LdapAuthEvent {
            // ident: Identity::from_internal(),
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

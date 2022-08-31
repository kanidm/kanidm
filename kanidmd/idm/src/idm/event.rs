use crate::prelude::*;
use kanidm_proto::v1::OperationError;

#[cfg(test)]
pub(crate) struct PasswordChangeEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub cleartext: String,
}

#[cfg(test)]
impl PasswordChangeEvent {
    pub fn new_internal(target: &Uuid, cleartext: &str) -> Self {
        PasswordChangeEvent {
            ident: Identity::from_internal(),
            target: *target,
            cleartext: cleartext.to_string(),
        }
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
        // qs: &QueryServerWriteTransaction,
        ident: Identity,
        target: Uuid,
    ) -> Result<Self, OperationError> {
        Ok(GeneratePasswordEvent { ident, target })
    }
}

#[derive(Debug)]
pub struct RegenerateRadiusSecretEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl RegenerateRadiusSecretEvent {
    pub fn from_parts(
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
pub struct CredentialStatusEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl CredentialStatusEvent {
    pub fn from_parts(
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

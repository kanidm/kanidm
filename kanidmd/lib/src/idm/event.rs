use std::time::Duration;

use crate::idm::AuthState;
use crate::prelude::*;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{AuthCredential, AuthMech, AuthRequest, AuthStep};

#[cfg(test)]
use webauthn_rs::prelude::PublicKeyCredential;

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

pub struct LdapTokenAuthEvent {
    pub token: String,
}

impl LdapTokenAuthEvent {
    pub fn from_parts(token: String) -> Result<Self, OperationError> {
        Ok(LdapTokenAuthEvent { token })
    }
}

#[derive(Debug)]
pub struct AuthEventStepInit {
    pub name: String,
    pub appid: Option<String>,
}

#[derive(Debug)]
pub struct AuthEventStepCred {
    pub sessionid: Uuid,
    pub cred: AuthCredential,
}

#[derive(Debug)]
pub struct AuthEventStepMech {
    pub sessionid: Uuid,
    pub mech: AuthMech,
}

#[derive(Debug)]
pub enum AuthEventStep {
    Init(AuthEventStepInit),
    Begin(AuthEventStepMech),
    Cred(AuthEventStepCred),
}

impl AuthEventStep {
    fn from_authstep(aus: AuthStep, sid: Option<Uuid>) -> Result<Self, OperationError> {
        match aus {
            AuthStep::Init(name) => {
                Ok(AuthEventStep::Init(AuthEventStepInit { name, appid: None }))
            }
            AuthStep::Begin(mech) => match sid {
                Some(ssid) => Ok(AuthEventStep::Begin(AuthEventStepMech {
                    sessionid: ssid,
                    mech,
                })),
                None => Err(OperationError::InvalidAuthState(
                    "session id not present in cred presented to 'begin' step".to_string(),
                )),
            },
            AuthStep::Cred(cred) => match sid {
                Some(ssid) => Ok(AuthEventStep::Cred(AuthEventStepCred {
                    sessionid: ssid,
                    cred,
                })),
                None => Err(OperationError::InvalidAuthState(
                    "session id not present in cred to 'cred' step".to_string(),
                )),
            },
        }
    }

    #[cfg(test)]
    pub fn anonymous_init() -> Self {
        AuthEventStep::Init(AuthEventStepInit {
            name: "anonymous".to_string(),
            appid: None,
        })
    }

    #[cfg(test)]
    pub fn named_init(name: &str) -> Self {
        AuthEventStep::Init(AuthEventStepInit {
            name: name.to_string(),
            appid: None,
        })
    }

    #[cfg(test)]
    pub fn begin_mech(sessionid: Uuid, mech: AuthMech) -> Self {
        AuthEventStep::Begin(AuthEventStepMech { sessionid, mech })
    }

    #[cfg(test)]
    pub fn cred_step_anonymous(sid: Uuid) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::Anonymous,
        })
    }

    #[cfg(test)]
    pub fn cred_step_password(sid: Uuid, pw: &str) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::Password(pw.to_string()),
        })
    }

    #[cfg(test)]
    pub fn cred_step_totp(sid: Uuid, totp: u32) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::Totp(totp),
        })
    }

    #[cfg(test)]
    pub fn cred_step_backup_code(sid: Uuid, code: &str) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::BackupCode(code.to_string()),
        })
    }

    #[cfg(test)]
    pub fn cred_step_passkey(sid: Uuid, passkey_response: PublicKeyCredential) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::Passkey(passkey_response),
        })
    }
}

#[derive(Debug)]
pub struct AuthEvent {
    pub ident: Option<Identity>,
    pub step: AuthEventStep,
    // pub sessionid: Option<Uuid>,
}

impl AuthEvent {
    pub fn from_message(sessionid: Option<Uuid>, req: AuthRequest) -> Result<Self, OperationError> {
        Ok(AuthEvent {
            ident: None,
            step: AuthEventStep::from_authstep(req.step, sessionid)?,
        })
    }

    #[cfg(test)]
    pub fn anonymous_init() -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::anonymous_init(),
        }
    }

    #[cfg(test)]
    pub fn named_init(name: &str) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::named_init(name),
        }
    }

    #[cfg(test)]
    pub fn begin_mech(sessionid: Uuid, mech: AuthMech) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::begin_mech(sessionid, mech),
        }
    }

    #[cfg(test)]
    pub fn cred_step_anonymous(sid: Uuid) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_anonymous(sid),
        }
    }

    #[cfg(test)]
    pub fn cred_step_password(sid: Uuid, pw: &str) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_password(sid, pw),
        }
    }

    #[cfg(test)]
    pub fn cred_step_totp(sid: Uuid, totp: u32) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_totp(sid, totp),
        }
    }

    #[cfg(test)]
    pub fn cred_step_backup_code(sid: Uuid, code: &str) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_backup_code(sid, code),
        }
    }

    #[cfg(test)]
    pub fn cred_step_passkey(sid: Uuid, passkey_response: PublicKeyCredential) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_passkey(sid, passkey_response),
        }
    }
}

// Probably should be a struct with the session id present.
#[derive(Debug)]
pub struct AuthResult {
    pub sessionid: Uuid,
    pub state: AuthState,
    pub delay: Option<Duration>,
}

/*
impl AuthResult {
    pub fn response(self) -> AuthResponse {
        AuthResponse {
            sessionid: self.sessionid,
            state: self.state,
        }
    }
}
*/

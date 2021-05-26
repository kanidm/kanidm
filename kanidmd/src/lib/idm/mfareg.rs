use crate::audit::AuditScope;
use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
use crate::credential::webauthn::WebauthnDomainConfig;
use crate::identity::IdentityId;
use crate::idm::account::Account;
use kanidm_proto::v1::TotpSecret;
use kanidm_proto::v1::{OperationError, SetCredentialResponse};
use std::mem;
use std::time::Duration;
use uuid::Uuid;

use webauthn_rs::proto::Credential as WebauthnCredential;
use webauthn_rs::proto::{CreationChallengeResponse, RegisterPublicKeyCredential};
use webauthn_rs::RegistrationState as WebauthnRegistrationState;
use webauthn_rs::{proto::UserVerificationPolicy, Webauthn};

pub(crate) enum MfaRegCred {
    Totp(Totp),
    Webauthn(String, WebauthnCredential),
}

pub(crate) enum MfaRegNext {
    Success,
    TotpCheck(TotpSecret),
    WebauthnChallenge(CreationChallengeResponse),
}

impl MfaRegNext {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_proto(self, u: Uuid) -> SetCredentialResponse {
        match self {
            MfaRegNext::Success => SetCredentialResponse::Success,
            MfaRegNext::TotpCheck(secret) => SetCredentialResponse::TotpCheck(u, secret),
            MfaRegNext::WebauthnChallenge(ccr) => {
                SetCredentialResponse::WebauthnCreateChallenge(u, ccr)
            }
        }
    }
}

#[derive(Clone)]
enum MfaRegState {
    TotpInit(Totp),
    TotpDone,
    WebauthnInit(String, WebauthnRegistrationState),
    WebauthnDone,
}

#[derive(Clone)]
pub(crate) struct MfaRegSession {
    // The event origin, aka who is requesting the MFA reg (may not
    // be the same as account!!!)
    origin: IdentityId,
    // The account that the MFA will be registered to
    pub account: Account,
    // What state is the reg process in?
    state: MfaRegState,
}

impl MfaRegSession {
    pub fn totp_new(
        origin: IdentityId,
        account: Account,
        label: String,
    ) -> Result<(Self, MfaRegNext), OperationError> {
        // Based on the req, init our session, and the return the next step.
        // Store the ID of the event that start's the attempt
        let token = Totp::generate_secure(label, TOTP_DEFAULT_STEP);

        let accountname = account.name.as_str();
        let issuer = account.spn.as_str();
        let next = MfaRegNext::TotpCheck(token.to_proto(accountname, issuer));

        let state = MfaRegState::TotpInit(token);
        let s = MfaRegSession {
            origin,
            account,
            state,
        };
        Ok((s, next))
    }

    pub fn totp_step(
        &mut self,
        origin: &IdentityId,
        target: &Uuid,
        chal: u32,
        ct: &Duration,
    ) -> Result<(MfaRegNext, Option<MfaRegCred>), OperationError> {
        if &self.origin != origin || target != &self.account.uuid {
            // Verify that the same event source is the one continuing this attempt
            return Err(OperationError::InvalidRequestState);
        };

        match &self.state {
            MfaRegState::TotpInit(token) => {
                if token.verify(chal, ct) {
                    let mut nstate = MfaRegState::TotpDone;
                    mem::swap(&mut self.state, &mut nstate);
                    match nstate {
                        MfaRegState::TotpInit(token) => {
                            Ok((MfaRegNext::Success, Some(MfaRegCred::Totp(token))))
                        }
                        _ => Err(OperationError::InvalidState),
                    }
                } else {
                    // Let them try again?
                    let accountname = self.account.name.as_str();
                    let issuer = self.account.spn.as_str();
                    Ok((
                        MfaRegNext::TotpCheck(token.to_proto(accountname, issuer)),
                        None,
                    ))
                }
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn webauthn_new(
        au: &mut AuditScope,
        origin: IdentityId,
        account: Account,
        label: String,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> Result<(Self, MfaRegNext), OperationError> {
        // Setup the registration.
        let (chal, reg_state) = webauthn
            .generate_challenge_register(&account.name, Some(UserVerificationPolicy::Discouraged))
            .map_err(|e| {
                ladmin_error!(au, "Unable to generate webauthn challenge -> {:?}", e);
                OperationError::Webauthn
            })?;

        let state = MfaRegState::WebauthnInit(label, reg_state);
        let s = MfaRegSession {
            origin,
            account,
            state,
        };
        let next = MfaRegNext::WebauthnChallenge(chal);
        Ok((s, next))
    }

    pub fn webauthn_step(
        &mut self,
        au: &mut AuditScope,
        origin: &IdentityId,
        target: &Uuid,
        chal: &RegisterPublicKeyCredential,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> Result<(MfaRegNext, Option<MfaRegCred>), OperationError> {
        if &self.origin != origin || target != &self.account.uuid {
            // Verify that the same event source is the one continuing this attempt
            return Err(OperationError::InvalidRequestState);
        };

        // Regardless of the outcome, we are done!
        let mut nstate = MfaRegState::WebauthnDone;
        mem::swap(&mut self.state, &mut nstate);

        match nstate {
            MfaRegState::WebauthnInit(label, reg_state) => webauthn
                .register_credential(chal, reg_state, |_| Ok(false))
                .map_err(|e| {
                    ladmin_error!(au, "Unable to register webauthn credential -> {:?}", e);
                    OperationError::Webauthn
                })
                .map(|cred| (MfaRegNext::Success, Some(MfaRegCred::Webauthn(label, cred)))),
            _ => Err(OperationError::InvalidRequestState),
        }
    }
}

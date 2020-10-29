use crate::credential::totp::{TOTP, TOTP_DEFAULT_STEP};
use crate::event::EventOriginId;
use crate::idm::account::Account;
use kanidm_proto::v1::TOTPSecret;
use kanidm_proto::v1::{OperationError, SetCredentialResponse};
use std::mem;
use std::time::Duration;
use uuid::Uuid;

use webauthn_rs::proto::{CreationChallengeResponse, RegisterPublicKeyCredential};
use webauthn_rs::proto::Credential as WebauthnCredential;
use webauthn_rs::RegistrationState as WebauthnRegistrationState;

// Client requests they want to reg a TOTP to account.
pub(crate) enum MfaReqInit {
    TOTP(String),
    Webauthn(String),
}

pub(crate) enum MfaReqStep {
    TOTPVerify(u32),
    WebauthnRegister(RegisterPublicKeyCredential),
}

pub(crate) enum MfaRegCred {
    TOTP(TOTP),
    Webauthn(WebauthnCredential),
}

pub(crate) enum MfaRegNext {
    Success,
    TOTPCheck(TOTPSecret),
    WebauthnChallenge(CreationChallengeResponse)
}

impl MfaRegNext {
    pub fn to_proto(&self, u: &Uuid) -> SetCredentialResponse {
        match self {
            MfaRegNext::Success => SetCredentialResponse::Success,
            MfaRegNext::TOTPCheck(secret) => {
                SetCredentialResponse::TOTPCheck(*u, (*secret).clone())
            }
            MfaRegNext::WebauthnChallenge(ccr) => {
                SetCredentialResponse::WebauthnCreateChallenge(*u, (*ccr).clone())
            }
        }
    }
}

#[derive(Clone)]
enum MfaRegState {
    TOTPInit(TOTP),
    TOTPDone,
    WebauthnInit(String, WebauthnRegistrationState),
    WebauthnDone,
}

#[derive(Clone)]
pub(crate) struct MfaRegSession {
    // The event origin, aka who is requesting the MFA reg (may not
    // be the same as account!!!)
    origin: EventOriginId,
    // The account that the MFA will be registered to
    pub account: Account,
    // What state is the reg process in?
    state: MfaRegState,
}

impl MfaRegSession {
    pub fn new(
        origin: EventOriginId,
        account: Account,
        req: MfaReqInit,
    ) -> Result<(Self, MfaRegNext), OperationError> {
        // Based on the req, init our session, and the return the next step.
        // Store the ID of the event that start's the attempt
        let state = match req {
            MfaReqInit::TOTP(label) => {
                MfaRegState::TOTPInit(TOTP::generate_secure(label, TOTP_DEFAULT_STEP))
            }
            MfaReqInit::Webauthn(label) => {
                unimplemented!();
                // let registration_state = ();
                // MfaRegState::WebauthnInit(label, registration_state)
            }
        };
        let s = MfaRegSession {
            origin,
            account,
            state,
        };
        let next = s.next();
        Ok((s, next))
    }

    pub fn step(
        &mut self,
        origin: &EventOriginId,
        target: &Uuid,
        req: MfaReqStep,
        ct: &Duration,
    ) -> Result<(MfaRegNext, Option<MfaRegCred>), OperationError> {
        if &self.origin != origin || target != &self.account.uuid {
            // Verify that the same event source is the one continuing this attempt
            return Err(OperationError::InvalidRequestState);
        };

        match (req, &self.state) {
            (MfaReqStep::TOTPVerify(chal), MfaRegState::TOTPInit(token)) => {
                if token.verify(chal, ct) {
                    let mut nstate = MfaRegState::TOTPDone;
                    mem::swap(&mut self.state, &mut nstate);
                    match nstate {
                        MfaRegState::TOTPInit(token) => {
                            Ok((MfaRegNext::Success, Some(MfaRegCred::TOTP(token))))
                        }
                        _ => Err(OperationError::InvalidState),
                    }
                } else {
                    // Let them try again?
                    let accountname = self.account.name.as_str();
                    let issuer = self.account.spn.as_str();
                    Ok((
                        MfaRegNext::TOTPCheck(token.to_proto(accountname, issuer)),
                        None,
                    ))
                }
            }
            (MfaReqStep::WebauthnRegister(ref rpkc), MfaRegState::WebauthnInit(label,  registration_state)) => {
                unimplemented!();
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }
}

impl MfaRegSession {
    pub fn next(&self) -> MfaRegNext {
        // Given our current state, what is the next step we need to process or offer?
        match &self.state {
            MfaRegState::TOTPDone | MfaRegState::WebauthnDone => MfaRegNext::Success,
            MfaRegState::TOTPInit(token) => {
                let accountname = self.account.name.as_str();
                let issuer = self.account.spn.as_str();
                MfaRegNext::TOTPCheck(token.to_proto(accountname, issuer))
            }
            MfaRegState::WebauthnInit(label, registration_state) => {
                unimplemented!();
            }
        }
    }
}

use crate::credential::totp::TOTP;
use crate::idm::account::Account;
use kanidm_proto::v1::TOTPSecret;

// Client requests they want to reg a TOTP to account.
pub(crate) enum MfaReqInit {
    TOTP,
    // Webauthn
}

pub(crate) enum MfaReqStep {
    TOTPVerify(u32),
}

pub(crate) enum MfaRegNext {
    Success,
    TOTPCheck(TOTPSecret),
    // Webauthn(chal)
}

#[derive(Clone)]
pub(crate) enum MfaRegState {
    TOTPInit(TOTP),
    TOTPDone,
    // Webauthn ...
}

#[derive(Clone)]
pub(crate) struct MfaRegSession {
    // The account that wants to register the MFA.
    account: Account,
    // What state is the reg process in?
    state: MfaRegState,
}

impl MfaRegSession {
    pub fn new(account: Account, req: MfaReqInit) -> Result<(Self, MfaRegNext), ()> {
        // Based on the req, init our session, and the return the next step.
        unimplemented!();
    }

    pub fn step(&mut self, req: MfaReqStep) -> Result<MfaRegNext, ()> {
        unimplemented!();
    }
}

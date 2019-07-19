use crate::constants::UUID_ANONYMOUS;
use crate::error::OperationError;
use crate::idm::account::Account;
use crate::idm::claim::Claim;
use crate::proto::v1::{AuthAllowed, AuthCredential, AuthState};

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fufilled. This is where MFA or other
// auth policies would exist, but each credHandler has to be a whole
// encapsulated unit of function.

enum CredState {
    Success(Vec<Claim>),
    Continue(Vec<AuthAllowed>),
    // TODO: Should we have a reason in Denied so that we
    Denied,
}

#[derive(Clone, Debug)]
enum CredHandler {
    Anonymous,
    // AppPassword
    // {
    // Password
    // Webauthn
    // Webauthn + Password
    // TOTP
    // TOTP + Password
    // } <<-- could all these be "AccountPrimary" and pass to Account?
    // Selection at this level could be premature ...
    // Verification Link?
}

impl CredHandler {
    pub fn validate(&mut self, creds: &Vec<AuthCredential>) -> CredState {
        match self {
            CredHandler::Anonymous => {
                creds.iter().fold(CredState::Denied, |acc, cred| {
                    // TODO: if denied, continue returning denied.
                    // TODO: if continue, contunue returning continue.
                    // How to do this correctly?

                    // There is no "continuation" from this type.
                    match cred {
                        AuthCredential::Anonymous => {
                            // For anonymous, no claims will ever be issued.
                            CredState::Success(Vec::new())
                        }
                        _ => {
                            // Should we have a reason in Denied so that we can say why denied?
                            acc
                            // CredState::Denied
                        }
                    }
                })
            }
        }
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Anonymous => vec![AuthAllowed::Anonymous],
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuthSession {
    // Do we store a copy of the entry?
    // How do we know what claims to add?
    account: Account,
    // Store how we plan to handle this sessions authentication: this is generally
    // made apparent by the presentation of an application id or not. If none is presented
    // we want the primary-interaction credentials.
    //
    // This handler will then handle the mfa and stepping up through to generate the auth states
    handler: CredHandler,
    // Store any related appid we are processing for.
    appid: Option<String>,
    finished: bool,
}

impl AuthSession {
    pub fn new(account: Account, appid: Option<String>) -> Self {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let handler = match appid {
            Some(_) => {
                unimplemented!();
            }
            None => {
                // We want the primary handler - this is where we make a decision
                // based on the anonymous ... in theory this could be cleaner
                // and interact with the account more?
                if account.uuid == UUID_ANONYMOUS {
                    CredHandler::Anonymous
                } else {
                    unimplemented!();
                }
            }
        };

        // Is this handler locked?
        // Is the whole account locked?
        // What about in memory account locking? Is that something
        // we store in the account somehow?
        // TODO: Implement handler locking!

        AuthSession {
            account: account,
            handler: handler,
            appid: appid,
            finished: false,
        }
    }

    // This should return a AuthResult or similar state of checking?
    // TODO: This needs some logging ....
    pub fn validate_creds(
        &mut self,
        creds: &Vec<AuthCredential>,
    ) -> Result<AuthState, OperationError> {
        if self.finished {
            return Err(OperationError::InvalidAuthState(
                "session already finalised!",
            ));
        }

        match self.handler.validate(creds) {
            CredState::Success(claims) => {
                self.finished = true;
                let uat = self
                    .account
                    .to_userauthtoken(claims)
                    .ok_or(OperationError::InvalidState)?;
                Ok(AuthState::Success(uat))
            }
            CredState::Continue(allowed) => Ok(AuthState::Continue(allowed)),
            CredState::Denied => {
                self.finished = true;
                Ok(AuthState::Denied)
            }
        }
        // Also send an async message to self to log the auth as provided.
        // Alternately, open a write, and commit the needed security metadata here
        // now rather than async (probably better for lock-outs etc)
        //
        // TODO: Async message the account owner about the login?
        // If this fails, how can we in memory lock the account?
        //
        // The lockouts could also be an in-memory concept too?

        // If this suceeds audit?
        //  If success, to authtoken?
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        // TODO: This needs logging ....
        if self.finished {
            Vec::new()
        } else {
            self.handler.valid_auth_mechs()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::JSON_ANONYMOUS_V1;
    use crate::idm::authsession::AuthSession;
    use crate::proto::v1::AuthAllowed;

    use std::convert::TryFrom;

    #[test]
    fn test_idm_account_anonymous_auth_mech() {
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);

        let session = AuthSession::new(anon_account, None);

        let auth_mechs = session.valid_auth_mechs();

        assert!(
            true == auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::Anonymous => true,
                _ => acc,
            })
        );
    }
}

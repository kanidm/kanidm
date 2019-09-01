use crate::audit::AuditScope;
use crate::constants::UUID_ANONYMOUS;
use crate::error::OperationError;
use crate::idm::account::Account;
use crate::idm::claim::Claim;
use crate::proto::v1::{AuthAllowed, AuthCredential, AuthState};

use crate::credential::{Credential, Password};

use std::convert::TryFrom;

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fufilled. This is where MFA or other
// auth policies would exist, but each credHandler has to be a whole
// encapsulated unit of function.

enum CredState {
    Success(Vec<Claim>),
    Continue(Vec<AuthAllowed>),
    Denied(&'static str),
}

#[derive(Clone, Debug)]
enum CredHandler {
    Denied,
    // The bool is a flag if the cred has been authed against.
    Anonymous,
    // AppPassword
    // {
    // Password
    Password(Password), // Webauthn
                        // Webauthn + Password
                        // TOTP
                        // TOTP + Password
                        // } <<-- could all these be "AccountPrimary" and pass to Account?
                        // Selection at this level could be premature ...
                        // Verification Link?
}

impl TryFrom<&Credential> for CredHandler {
    type Error = ();
    // Is there a nicer implementation of this?
    fn try_from(c: &Credential) -> Result<Self, Self::Error> {
        if c.password.is_some() {
            Ok(CredHandler::Password(c.password.clone().unwrap()))
        } else {
            Err(())
        }
    }
}

impl CredHandler {
    pub fn validate(&mut self, creds: &Vec<AuthCredential>) -> CredState {
        match self {
            CredHandler::Denied => {
                // Sad trombone.
                CredState::Denied("authentication denied")
            }
            CredHandler::Anonymous => {
                creds.iter().fold(
                    CredState::Continue(vec![AuthAllowed::Anonymous]),
                    |acc, cred| {
                        // There is no "continuation" from this type - we only set it at
                        // the start assuming there is no values in the iter so we can tell
                        // the session to continue up to some timelimit.
                        match acc {
                            // If denied, continue returning denied.
                            CredState::Denied(_) => acc,
                            // We have a continue or success, it's important we keep checking here
                            // after the success, because if they sent "multiple" anonymous or
                            // they sent anon + password, we need to handle both cases. Double anon
                            // is okay, but anything else is instant failure, even if we already
                            // had a success.
                            _ => {
                                match cred {
                                    AuthCredential::Anonymous => {
                                        // For anonymous, no claims will ever be issued.
                                        CredState::Success(Vec::new())
                                    }
                                    _ => CredState::Denied("non-anonymous credential provided"),
                                }
                            }
                        } // end match acc
                    },
                )
            } // end credhandler::anonymous
            CredHandler::Password(pw) => {
                creds.iter().fold(
                    // If no creds, remind that we want pw ...
                    CredState::Continue(vec![AuthAllowed::Password]),
                    |acc, cred| {
                        match acc {
                            // If failed, continue to fail.
                            CredState::Denied(_) => acc,
                            _ => {
                                match cred {
                                    AuthCredential::Password(cleartext) => {
                                        if pw.verify(cleartext.as_str()) {
                                            CredState::Success(Vec::new())
                                        } else {
                                            CredState::Denied("incorrect password")
                                        }
                                    }
                                    // All other cases fail.
                                    _ => CredState::Denied("pw authentication denied"),
                                }
                            }
                        } // end match acc
                    },
                )
            } // end credhandler::password
        }
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Denied => Vec::new(),
            CredHandler::Anonymous => vec![AuthAllowed::Anonymous],
            CredHandler::Password(_) => vec![AuthAllowed::Password],
            // webauth
            // mfa
        }
    }

    pub(crate) fn is_denied(&self) -> bool {
        match &self {
            CredHandler::Denied => true,
            _ => false,
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
    // Store claims related to the handler
    // need to store state somehow?
    finished: bool,
}

impl AuthSession {
    pub fn new(account: Account, appid: Option<String>) -> Self {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let handler = match appid {
            Some(_) => CredHandler::Denied,
            None => {
                // We want the primary handler - this is where we make a decision
                // based on the anonymous ... in theory this could be cleaner
                // and interact with the account more?
                if account.uuid == UUID_ANONYMOUS.clone() {
                    CredHandler::Anonymous
                } else {
                    // Now we see if they have one ...
                    match &account.primary {
                        Some(cred) => {
                            // TODO: Log this corruption better ... :(
                            // Probably means new authsession has to be failable
                            CredHandler::try_from(cred).unwrap_or_else(|_| CredHandler::Denied)
                        }
                        None => CredHandler::Denied,
                    }
                }
            }
        };

        // Is this handler locked?
        // Is the whole account locked?
        // What about in memory account locking? Is that something
        // we store in the account somehow?
        // TODO #59: Implement handler locking!

        // if credhandler == deny, finish = true.
        let finished: bool = handler.is_denied();

        AuthSession {
            account: account,
            handler: handler,
            appid: appid,
            finished: finished,
        }
    }

    // This should return a AuthResult or similar state of checking?
    pub fn validate_creds(
        &mut self,
        au: &mut AuditScope,
        creds: &Vec<AuthCredential>,
    ) -> Result<AuthState, OperationError> {
        if self.finished {
            return Err(OperationError::InvalidAuthState(
                "session already finalised!",
            ));
        }

        match self.handler.validate(creds) {
            CredState::Success(claims) => {
                audit_log!(au, "Successful cred handling");
                self.finished = true;
                let uat = self
                    .account
                    .to_userauthtoken(claims)
                    .ok_or(OperationError::InvalidState)?;
                Ok(AuthState::Success(uat))
            }
            CredState::Continue(allowed) => {
                audit_log!(au, "Request credential continuation: {:?}", allowed);
                Ok(AuthState::Continue(allowed))
            }
            CredState::Denied(reason) => {
                self.finished = true;
                audit_log!(au, "Credentials denied: {}", reason);
                Ok(AuthState::Denied(reason.to_string()))
            }
        }
        // Also send an async message to self to log the auth as provided.
        // Alternately, open a write, and commit the needed security metadata here
        // now rather than async (probably better for lock-outs etc)
        //
        // TODO #59: Async message the account owner about the login?
        // If this fails, how can we in memory lock the account?
        //
        // The lockouts could also be an in-memory concept too?

        // If this suceeds audit?
        //  If success, to authtoken?
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        if self.finished {
            Vec::new()
        } else {
            self.handler.valid_auth_mechs()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::{JSON_ADMIN_V1, JSON_ANONYMOUS_V1};
    use crate::credential::Credential;
    use crate::idm::authsession::AuthSession;
    use crate::proto::v1::AuthAllowed;

    #[test]
    fn test_idm_authsession_anonymous_auth_mech() {
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

    #[test]
    fn test_idm_authsession_missing_appid() {
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);

        let session = AuthSession::new(anon_account, Some("NonExistantAppID".to_string()));

        let auth_mechs = session.valid_auth_mechs();

        // Will always move to denied.
        assert!(auth_mechs == Vec::new());
    }

    #[test]
    fn test_idm_authsession_simple_password_mech() {
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);
        // manually load in a cred
        let cred = Credential::new_password_only("test_password");
        account.primary = Some(cred);

        // now check
        let session = AuthSession::new(account, None);
        let auth_mechs = session.valid_auth_mechs();

        assert!(
            true == auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::Password => true,
                _ => acc,
            })
        );
    }
}

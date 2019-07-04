use crate::constants::UUID_ANONYMOUS;
use crate::error::OperationError;
use crate::idm::account::Account;
use crate::proto::v1::{AuthAllowed, AuthCredential};

#[derive(Clone)]
pub(crate) struct AuthSession {
    // Do we store a copy of the entry?
    // How do we know what claims to add?
    pub account: Account,
    // Store what creds have been presented?
    // Store any related appid we are processing for.
}

impl AuthSession {
    pub fn is_finished(&mut self) -> () {
        // If we are done, mark as such, and return a uat. This could also
        // finish to a DENIED!!!
    }

    fn validate_cred(&mut self) -> () {}

    // This should return a AuthResult or similar state of checking?
    pub fn validate_creds(&mut self, creds: &Vec<AuthCredential>) -> Result<(), OperationError> {
        Err(OperationError::InvalidState)
    }

    fn auth_mech_anonymous(&self) -> Option<AuthAllowed> {
        if self.account.uuid == UUID_ANONYMOUS {
            // Was it already presented?
            Some(AuthAllowed::Anonymous)
        } else {
            None
        }
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        let mut valid = Vec::new();

        match self.auth_mech_anonymous() {
            Some(a) => valid.push(a),
            None => {}
        }

        valid
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::JSON_ANONYMOUS_V1;
    use crate::entry::{Entry, EntryNew, EntryValid};
    use crate::idm::account::Account;
    use crate::idm::authsession::AuthSession;
    use crate::proto::v1::AuthAllowed;

    use std::convert::TryFrom;

    #[test]
    fn test_idm_account_anonymous_auth_mech() {
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);

        let session = AuthSession {
            account: anon_account,
        };

        let auth_mechs = session.valid_auth_mechs();

        assert!(
            true == auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::Anonymous => true,
                _ => acc,
            })
        );
    }
}

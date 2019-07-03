use crate::be::Backend;
use crate::audit::AuditScope;
use crate::constants::UUID_ANONYMOUS;
use crate::error::OperationError;
use crate::event::{AuthEvent, AuthResult, SearchEvent};
use crate::proto::v1::{UserAuthToken, AuthResponse, AuthState, AuthStep};
use crate::schema::Schema;
use crate::server::{QueryServer, QueryServerTransaction};
use crate::idm::account::Account;
use concread::cowcell::{CowCell, CowCellReadTxn, CowCellWriteTxn};

use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;
use std::convert::TryFrom;
// use lru::LruCache;

pub struct IdmServer {
    // Need an auth-session table to save in progress authentications
    // sessions:
    //
    // TODO: This should be Lru
    // TODO: AuthSession should be per-session mutex to keep locking on the
    //   cell low to allow more concurrent auths.
    sessions: CowCell<BTreeMap<Uuid, AuthSession>>,
    // Need a reference to the query server.
    qs: QueryServer,
}

pub struct IdmServerWriteTransaction<'a> {
    // Contains methods that require writes, but in the context of writing to
    // the idm in memory structures (maybe the query server too). This is
    // things like authentication
    sessions: CowCellWriteTxn<'a, BTreeMap<Uuid, AuthSession>>,
    qs: &'a QueryServer,
}

pub struct IdmServerReadTransaction<'a> {
    // This contains read-only methods, like getting users, groups
    // and other structured content.
    qs: &'a QueryServer,
}

impl IdmServer {
    // TODO: Make number of authsessions configurable!!!
    pub fn new(qs: QueryServer) -> IdmServer {
        IdmServer {
            sessions: CowCell::new(BTreeMap::new()),
            qs: qs,
        }
    }

    pub fn write(&self) -> IdmServerWriteTransaction {
        IdmServerWriteTransaction {
            sessions: self.sessions.write(),
            qs: &self.qs,
        }
    }

    pub fn read(&self) -> IdmServerReadTransaction {
        IdmServerReadTransaction { qs: &self.qs }
    }
}

#[derive(Clone)]
struct AuthSession {
    // Do we store a copy of the entry?
    // How do we know what claims to add?
    pub account: Account
}

impl<'a> IdmServerWriteTransaction<'a> {
    // TODO: This should be something else, not the proto token!
    pub fn auth(&mut self, au: &mut AuditScope, ae: &AuthEvent) -> Result<AuthResult, OperationError> {
        audit_log!(au, "Received AuthEvent -> {:?}", ae);

        // Match on the auth event, to see what we need to do.

        match &ae.step {
            AuthStep::Init(name, opt_app_name) => {
                // Check the session id is None
                match ae.sessionid {
                    Some(id) => {
                        // TODO: Alternately, we just clear this from the sessions.
                        Err(OperationError::InvalidRequestState)
                    }
                    None => {
                        // Allocate a session id.
                        let sessionid = Uuid::new_v4();

                        // Begin the auth procedure!
                        // Start a read
                        //
                        // Actually we may not need this - at the time we issue the auth-init
                        // we could generate the uat, the nonce and cache hashes in memory,
                        // then this can just be fully without a txn.
                        //
                        // We do need a txn so that we can process/search and claims
                        // or related based on the quality of the provided auth steps
                        //
                        // We *DO NOT* need a write though, because I think that lock outs
                        // and rate limits are *per server* and *in memory* only.
                        let qs_read = self.qs.read();
                        // Check anything needed? Get the current auth-session-id from request
                        // because it associates to the nonce's etc which were all cached.

                        // FIXME!!! This hack is to get anonymous, then we just use them
                        // to generate the UAT.
                        let filter_entry = filter!(f_or!([
                            f_eq("name", name.as_str()),
                            // This currently says invalid syntax, which is correct, but also
                            // annoying because it would be nice to search both ...
                            // f_eq("uuid", name.as_str()),
                        ]));


                        // Get the first / single entry we expect here ....
                        let entry = match qs_read.internal_search(au, filter_entry) {
                            Ok(mut entries) => {
                                // Get only one entry out ...
                                if entries.len() >= 2 {
                                    return Err(OperationError::InvalidDBState);
                                }
                                entries.pop()
                                    .ok_or(OperationError::NoMatchingEntries)?
                            }
                            Err(e) => {
                                // Something went wrong! Abort!
                                return Err(e);
                            }
                        };

                        audit_log!(au, "Initiating Authentication Session for ... {:?}", entry);

                        // Now, convert the Entry to an account - this gives us some stronger
                        // typing and functionality so we can assess what auth types can
                        // continue, and helps to keep non-needed entry specific data
                        // out of the LRU.

                        let account = Account::try_from(entry)?;

                        // Get the set of mechanisms that can proceed

                        let next_mech = account.valid_auth_mechs();

                        let auth_session = AuthSession {
                            account: account
                        };

                        self.sessions.insert(sessionid, auth_session);

                        Ok(AuthResult {
                            sessionid: sessionid,
                            state: AuthState::Continue(next_mech),
                        })
                    }
                }
            }
            AuthStep::Creds(creds) => {
                // Do we have a session?
                // Process the credentials here as required.
                        // If everything is good, finally issue the token. Oui oui!
                        // Also send an async message to self to log the auth as provided.
                        // Alternately, open a write, and commit the needed security metadata here
                        // now rather than async (probably better for lock-outs etc)
                        //
                        // TODO: Async message the account owner about the login?

                        //
                        // The lockouts could also be an in-memory concept too?

                        /*
                        match anon_entry.to_userauthtoken() {
                            Some(uat) => Ok(uat),
                            None => Err(OperationError::InvalidState),
                        }
                        */

                        // Else, non non non!
                println!("{:?}", creds);
                unimplemented!();
            }
        }

    }

    pub fn commit(self) -> Result<(), OperationError> {
        self.sessions.commit();
        Ok(())
    }
}

impl<'a> IdmServerReadTransaction<'a> {
    pub fn whoami() -> () {}
}

// Need tests of the sessions and the auth ...

#[cfg(test)]
mod tests {
    #[test]
    fn test_idm_anonymous_auth() {
        run_idm_test!(|qs, idms, au| {
            // Start and test anonymous auth.
            // Send the initial auth event for initialising the session

            // Now send the anonymous request

            // Expect success
        });
    }

    // Test sending anonymous but with no session init.
}




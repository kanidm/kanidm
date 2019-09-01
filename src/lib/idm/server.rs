use crate::audit::AuditScope;
use crate::error::OperationError;
use crate::event::{AuthEvent, AuthEventStep, AuthResult};
use crate::idm::account::Account;
use crate::idm::authsession::AuthSession;
use crate::proto::v1::AuthState;
use crate::server::{QueryServer, QueryServerTransaction};
use crate::value::PartialValue;

use concread::cowcell::{CowCell, CowCellWriteTxn};
use std::collections::BTreeMap;
use uuid::Uuid;
// use lru::LruCache;

pub struct IdmServer {
    // There is a good reason to keep this single thread - it
    // means that limits to sessions can be easily applied and checked to
    // variaous accounts, and we have a good idea of how to structure the
    // in memory caches related to locking.
    //
    // TODO #60: This needs a mark-and-sweep gc to be added.
    // use split_off()
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

/*
pub struct IdmServerReadTransaction<'a> {
    // This contains read-only methods, like getting users, groups
    // and other structured content.
    qs: &'a QueryServer,
}
*/

impl IdmServer {
    // TODO #59: Make number of authsessions configurable!!!
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

    /*
    pub fn read(&self) -> IdmServerReadTransaction {
        IdmServerReadTransaction { qs: &self.qs }
    }
    */
}

impl<'a> IdmServerWriteTransaction<'a> {
    pub fn auth(
        &mut self,
        au: &mut AuditScope,
        ae: &AuthEvent,
    ) -> Result<AuthResult, OperationError> {
        audit_log!(au, "Received AuthEvent -> {:?}", ae);

        // Match on the auth event, to see what we need to do.

        match &ae.step {
            AuthEventStep::Init(init) => {
                // Allocate a session id.
                // TODO: #60 - make this new_v1 and use the tstamp.
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

                let filter_entry = filter!(f_or!([
                    f_eq("name", PartialValue::new_iutf8s(init.name.as_str())),
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
                        entries.pop().ok_or(OperationError::NoMatchingEntries)?
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
                let account = Account::try_from_entry(entry)?;
                let auth_session = AuthSession::new(account, init.appid.clone());

                // Get the set of mechanisms that can proceed. This is tied
                // to the session so that it can mutate state and have progression
                // of what's next, or ordering.
                let next_mech = auth_session.valid_auth_mechs();

                // If we have a session of the same id, return an error (despite how
                // unlikely this is ...
                if self.sessions.contains_key(&sessionid) {
                    return Err(OperationError::InvalidSessionState);
                }
                self.sessions.insert(sessionid, auth_session);

                // Debugging: ensure we really inserted ...
                assert!(self.sessions.get(&sessionid).is_some());

                Ok(AuthResult {
                    sessionid: sessionid,
                    state: AuthState::Continue(next_mech),
                })
            }
            AuthEventStep::Creds(creds) => {
                // Do we have a session?
                let auth_session = try_audit!(
                    au,
                    (*self.sessions)
                        // Why is the session missing?
                        .get_mut(&creds.sessionid)
                        .ok_or(OperationError::InvalidSessionState)
                );
                // Process the credentials here as required.
                // Basically throw them at the auth_session and see what
                // falls out.
                auth_session.validate_creds(au, &creds.creds).map(|aus| {
                    AuthResult {
                        // Is this right?
                        sessionid: creds.sessionid,
                        state: aus,
                    }
                })
            }
        }
    }

    pub fn commit(self) -> Result<(), OperationError> {
        self.sessions.commit();
        Ok(())
    }
}

/*
impl<'a> IdmServerReadTransaction<'a> {
    pub fn whoami() -> () {}
}
*/

// Need tests of the sessions and the auth ...

#[cfg(test)]
mod tests {
    use crate::credential::Credential;
    use crate::error::OperationError;
    use crate::event::{AuthEvent, AuthResult, ModifyEvent};
    use crate::modify::{Modify, ModifyList};
    use crate::proto::v1::{AuthAllowed, AuthState};
    use crate::value::{PartialValue, Value};

    use crate::audit::AuditScope;
    use crate::idm::server::IdmServer;
    use crate::server::QueryServer;
    use uuid::Uuid;

    static TEST_PASSWORD: &'static str = "ntaoeuntnaoeuhraohuercahu😍";
    static TEST_PASSWORD_INC: &'static str = "ntaoentu nkrcgaeunhibwmwmqj;k wqjbkx ";

    #[test]
    fn test_idm_anonymous_auth() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            let sid = {
                // Start and test anonymous auth.
                let mut idms_write = idms.write();
                // Send the initial auth event for initialising the session
                let anon_init = AuthEvent::anonymous_init();
                // Expect success
                let r1 = idms_write.auth(au, &anon_init);
                /* Some weird lifetime shit happens here ... */
                // audit_log!(au, "r1 ==> {:?}", r1);

                let sid = match r1 {
                    Ok(ar) => {
                        let AuthResult { sessionid, state } = ar;
                        match state {
                            AuthState::Continue(mut conts) => {
                                // Should only be one auth mech
                                assert!(conts.len() == 1);
                                // And it should be anonymous
                                let m = conts.pop().expect("Should not fail");
                                assert!(m == AuthAllowed::Anonymous);
                            }
                            _ => {
                                error!(
                                    "A critical error has occured! We have a non-continue result!"
                                );
                                panic!();
                            }
                        };
                        // Now pass back the sessionid, we are good to continue.
                        sessionid
                    }
                    Err(e) => {
                        // Should not occur!
                        error!("A critical error has occured! {:?}", e);
                        panic!();
                    }
                };

                println!("sessionid is ==> {:?}", sid);

                idms_write.commit().expect("Must not fail");

                sid
            };
            {
                let mut idms_write = idms.write();
                // Now send the anonymous request, given the session id.
                let anon_step = AuthEvent::cred_step_anonymous(sid);

                // Expect success
                let r2 = idms_write.auth(au, &anon_step);
                println!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                        } = ar;
                        match state {
                            AuthState::Success(_uat) => {
                                // Check the uat.
                            }
                            _ => {
                                error!(
                                    "A critical error has occured! We have a non-succcess result!"
                                );
                                panic!();
                            }
                        }
                    }
                    Err(e) => {
                        error!("A critical error has occured! {:?}", e);
                        // Should not occur!
                        panic!();
                    }
                };

                idms_write.commit().expect("Must not fail");
            }
        });
    }

    // Test sending anonymous but with no session init.
    #[test]
    fn test_idm_anonymous_auth_invalid_states() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            {
                let mut idms_write = idms.write();
                let sid = Uuid::new_v4();
                let anon_step = AuthEvent::cred_step_anonymous(sid);

                // Expect failure
                let r2 = idms_write.auth(au, &anon_step);
                println!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(_) => {
                        error!("Auth state machine not correctly enforced!");
                        panic!();
                    }
                    Err(e) => match e {
                        OperationError::InvalidSessionState => {}
                        _ => panic!(),
                    },
                };
            }
        })
    }

    fn init_admin_w_password(
        au: &mut AuditScope,
        qs: &QueryServer,
        pw: &str,
    ) -> Result<(), OperationError> {
        let cred = Credential::new_password_only(pw);
        let v_cred = Value::new_credential("primary", cred);
        let mut qs_write = qs.write();

        // now modify and provide a primary credential.
        let me_inv_m = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                ModifyList::new_list(vec![Modify::Present(
                    "primary_credential".to_string(),
                    v_cred,
                )]),
            )
        };
        // go!
        assert!(qs_write.modify(au, &me_inv_m).is_ok());

        qs_write.commit(au)
    }

    fn init_admin_authsession_sid(idms: &IdmServer, au: &mut AuditScope) -> Uuid {
        let mut idms_write = idms.write();
        let admin_init = AuthEvent::named_init("admin");

        let r1 = idms_write.auth(au, &admin_init);
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        match state {
            AuthState::Continue(_) => {}
            _ => {
                error!("Sessions was not initialised");
                panic!();
            }
        };

        idms_write.commit().expect("Must not fail");

        sessionid
    }

    #[test]
    fn test_idm_simple_password_auth() {
        run_idm_test!(|qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            init_admin_w_password(au, qs, TEST_PASSWORD).expect("Failed to setup admin account");
            let sid = init_admin_authsession_sid(idms, au);

            let mut idms_write = idms.write();
            let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD);

            // Expect success
            let r2 = idms_write.auth(au, &anon_step);
            println!("r2 ==> {:?}", r2);

            match r2 {
                Ok(ar) => {
                    let AuthResult {
                        sessionid: _,
                        state,
                    } = ar;
                    match state {
                        AuthState::Success(_uat) => {
                            // Check the uat.
                        }
                        _ => {
                            error!("A critical error has occured! We have a non-succcess result!");
                            panic!();
                        }
                    }
                }
                Err(e) => {
                    error!("A critical error has occured! {:?}", e);
                    // Should not occur!
                    panic!();
                }
            };

            idms_write.commit().expect("Must not fail");
        })
    }

    #[test]
    fn test_idm_simple_password_invalid() {
        run_idm_test!(|qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            init_admin_w_password(au, qs, TEST_PASSWORD).expect("Failed to setup admin account");
            let sid = init_admin_authsession_sid(idms, au);
            let mut idms_write = idms.write();
            let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD_INC);

            // Expect success
            let r2 = idms_write.auth(au, &anon_step);
            println!("r2 ==> {:?}", r2);

            match r2 {
                Ok(ar) => {
                    let AuthResult {
                        sessionid: _,
                        state,
                    } = ar;
                    match state {
                        AuthState::Denied(_reason) => {
                            // Check the uat.
                        }
                        _ => {
                            error!("A critical error has occured! We have a non-denied result!");
                            panic!();
                        }
                    }
                }
                Err(e) => {
                    error!("A critical error has occured! {:?}", e);
                    // Should not occur!
                    panic!();
                }
            };

            idms_write.commit().expect("Must not fail");
        })
    }
}

use crate::audit::AuditScope;
use crate::constants::UUID_SYSTEM_CONFIG;
use crate::constants::{AUTH_SESSION_TIMEOUT, PW_MIN_LENGTH};
use crate::event::{AuthEvent, AuthEventStep, AuthResult};
use crate::idm::account::Account;
use crate::idm::authsession::AuthSession;
use crate::idm::event::{
    GeneratePasswordEvent, PasswordChangeEvent, RadiusAuthTokenEvent, RegenerateRadiusSecretEvent,
};
use crate::idm::radius::RadiusAccount;
use crate::server::QueryServerReadTransaction;
use crate::server::{QueryServer, QueryServerTransaction, QueryServerWriteTransaction};
use crate::utils::{password_from_random, readable_password_from_random, uuid_from_duration, SID};
use crate::value::PartialValue;

use kanidm_proto::v1::AuthState;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::RadiusAuthToken;

use concread::collections::bptree::*;
use std::time::Duration;
use uuid::Uuid;
use zxcvbn;

pub struct IdmServer {
    // There is a good reason to keep this single thread - it
    // means that limits to sessions can be easily applied and checked to
    // variaous accounts, and we have a good idea of how to structure the
    // in memory caches related to locking.
    sessions: BptreeMap<Uuid, AuthSession>,
    // Need a reference to the query server.
    qs: QueryServer,
    // thread/server id
    sid: SID,
}

pub struct IdmServerWriteTransaction<'a> {
    // Contains methods that require writes, but in the context of writing to
    // the idm in memory structures (maybe the query server too). This is
    // things like authentication
    sessions: BptreeMapWriteTxn<'a, Uuid, AuthSession>,
    qs: &'a QueryServer,
    sid: &'a SID,
}

pub struct IdmServerProxyReadTransaction {
    // This contains read-only methods, like getting users, groups
    // and other structured content.
    pub qs_read: QueryServerReadTransaction,
}

pub struct IdmServerProxyWriteTransaction<'a> {
    // This does NOT take any read to the memory content, allowing safe
    // qs operations to occur through this interface.
    pub qs_write: QueryServerWriteTransaction<'a>,
}

impl IdmServer {
    // TODO #59: Make number of authsessions configurable!!!
    pub fn new(qs: QueryServer, sid: SID) -> IdmServer {
        IdmServer {
            sessions: BptreeMap::new(),
            qs,
            sid,
        }
    }

    pub fn write(&self) -> IdmServerWriteTransaction {
        IdmServerWriteTransaction {
            sessions: self.sessions.write(),
            qs: &self.qs,
            sid: &self.sid,
        }
    }

    pub fn proxy_read(&self) -> IdmServerProxyReadTransaction {
        IdmServerProxyReadTransaction {
            qs_read: self.qs.read(),
        }
    }

    pub fn proxy_write(&self) -> IdmServerProxyWriteTransaction {
        IdmServerProxyWriteTransaction {
            qs_write: self.qs.write(),
        }
    }
}

impl<'a> IdmServerWriteTransaction<'a> {
    #[cfg(test)]
    pub fn is_sessionid_present(&self, sessionid: &Uuid) -> bool {
        self.sessions.contains_key(sessionid)
    }

    pub fn expire_auth_sessions(&mut self, ct: Duration) {
        // ct is current time - sub the timeout. and then split.
        let expire = ct - Duration::from_secs(AUTH_SESSION_TIMEOUT);
        let split_at = uuid_from_duration(expire, *self.sid);
        // Removes older sessions in place.
        self.sessions.split_off_lt(&split_at);
        // expired will now be dropped, and can't be used by future sessions.
    }

    pub fn auth(
        &mut self,
        au: &mut AuditScope,
        ae: &AuthEvent,
        ct: Duration,
    ) -> Result<AuthResult, OperationError> {
        audit_log!(au, "Received AuthEvent -> {:?}", ae);

        // Match on the auth event, to see what we need to do.

        match &ae.step {
            AuthEventStep::Init(init) => {
                // Allocate a session id, based on current time.
                let sessionid = uuid_from_duration(ct, *self.sid);

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
                let account = Account::try_from_entry_ro(au, entry, &qs_read)?;
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
                    sessionid,
                    state: AuthState::Continue(next_mech),
                })
            }
            AuthEventStep::Creds(creds) => {
                // Do we have a session?
                let auth_session = try_audit!(
                    au,
                    self.sessions
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

impl IdmServerProxyReadTransaction {
    pub fn get_radiusauthtoken(
        &self,
        au: &mut AuditScope,
        rate: &RadiusAuthTokenEvent,
    ) -> Result<RadiusAuthToken, OperationError> {
        // TODO: This needs to be an impersonate search!
        let account_entry = try_audit!(
            au,
            self.qs_read
                .impersonate_search_ext_uuid(au, &rate.target, &rate.event)
        );
        let account = try_audit!(
            au,
            RadiusAccount::try_from_entry_reduced(au, account_entry, &self.qs_read)
        );

        account.to_radiusauthtoken()
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn set_account_password(
        &mut self,
        au: &mut AuditScope,
        pce: &PasswordChangeEvent,
    ) -> Result<(), OperationError> {
        // Get the account
        let account_entry = try_audit!(au, self.qs_write.internal_search_uuid(au, &pce.target));
        let account = try_audit!(
            au,
            Account::try_from_entry_rw(au, account_entry, &self.qs_write)
        );
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            return Err(OperationError::SystemProtectedObject);
        }

        // Question: Is it a security issue to reveal pw policy checks BEFORE permission is
        // determined over the credential modification?
        //
        // I don't think so - because we should only be showing how STRONG the pw is ...

        // password strength and badlisting is always global, rather than per-pw-policy.
        // pw-policy as check on the account is about requirements for mfa for example.
        //

        // is the password at least 10 char?
        if pce.cleartext.len() < PW_MIN_LENGTH {
            return Err(OperationError::PasswordTooShort(PW_MIN_LENGTH));
        }

        // does the password pass zxcvbn?

        // Get related inputs, such as account name, email, etc.
        let related: Vec<&str> = vec![
            account.name.as_str(),
            account.displayname.as_str(),
            account.spn.as_str(),
        ];

        let entropy = try_audit!(
            au,
            zxcvbn::zxcvbn(pce.cleartext.as_str(), related.as_slice())
                .map_err(|_| OperationError::PasswordEmpty)
        );

        // check account pwpolicy (for 3 or 4)? Do we need pw strength beyond this
        // or should we be enforcing mfa instead
        if entropy.score() < 3 {
            // The password is too week as per:
            // https://docs.rs/zxcvbn/2.0.0/zxcvbn/struct.Entropy.html
            let feedback: zxcvbn::feedback::Feedback = entropy
                .feedback()
                .as_ref()
                .ok_or(OperationError::InvalidState)
                .map(|v| v.clone())
                .map_err(|e| {
                    audit_log!(au, "zxcvbn returned no feedback when score < 3");
                    e
                })?;

            audit_log!(au, "pw feedback -> {:?}", feedback);

            // return Err(OperationError::PasswordTooWeak(feedback))
            return Err(OperationError::PasswordTooWeak);
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        let lc_password = PartialValue::new_iutf8s(pce.cleartext.as_str());
        let badlist_entry = try_audit!(
            au,
            self.qs_write.internal_search_uuid(au, &UUID_SYSTEM_CONFIG)
        );
        if badlist_entry.attribute_value_pres("badlist_password", &lc_password) {
            audit_log!(au, "Password found in badlist, rejecting");
            return Err(OperationError::PasswordBadListed);
        }

        // it returns a modify
        let modlist = try_audit!(
            au,
            account.gen_password_mod(pce.cleartext.as_str(), &pce.appid)
        );
        audit_log!(au, "processing change {:?}", modlist);
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        try_audit!(
            au,
            self.qs_write.impersonate_modify(
                au,
                // Filter as executed
                filter!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                // Filter as intended (acp)
                filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                modlist,
                &pce.event,
            )
        );

        Ok(())
    }

    pub fn recover_account(
        &mut self,
        au: &mut AuditScope,
        name: String,
        cleartext: String,
    ) -> Result<(), OperationError> {
        // name to uuid
        let target = try_audit!(au, self.qs_write.name_to_uuid(au, name.as_str()));
        // internal pce.
        let pce = PasswordChangeEvent::new_internal(&target, cleartext.as_str(), None);
        // now set_account_password.
        self.set_account_password(au, &pce)
    }

    pub fn generate_account_password(
        &mut self,
        au: &mut AuditScope,
        gpe: &GeneratePasswordEvent,
    ) -> Result<String, OperationError> {
        // Get the account
        let account_entry = try_audit!(au, self.qs_write.internal_search_uuid(au, &gpe.target));
        let account = try_audit!(
            au,
            Account::try_from_entry_rw(au, account_entry, &self.qs_write)
        );
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the target account is anonymous!
        if account.is_anonymous() {
            return Err(OperationError::SystemProtectedObject);
        }

        // Generate a new random, long pw.
        // Because this is generated, we can bypass policy checks!
        let cleartext = password_from_random();

        // check a password badlist - even if generated, we still don't want to
        // reuse something that has been disclosed.

        // it returns a modify
        let modlist = try_audit!(au, account.gen_password_mod(cleartext.as_str(), &gpe.appid));
        audit_log!(au, "processing change {:?}", modlist);
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        try_audit!(
            au,
            self.qs_write.impersonate_modify(
                au,
                // Filter as executed
                filter!(f_eq("uuid", PartialValue::new_uuidr(&gpe.target))),
                // Filter as intended (acp)
                filter_all!(f_eq("uuid", PartialValue::new_uuidr(&gpe.target))),
                modlist,
                // Provide the event to impersonate
                &gpe.event,
            )
        );

        Ok(cleartext)
    }

    pub fn regenerate_radius_secret(
        &mut self,
        au: &mut AuditScope,
        rrse: &RegenerateRadiusSecretEvent,
    ) -> Result<String, OperationError> {
        // regenerates and returns the radius secret
        let account_entry = try_audit!(au, self.qs_write.internal_search_uuid(au, &rrse.target));
        let account = try_audit!(
            au,
            Account::try_from_entry_rw(au, account_entry, &self.qs_write)
        );
        // Deny the change if the target account is anonymous!
        if account.is_anonymous() {
            return Err(OperationError::SystemProtectedObject);
        }

        // Difference to the password above, this is intended to be read/copied
        // by a human wiath a keyboard in some cases.
        let cleartext = readable_password_from_random();

        // Create a modlist from the change.
        let modlist = try_audit!(au, account.regenerate_radius_secret_mod(cleartext.as_str()));
        audit_log!(au, "processing change {:?}", modlist);

        // Apply it.
        try_audit!(
            au,
            self.qs_write.impersonate_modify(
                au,
                // Filter as executed
                filter!(f_eq("uuid", PartialValue::new_uuidr(&rrse.target))),
                // Filter as intended (acp)
                filter_all!(f_eq("uuid", PartialValue::new_uuidr(&rrse.target))),
                modlist,
                // Provide the event to impersonate
                &rrse.event,
            )
        );

        Ok(cleartext)
    }

    pub fn commit(self, au: &mut AuditScope) -> Result<(), OperationError> {
        self.qs_write.commit(au)
    }
}

// Need tests of the sessions and the auth ...

#[cfg(test)]
mod tests {
    use crate::constants::{AUTH_SESSION_TIMEOUT, UUID_ADMIN, UUID_ANONYMOUS};
    use crate::credential::Credential;
    use crate::event::{AuthEvent, AuthResult, ModifyEvent};
    use crate::idm::event::{
        PasswordChangeEvent, RadiusAuthTokenEvent, RegenerateRadiusSecretEvent,
    };
    use crate::modify::{Modify, ModifyList};
    use crate::value::{PartialValue, Value};
    use kanidm_proto::v1::OperationError;
    use kanidm_proto::v1::{AuthAllowed, AuthState};

    use crate::audit::AuditScope;
    use crate::idm::server::IdmServer;
    use crate::server::QueryServer;
    use std::time::Duration;
    use uuid::Uuid;

    static TEST_PASSWORD: &'static str = "ntaoeuntnaoeuhraohuercahu😍";
    static TEST_PASSWORD_INC: &'static str = "ntaoentu nkrcgaeunhibwmwmqj;k wqjbkx ";
    static TEST_CURRENT_TIME: u64 = 6000;
    static TEST_CURRENT_EXPIRE: u64 = TEST_CURRENT_TIME + AUTH_SESSION_TIMEOUT + 1;

    #[test]
    fn test_idm_anonymous_auth() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            let sid = {
                // Start and test anonymous auth.
                let mut idms_write = idms.write();
                // Send the initial auth event for initialising the session
                let anon_init = AuthEvent::anonymous_init();
                // Expect success
                let r1 = idms_write.auth(au, &anon_init, Duration::from_secs(TEST_CURRENT_TIME));
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
                let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
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
                let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
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

        let r1 = idms_write.auth(au, &admin_init, Duration::from_secs(TEST_CURRENT_TIME));
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
            let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
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
            let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
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

    #[test]
    fn test_idm_simple_password_reset() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD, None);

            let mut idms_prox_write = idms.proxy_write();
            assert!(idms_prox_write.set_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.set_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.commit(au).is_ok());
        })
    }

    #[test]
    fn test_idm_anonymous_set_password_denied() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            let pce = PasswordChangeEvent::new_internal(&UUID_ANONYMOUS, TEST_PASSWORD, None);

            let mut idms_prox_write = idms.proxy_write();
            assert!(idms_prox_write.set_account_password(au, &pce).is_err());
            assert!(idms_prox_write.commit(au).is_ok());
        })
    }

    #[test]
    fn test_idm_session_expire() {
        run_idm_test!(|qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            init_admin_w_password(au, qs, TEST_PASSWORD).expect("Failed to setup admin account");
            let sid = init_admin_authsession_sid(idms, au);
            let mut idms_write = idms.write();
            assert!(idms_write.is_sessionid_present(&sid));
            // Expire like we are currently "now". Should not affect our session.
            idms_write.expire_auth_sessions(Duration::from_secs(TEST_CURRENT_TIME));
            assert!(idms_write.is_sessionid_present(&sid));
            // Expire as though we are in the future.
            idms_write.expire_auth_sessions(Duration::from_secs(TEST_CURRENT_EXPIRE));
            assert!(!idms_write.is_sessionid_present(&sid));
            assert!(idms_write.commit().is_ok());
            let idms_write = idms.write();
            assert!(!idms_write.is_sessionid_present(&sid));
        })
    }

    #[test]
    fn test_idm_regenerate_radius_secret() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            let mut idms_prox_write = idms.proxy_write();
            let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());

            // Generates a new credential when none exists
            let r1 = idms_prox_write
                .regenerate_radius_secret(au, &rrse)
                .expect("Failed to reset radius credential 1");
            // Regenerates and overwrites the radius credential
            let r2 = idms_prox_write
                .regenerate_radius_secret(au, &rrse)
                .expect("Failed to reset radius credential 2");
            assert!(r1 != r2);
        })
    }

    #[test]
    fn test_idm_radiusauthtoken() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            let mut idms_prox_write = idms.proxy_write();
            let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());
            let r1 = idms_prox_write
                .regenerate_radius_secret(au, &rrse)
                .expect("Failed to reset radius credential 1");
            idms_prox_write.commit(au).expect("failed to commit");

            let idms_prox_read = idms.proxy_read();
            let rate = RadiusAuthTokenEvent::new_internal(UUID_ADMIN.clone());
            let tok_r = idms_prox_read
                .get_radiusauthtoken(au, &rate)
                .expect("Failed to generate radius auth token");

            // view the token?
            assert!(r1 == tok_r.secret);
        })
    }

    #[test]
    fn test_idm_simple_password_reject_weak() {
        run_idm_test!(|_qs: &QueryServer, idms: &IdmServer, au: &mut AuditScope| {
            // len check
            let mut idms_prox_write = idms.proxy_write();

            let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "password", None);
            let e = idms_prox_write.set_account_password(au, &pce);
            assert!(e.is_err());

            // zxcvbn check
            let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "password1234", None);
            let e = idms_prox_write.set_account_password(au, &pce);
            assert!(e.is_err());

            // Check the "name" checking works too (I think admin may hit a common pw rule first)
            let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "admin_nta", None);
            let e = idms_prox_write.set_account_password(au, &pce);
            assert!(e.is_err());

            // Check that the demo badlist password is rejected.
            let pce = PasswordChangeEvent::new_internal(
                &UUID_ADMIN,
                "demo_badlist_shohfie3aeci2oobur0aru9uushah6EiPi2woh4hohngoighaiRuepieN3ongoo1",
                None,
            );
            let e = idms_prox_write.set_account_password(au, &pce);
            assert!(e.is_err());

            assert!(idms_prox_write.commit(au).is_ok());
        })
    }
}

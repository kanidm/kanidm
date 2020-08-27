use crate::audit::AuditScope;
use crate::constants::{AUTH_SESSION_TIMEOUT, MFAREG_SESSION_TIMEOUT, PW_MIN_LENGTH};
use crate::constants::{UUID_ANONYMOUS, UUID_SYSTEM_CONFIG};
use crate::credential::policy::CryptoPolicy;
use crate::event::{AuthEvent, AuthEventStep, AuthResult};
use crate::idm::account::Account;
use crate::idm::authsession::AuthSession;
use crate::idm::event::{
    GeneratePasswordEvent, GenerateTOTPEvent, LdapAuthEvent, PasswordChangeEvent,
    RadiusAuthTokenEvent, RegenerateRadiusSecretEvent, UnixGroupTokenEvent,
    UnixPasswordChangeEvent, UnixUserAuthEvent, UnixUserTokenEvent, VerifyTOTPEvent,
};
use crate::idm::mfareg::{MfaRegCred, MfaRegNext, MfaRegSession, MfaReqInit, MfaReqStep};
use crate::idm::radius::RadiusAccount;
use crate::idm::unix::{UnixGroup, UnixUserAccount};
use crate::ldap::LdapBoundToken;
use crate::server::QueryServerReadTransaction;
use crate::server::{QueryServer, QueryServerTransaction, QueryServerWriteTransaction};
use crate::utils::{password_from_random, readable_password_from_random, uuid_from_duration, SID};
use crate::value::PartialValue;

use crate::idm::delayed::{DelayedAction, PasswordUpgrade, UnixPasswordUpgrade};

use kanidm_proto::v1::AuthState;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::RadiusAuthToken;
// use kanidm_proto::v1::TOTPSecret as ProtoTOTPSecret;
use kanidm_proto::v1::SetCredentialResponse;
use kanidm_proto::v1::UnixGroupToken;
use kanidm_proto::v1::UnixUserToken;

use std::sync::Arc;

// use crossbeam::channel::{unbounded, Sender, Receiver, TryRecvError};
#[cfg(test)]
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{
    unbounded_channel as unbounded, UnboundedReceiver as Receiver, UnboundedSender as Sender,
};
use tokio::sync::{Semaphore, SemaphorePermit};

use async_std::task;

use concread::bptree::{BptreeMap, BptreeMapWriteTxn};
use rand::prelude::*;
use std::time::Duration;
use uuid::Uuid;

pub struct IdmServer {
    // There is a good reason to keep this single thread - it
    // means that limits to sessions can be easily applied and checked to
    // variaous accounts, and we have a good idea of how to structure the
    // in memory caches related to locking.
    session_ticket: Arc<Semaphore>,
    sessions: BptreeMap<Uuid, AuthSession>,
    // Keep a set of inprogress mfa registrations
    mfareg_sessions: BptreeMap<Uuid, MfaRegSession>,
    // Need a reference to the query server.
    qs: QueryServer,
    // The configured crypto policy for the IDM server. Later this could be transactional
    // and loaded from the db similar to access. But today it's just to allow dynamic pbkdf2rounds
    crypto_policy: CryptoPolicy,
    async_tx: Sender<DelayedAction>,
}

pub struct IdmServerWriteTransaction<'a> {
    // Contains methods that require writes, but in the context of writing to
    // the idm in memory structures (maybe the query server too). This is
    // things like authentication
    _session_ticket: SemaphorePermit<'a>,
    sessions: BptreeMapWriteTxn<'a, Uuid, AuthSession>,
    pub qs_read: QueryServerReadTransaction<'a>,
    // thread/server id
    sid: SID,
    // For flagging eventual actions.
    async_tx: Sender<DelayedAction>,
}

pub struct IdmServerProxyReadTransaction<'a> {
    // This contains read-only methods, like getting users, groups
    // and other structured content.
    pub qs_read: QueryServerReadTransaction<'a>,
}

pub struct IdmServerProxyWriteTransaction<'a> {
    // This does NOT take any read to the memory content, allowing safe
    // qs operations to occur through this interface.
    pub qs_write: QueryServerWriteTransaction<'a>,
    // Associate to an event origin ID, which has a TS and a UUID instead
    mfareg_sessions: BptreeMapWriteTxn<'a, Uuid, MfaRegSession>,
    sid: SID,
    crypto_policy: &'a CryptoPolicy,
}

pub struct IdmServerDelayed {
    async_rx: Receiver<DelayedAction>,
}

impl IdmServer {
    // TODO #59: Make number of authsessions configurable!!!
    pub fn new(qs: QueryServer) -> (IdmServer, IdmServerDelayed) {
        // This is calculated back from:
        //  500 auths / thread -> 0.002 sec per op
        //      we can then spend up to ~0.001s hashing
        //      that means an attacker could possibly have
        //      1000 attempts/sec on a compromised pw.
        // overtime, we could increase this as auth parallelism
        // improves.
        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(1));
        let (async_tx, async_rx) = unbounded();
        (
            IdmServer {
                session_ticket: Arc::new(Semaphore::new(1)),
                sessions: BptreeMap::new(),
                mfareg_sessions: BptreeMap::new(),
                qs,
                crypto_policy,
                async_tx,
            },
            IdmServerDelayed { async_rx },
        )
    }

    pub fn write(&self) -> IdmServerWriteTransaction {
        task::block_on(self.write_async())
    }

    pub async fn write_async<'a>(&'a self) -> IdmServerWriteTransaction<'a> {
        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);

        let qs_read = self.qs.read_async().await;
        let session_ticket = self.session_ticket.acquire().await;

        IdmServerWriteTransaction {
            _session_ticket: session_ticket,
            sessions: self.sessions.write(),
            qs_read,
            sid,
            async_tx: self.async_tx.clone(),
        }
    }

    pub fn proxy_read<'a>(&'a self) -> IdmServerProxyReadTransaction<'a> {
        task::block_on(self.proxy_read_async())
    }

    pub async fn proxy_read_async<'a>(&'a self) -> IdmServerProxyReadTransaction<'a> {
        IdmServerProxyReadTransaction {
            qs_read: self.qs.read_async().await,
        }
    }

    pub fn proxy_write(&self, ts: Duration) -> IdmServerProxyWriteTransaction {
        task::block_on(self.proxy_write_async(ts))
    }

    pub async fn proxy_write_async<'a>(
        &'a self,
        ts: Duration,
    ) -> IdmServerProxyWriteTransaction<'a> {
        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);
        let qs_write = self.qs.write_async(ts).await;

        IdmServerProxyWriteTransaction {
            mfareg_sessions: self.mfareg_sessions.write(),
            qs_write,
            sid,
            crypto_policy: &self.crypto_policy,
        }
    }

    pub(crate) fn delayed_action(
        &self,
        au: &mut AuditScope,
        ts: Duration,
        da: DelayedAction,
    ) -> Result<bool, OperationError> {
        let mut pw = self.proxy_write(ts);
        pw.process_delayedaction(au, da)
            .and_then(|_| pw.commit(au))
            .map(|()| true)
    }
}

impl IdmServerDelayed {
    #[cfg(test)]
    pub fn is_empty_or_panic(&mut self) {
        assert!(self.async_rx.try_recv().is_err());
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&mut self) -> Result<DelayedAction, OperationError> {
        self.async_rx.try_recv().map_err(|e| match e {
            TryRecvError::Empty => OperationError::InvalidState,
            TryRecvError::Closed => OperationError::QueueDisconnected,
        })
    }

    pub(crate) async fn temp_drop_all(&mut self) {
        loop {
            match self.async_rx.recv().await {
                // Drop it
                Some(_) => {}
                // Channel has closed
                None => return,
            }
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
        let split_at = uuid_from_duration(expire, self.sid);
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
        ltrace!(au, "Received -> {:?}", ae);

        // Match on the auth event, to see what we need to do.

        match &ae.step {
            AuthEventStep::Init(init) => {
                lperf_segment!(au, "idm::server::auth<Init>", || {
                    // Allocate a session id, based on current time.
                    let sessionid = uuid_from_duration(ct, self.sid);

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
                    //
                    // Check anything needed? Get the current auth-session-id from request
                    // because it associates to the nonce's etc which were all cached.
                    let euuid = self.qs_read.name_to_uuid(au, init.name.as_str())?;

                    // Get the first / single entry we expect here ....
                    let entry = self.qs_read.internal_search_uuid(au, &euuid)?;

                    lsecurity!(
                        au,
                        "Initiating Authentication Session for ... {:?}: {:?}",
                        euuid,
                        entry
                    );

                    // Now, convert the Entry to an account - this gives us some stronger
                    // typing and functionality so we can assess what auth types can
                    // continue, and helps to keep non-needed entry specific data
                    // out of the LRU.
                    let account = Account::try_from_entry_ro(au, &entry, &mut self.qs_read)?;
                    let auth_session = AuthSession::new(au, account, init.appid.clone());

                    // Get the set of mechanisms that can proceed. This is tied
                    // to the session so that it can mutate state and have progression
                    // of what's next, or ordering.
                    let next_mech = auth_session.valid_auth_mechs();

                    // If we have a session of the same id, return an error (despite how
                    // unlikely this is ...
                    lperf_segment!(au, "idm::server::auth<Init> -> sessions", || {
                        if self.sessions.contains_key(&sessionid) {
                            Err(OperationError::InvalidSessionState)
                        } else {
                            self.sessions.insert(sessionid, auth_session);
                            // Debugging: ensure we really inserted ...
                            debug_assert!(self.sessions.get(&sessionid).is_some());
                            Ok(())
                        }
                    })?;

                    Ok(AuthResult {
                        sessionid,
                        state: AuthState::Continue(next_mech),
                    })
                })
            }
            AuthEventStep::Creds(creds) => {
                lperf_segment!(au, "idm::server::auth<Creds>", || {
                    // Do we have a session?
                    let auth_session = self
                        .sessions
                        // Why is the session missing?
                        .get_mut(&creds.sessionid)
                        .ok_or_else(|| {
                            ladmin_error!(au, "Invalid Session State (no present session uuid)");
                            OperationError::InvalidSessionState
                        })?;
                    // Process the credentials here as required.
                    // Basically throw them at the auth_session and see what
                    // falls out.
                    auth_session
                        .validate_creds(au, &creds.creds, &ct, &self.async_tx)
                        .map(|aus| {
                            AuthResult {
                                // Is this right?
                                sessionid: creds.sessionid,
                                state: aus,
                            }
                        })
                })
            }
        }
    }

    pub fn auth_unix(
        &mut self,
        au: &mut AuditScope,
        uae: &UnixUserAuthEvent,
        _ct: Duration,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        // TODO #59: Implement soft lock checking for unix creds here!

        // Get the entry/target we are working on.
        let account = self
            .qs_read
            .internal_search_uuid(au, &uae.target)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_ro(au, &account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to start auth unix -> {:?}", e);
                e
            })?;

        // Validate the unix_pw - this checks the account/cred lock states.
        account.verify_unix_credential(au, uae.cleartext.as_str(), &self.async_tx)
    }

    pub fn auth_ldap(
        &mut self,
        au: &mut AuditScope,
        lae: &LdapAuthEvent,
        _ct: Duration,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        // TODO #59: Implement soft lock checking for unix creds here!

        let account_entry = self
            .qs_read
            .internal_search_uuid(au, &lae.target)
            .map_err(|e| {
                ladmin_error!(au, "Failed to start auth ldap -> {:?}", e);
                e
            })?;
        /* !!! This would probably be better if we DIDN'T use the Unix/Account types ... ? */

        // if anonymous
        if lae.target == *UUID_ANONYMOUS {
            // TODO: #59 We should have checked if anonymous was locked by now!
            let account = Account::try_from_entry_ro(au, &account_entry, &mut self.qs_read)?;
            // Account must be anon, so we can gen the uat.
            Ok(Some(LdapBoundToken {
                uuid: *UUID_ANONYMOUS,
                effective_uat: account
                    .to_userauthtoken(&[])
                    .ok_or(OperationError::InvalidState)
                    .map_err(|e| {
                        ladmin_error!(au, "Unable to generate effective_uat -> {:?}", e);
                        e
                    })?,
                spn: account.spn,
            }))
        } else {
            let account =
                UnixUserAccount::try_from_entry_ro(au, &account_entry, &mut self.qs_read)?;
            if account
                .verify_unix_credential(au, lae.cleartext.as_str(), &self.async_tx)?
                .is_some()
            {
                // Get the anon uat
                let anon_entry = self
                    .qs_read
                    .internal_search_uuid(au, &UUID_ANONYMOUS)
                    .map_err(|e| {
                        ladmin_error!(au, "Failed to find effective uat for auth ldap -> {:?}", e);
                        e
                    })?;
                let anon_account = Account::try_from_entry_ro(au, &anon_entry, &mut self.qs_read)?;

                Ok(Some(LdapBoundToken {
                    spn: account.spn,
                    uuid: account.uuid,
                    effective_uat: anon_account
                        .to_userauthtoken(&[])
                        .ok_or(OperationError::InvalidState)
                        .map_err(|e| {
                            ladmin_error!(au, "Unable to generate effective_uat -> {:?}", e);
                            e
                        })?,
                }))
            } else {
                Ok(None)
            }
        }
    }

    pub fn commit(self, au: &mut AuditScope) -> Result<(), OperationError> {
        lperf_trace_segment!(au, "idm::server::IdmServerWriteTransaction::commit", || {
            self.sessions.commit();
            Ok(())
        })
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn get_radiusauthtoken(
        &mut self,
        au: &mut AuditScope,
        rate: &RadiusAuthTokenEvent,
    ) -> Result<RadiusAuthToken, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(au, &rate.target, &rate.event)
            .and_then(|account_entry| {
                RadiusAccount::try_from_entry_reduced(au, &account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to start radius auth token {:?}", e);
                e
            })?;

        account.to_radiusauthtoken()
    }

    pub fn get_unixusertoken(
        &mut self,
        au: &mut AuditScope,
        uute: &UnixUserTokenEvent,
    ) -> Result<UnixUserToken, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(au, &uute.target, &uute.event)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_reduced(au, &account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to start unix user token -> {:?}", e);
                e
            })?;

        account.to_unixusertoken()
    }

    pub fn get_unixgrouptoken(
        &mut self,
        au: &mut AuditScope,
        uute: &UnixGroupTokenEvent,
    ) -> Result<UnixGroupToken, OperationError> {
        let group = self
            .qs_read
            .impersonate_search_ext_uuid(au, &uute.target, &uute.event)
            .and_then(|e| UnixGroup::try_from_entry_reduced(&e))
            .map_err(|e| {
                ladmin_error!(au, "Failed to start unix group token {:?}", e);
                e
            })?;
        group.to_unixgrouptoken()
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn expire_mfareg_sessions(&mut self, ct: Duration) {
        // ct is current time - sub the timeout. and then split.
        let expire = ct - Duration::from_secs(MFAREG_SESSION_TIMEOUT);
        let split_at = uuid_from_duration(expire, self.sid);
        // Removes older sessions in place.
        self.mfareg_sessions.split_off_lt(&split_at);
        // expired will now be dropped, and can't be used by future sessions.
    }

    fn check_password_quality(
        &mut self,
        au: &mut AuditScope,
        cleartext: &str,
        related_inputs: &[&str],
    ) -> Result<(), OperationError> {
        // password strength and badlisting is always global, rather than per-pw-policy.
        // pw-policy as check on the account is about requirements for mfa for example.
        //

        // is the password at least 10 char?
        if cleartext.len() < PW_MIN_LENGTH {
            return Err(OperationError::PasswordTooShort(PW_MIN_LENGTH));
        }

        // does the password pass zxcvbn?

        let entropy = zxcvbn::zxcvbn(cleartext, related_inputs).map_err(|e| {
            ladmin_error!(au, "zxcvbn check failure (password empty?) {:?}", e);
            OperationError::PasswordEmpty
        })?;

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
                    lsecurity!(au, "zxcvbn returned no feedback when score < 3");
                    e
                })?;

            lsecurity!(au, "pw feedback -> {:?}", feedback);

            // return Err(OperationError::PasswordTooWeak(feedback))
            return Err(OperationError::PasswordTooWeak);
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        let lc_password = PartialValue::new_iutf8(cleartext);
        let badlist_entry = self
            .qs_write
            .internal_search_uuid(au, &UUID_SYSTEM_CONFIG)
            .map_err(|e| {
                ladmin_error!(au, "Failed to retrieve system configuration {:?}", e);
                e
            })?;
        if badlist_entry.attribute_value_pres("badlist_password", &lc_password) {
            lsecurity!(au, "Password found in badlist, rejecting");
            Err(OperationError::PasswordBadListed)
        } else {
            Ok(())
        }
    }

    fn target_to_account(
        &mut self,
        au: &mut AuditScope,
        target: &Uuid,
    ) -> Result<Account, OperationError> {
        // Get the account
        let account = self
            .qs_write
            .internal_search_uuid(au, target)
            .and_then(|account_entry| {
                Account::try_from_entry_rw(au, &account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to search account {:?}", e);
                e
            })?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            Err(OperationError::SystemProtectedObject)
        } else {
            Ok(account)
        }
    }

    pub fn set_account_password(
        &mut self,
        au: &mut AuditScope,
        pce: &PasswordChangeEvent,
    ) -> Result<(), OperationError> {
        let account = self.target_to_account(au, &pce.target)?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Question: Is it a security issue to reveal pw policy checks BEFORE permission is
        // determined over the credential modification?
        //
        // I don't think so - because we should only be showing how STRONG the pw is ...

        // Get related inputs, such as account name, email, etc.
        let related_inputs: Vec<&str> = vec![
            account.name.as_str(),
            account.displayname.as_str(),
            account.spn.as_str(),
        ];

        self.check_password_quality(au, pce.cleartext.as_str(), related_inputs.as_slice())
            .map_err(|e| {
                lrequest_error!(au, "check_password_quality -> {:?}", e);
                e
            })?;

        // it returns a modify
        let modlist = account
            .gen_password_mod(pce.cleartext.as_str(), &pce.appid, self.crypto_policy)
            .map_err(|e| {
                ladmin_error!(au, "Failed to generate password mod {:?}", e);
                e
            })?;
        ltrace!(au, "processing change {:?}", modlist);
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                au,
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                &modlist,
                &pce.event,
            )
            .map_err(|e| {
                lrequest_error!(au, "error -> {:?}", e);
                e
            })?;

        Ok(())
    }

    pub fn set_unix_account_password(
        &mut self,
        au: &mut AuditScope,
        pce: &UnixPasswordChangeEvent,
    ) -> Result<(), OperationError> {
        // Get the account
        let account = self
            .qs_write
            .internal_search_uuid(au, &pce.target)
            .and_then(|account_entry| {
                // Assert the account is unix and valid.
                UnixUserAccount::try_from_entry_rw(au, &account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to start set unix account password {:?}", e);
                e
            })?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            return Err(OperationError::SystemProtectedObject);
        }

        // Get related inputs, such as account name, email, etc.
        let related_inputs: Vec<&str> = vec![
            account.name.as_str(),
            account.displayname.as_str(),
            account.spn.as_str(),
        ];

        self.check_password_quality(au, pce.cleartext.as_str(), related_inputs.as_slice())
            .map_err(|e| {
                ladmin_error!(au, "Failed to checked password quality {:?}", e);
                e
            })?;

        // it returns a modify
        let modlist = account
            .gen_password_mod(pce.cleartext.as_str(), self.crypto_policy)
            .map_err(|e| {
                ladmin_error!(au, "Unable to generate password change modlist {:?}", e);
                e
            })?;
        ltrace!(au, "processing change {:?}", modlist);
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                au,
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                &modlist,
                &pce.event,
            )
            .map_err(|e| {
                lrequest_error!(au, "error -> {:?}", e);
                e
            })
            .map(|_| ())
    }

    pub fn recover_account(
        &mut self,
        au: &mut AuditScope,
        name: &str,
        cleartext: &str,
    ) -> Result<(), OperationError> {
        // name to uuid
        let target = self.qs_write.name_to_uuid(au, name).map_err(|e| {
            ladmin_error!(au, "name to uuid failed {:?}", e);
            e
        })?;
        // internal pce.
        let pce = PasswordChangeEvent::new_internal(&target, cleartext, None);
        // now set_account_password.
        self.set_account_password(au, &pce)
    }

    pub fn generate_account_password(
        &mut self,
        au: &mut AuditScope,
        gpe: &GeneratePasswordEvent,
    ) -> Result<String, OperationError> {
        let account = self.target_to_account(au, &gpe.target)?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Generate a new random, long pw.
        // Because this is generated, we can bypass policy checks!
        let cleartext = password_from_random();

        // check a password badlist - even if generated, we still don't want to
        // reuse something that has been disclosed.

        // it returns a modify
        let modlist = account
            .gen_password_mod(cleartext.as_str(), &gpe.appid, self.crypto_policy)
            .map_err(|e| {
                ladmin_error!(au, "Unable to generate password mod {:?}", e);
                e
            })?;

        ltrace!(au, "processing change {:?}", modlist);
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                au,
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&gpe.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&gpe.target))),
                &modlist,
                // Provide the event to impersonate
                &gpe.event,
            )
            .map(|_| cleartext)
            .map_err(|e| {
                ladmin_error!(au, "Failed to generate account password {:?}", e);
                e
            })
    }

    pub fn regenerate_radius_secret(
        &mut self,
        au: &mut AuditScope,
        rrse: &RegenerateRadiusSecretEvent,
    ) -> Result<String, OperationError> {
        let account = self.target_to_account(au, &rrse.target)?;

        // Difference to the password above, this is intended to be read/copied
        // by a human wiath a keyboard in some cases.
        let cleartext = readable_password_from_random();

        // Create a modlist from the change.
        let modlist = account
            .regenerate_radius_secret_mod(cleartext.as_str())
            .map_err(|e| {
                ladmin_error!(au, "Unable to generate radius secret mod {:?}", e);
                e
            })?;
        ltrace!(au, "processing change {:?}", modlist);

        // Apply it.
        self.qs_write
            .impersonate_modify(
                au,
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&rrse.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&rrse.target))),
                &modlist,
                // Provide the event to impersonate
                &rrse.event,
            )
            .map_err(|e| {
                lrequest_error!(au, "error -> {:?}", e);
                e
            })
            .map(|_| cleartext)
    }

    pub fn generate_account_totp(
        &mut self,
        au: &mut AuditScope,
        gte: &GenerateTOTPEvent,
        ct: Duration,
    ) -> Result<SetCredentialResponse, OperationError> {
        let account = self.target_to_account(au, &gte.target)?;
        let sessionid = uuid_from_duration(ct, self.sid);

        let origin = (&gte.event.origin).into();
        let label = gte.label.clone();
        let (session, next) = MfaRegSession::new(origin, account, MfaReqInit::TOTP(label))
            .map_err(|e| {
                ladmin_error!(au, "Unable to start totp MfaRegSession {:?}", e);
                e
            })?;

        let next = next.to_proto(&sessionid);

        // Add session to tree
        self.mfareg_sessions.insert(sessionid, session);
        ltrace!(au, "Start mfa reg session -> {:?}", sessionid);
        Ok(next)
    }

    pub fn verify_account_totp(
        &mut self,
        au: &mut AuditScope,
        vte: &VerifyTOTPEvent,
        ct: Duration,
    ) -> Result<SetCredentialResponse, OperationError> {
        let sessionid = vte.session;
        let origin = (&vte.event.origin).into();
        let chal = vte.chal;

        ltrace!(au, "Attempting to find mfareg_session -> {:?}", sessionid);

        let (next, opt_cred) = self
            .mfareg_sessions
            .get_mut(&sessionid)
            .ok_or(OperationError::InvalidRequestState)
            .and_then(|session| {
                session.step(&origin, &vte.target, MfaReqStep::TOTPVerify(chal), &ct)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to verify totp {:?}", e);
                e
            })?;

        if let (MfaRegNext::Success, Some(MfaRegCred::TOTP(token))) = (&next, opt_cred) {
            // Purge the session.
            let session = self
                .mfareg_sessions
                .remove(&sessionid)
                .ok_or(OperationError::InvalidState)
                .map_err(|e| {
                    ladmin_error!(au, "Session within transaction vanished!");
                    e
                })?;
            // reg the token
            let modlist = session.account.gen_totp_mod(token).map_err(|e| {
                ladmin_error!(au, "Failed to gen totp mod {:?}", e);
                e
            })?;
            // Perform the mod
            self.qs_write
                .impersonate_modify(
                    au,
                    // Filter as executed
                    &filter!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    // Filter as intended (acp)
                    &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    &modlist,
                    &vte.event,
                )
                .map_err(|e| {
                    ladmin_error!(au, "verify_account_totp {:?}", e);
                    e
                })?;
        };

        let next = next.to_proto(&sessionid);
        Ok(next)
    }

    // -- delayed action processing --
    fn process_pwupgrade(
        &mut self,
        au: &mut AuditScope,
        pwu: PasswordUpgrade,
    ) -> Result<(), OperationError> {
        // get the account
        let account = self.target_to_account(au, &pwu.target_uuid)?;

        // check, does the pw still match?
        let same = account.check_credential_pw(pwu.existing_password.as_str(), &pwu.appid)?;

        // if yes, gen the pw mod and apply.
        if same {
            let modlist = account
                .gen_password_mod(
                    pwu.existing_password.as_str(),
                    &pwu.appid,
                    self.crypto_policy,
                )
                .map_err(|e| {
                    ladmin_error!(au, "Unable to generate password mod {:?}", e);
                    e
                })?;

            self.qs_write.internal_modify(
                au,
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pwu.target_uuid))),
                &modlist,
            )
        } else {
            // No action needed, it's probably been changed/updated already.
            Ok(())
        }
    }

    fn process_unixpwupgrade(
        &mut self,
        au: &mut AuditScope,
        pwu: UnixPasswordUpgrade,
    ) -> Result<(), OperationError> {
        let account = self
            .qs_write
            .internal_search_uuid(au, &pwu.target_uuid)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_rw(au, &account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                ladmin_error!(au, "Failed to start unix pw upgrade -> {:?}", e);
                e
            })?;

        let same = account.check_existing_pw(pwu.existing_password.as_str())?;

        if same {
            let modlist = account
                .gen_password_mod(pwu.existing_password.as_str(), self.crypto_policy)
                .map_err(|e| {
                    ladmin_error!(au, "Unable to generate password mod {:?}", e);
                    e
                })?;

            self.qs_write.internal_modify(
                au,
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pwu.target_uuid))),
                &modlist,
            )
        } else {
            Ok(())
        }
    }

    fn process_delayedaction(
        &mut self,
        au: &mut AuditScope,
        da: DelayedAction,
    ) -> Result<(), OperationError> {
        match da {
            DelayedAction::PwUpgrade(pwu) => self.process_pwupgrade(au, pwu),
            DelayedAction::UnixPwUpgrade(upwu) => self.process_unixpwupgrade(au, upwu),
        }
    }

    pub fn commit(self, au: &mut AuditScope) -> Result<(), OperationError> {
        lperf_trace_segment!(au, "idm::server::IdmServerWriteTransaction::commit", || {
            self.mfareg_sessions.commit();
            self.qs_write.commit(au)
        })
    }
}

// Need tests of the sessions and the auth ...

#[cfg(test)]
mod tests {
    use crate::constants::{
        AUTH_SESSION_TIMEOUT, MFAREG_SESSION_TIMEOUT, UUID_ADMIN, UUID_ANONYMOUS,
    };
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::TOTP;
    use crate::credential::{Credential, Password};
    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::event::{AuthEvent, AuthResult, CreateEvent, ModifyEvent};
    use crate::idm::event::{
        GenerateTOTPEvent, PasswordChangeEvent, RadiusAuthTokenEvent, RegenerateRadiusSecretEvent,
        UnixGroupTokenEvent, UnixPasswordChangeEvent, UnixUserAuthEvent, UnixUserTokenEvent,
        VerifyTOTPEvent,
    };
    use crate::modify::{Modify, ModifyList};
    use crate::value::{PartialValue, Value};
    // use crate::idm::delayed::{PasswordUpgrade, DelayedAction};

    use kanidm_proto::v1::OperationError;
    use kanidm_proto::v1::SetCredentialResponse;
    use kanidm_proto::v1::{AuthAllowed, AuthState};

    use crate::audit::AuditScope;
    use crate::idm::server::IdmServer;
    // , IdmServerDelayed;
    use crate::server::QueryServer;
    use crate::utils::duration_from_epoch_now;
    use std::convert::TryFrom;
    use std::time::Duration;
    use uuid::Uuid;

    const TEST_PASSWORD: &'static str = "ntaoeuntnaoeuhraohuercahu😍";
    const TEST_PASSWORD_INC: &'static str = "ntaoentu nkrcgaeunhibwmwmqj;k wqjbkx ";
    const TEST_CURRENT_TIME: u64 = 6000;
    const TEST_CURRENT_EXPIRE: u64 = TEST_CURRENT_TIME + AUTH_SESSION_TIMEOUT + 1;

    #[test]
    fn test_idm_anonymous_auth() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let sid = {
                // Start and test anonymous auth.
                let mut idms_write = idms.write();
                // Send the initial auth event for initialising the session
                let anon_init = AuthEvent::anonymous_init();
                // Expect success
                let r1 = idms_write.auth(au, &anon_init, Duration::from_secs(TEST_CURRENT_TIME));
                /* Some weird lifetime shit happens here ... */

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

                debug!("sessionid is ==> {:?}", sid);

                idms_write.commit(au).expect("Must not fail");

                sid
            };
            {
                let mut idms_write = idms.write();
                // Now send the anonymous request, given the session id.
                let anon_step = AuthEvent::cred_step_anonymous(sid);

                // Expect success
                let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
                debug!("r2 ==> {:?}", r2);

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

                idms_write.commit(au).expect("Must not fail");
            }
        });
    }

    // Test sending anonymous but with no session init.
    #[test]
    fn test_idm_anonymous_auth_invalid_states() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            {
                let mut idms_write = idms.write();
                let sid = Uuid::new_v4();
                let anon_step = AuthEvent::cred_step_anonymous(sid);

                // Expect failure
                let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
                debug!("r2 ==> {:?}", r2);

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
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw)?;
        let v_cred = Value::new_credential("primary", cred);
        let qs_write = qs.write(duration_from_epoch_now());

        // now modify and provide a primary credential.
        let me_inv_m = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("admin"))),
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

        idms_write.commit(au).expect("Must not fail");

        sessionid
    }

    fn check_admin_password(idms: &IdmServer, au: &mut AuditScope, pw: &str) {
        let sid = init_admin_authsession_sid(idms, au);

        let mut idms_write = idms.write();
        let anon_step = AuthEvent::cred_step_password(sid, pw);

        // Expect success
        let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
        debug!("r2 ==> {:?}", r2);

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

        idms_write.commit(au).expect("Must not fail");
    }

    #[test]
    fn test_idm_simple_password_auth() {
        run_idm_test!(|qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            init_admin_w_password(au, qs, TEST_PASSWORD).expect("Failed to setup admin account");
            check_admin_password(idms, au, TEST_PASSWORD);
        })
    }

    #[test]
    fn test_idm_simple_password_spn_auth() {
        run_idm_test!(|qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            init_admin_w_password(au, qs, TEST_PASSWORD).expect("Failed to setup admin account");
            let mut idms_write = idms.write();
            let admin_init = AuthEvent::named_init("admin@example.com");

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

            idms_write.commit(au).expect("Must not fail");

            let sid = sessionid;

            let mut idms_write = idms.write();
            let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD);

            // Expect success
            let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
            debug!("r2 ==> {:?}", r2);

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

            idms_write.commit(au).expect("Must not fail");
        })
    }

    #[test]
    fn test_idm_simple_password_invalid() {
        run_idm_test!(|qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            init_admin_w_password(au, qs, TEST_PASSWORD).expect("Failed to setup admin account");
            let sid = init_admin_authsession_sid(idms, au);
            let mut idms_write = idms.write();
            let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD_INC);

            // Expect success
            let r2 = idms_write.auth(au, &anon_step, Duration::from_secs(TEST_CURRENT_TIME));
            debug!("r2 ==> {:?}", r2);

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

            idms_write.commit(au).expect("Must not fail");
        })
    }

    #[test]
    fn test_idm_simple_password_reset() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD, None);

            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            assert!(idms_prox_write.set_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.set_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.commit(au).is_ok());
        })
    }

    #[test]
    fn test_idm_anonymous_set_password_denied() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let pce = PasswordChangeEvent::new_internal(&UUID_ANONYMOUS, TEST_PASSWORD, None);

            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            assert!(idms_prox_write.set_account_password(au, &pce).is_err());
            assert!(idms_prox_write.commit(au).is_ok());
        })
    }

    #[test]
    fn test_idm_session_expire() {
        run_idm_test!(|qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
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
            assert!(idms_write.commit(au).is_ok());
            let idms_write = idms.write();
            assert!(!idms_write.is_sessionid_present(&sid));
        })
    }

    #[test]
    fn test_idm_regenerate_radius_secret() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
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
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());
            let r1 = idms_prox_write
                .regenerate_radius_secret(au, &rrse)
                .expect("Failed to reset radius credential 1");
            idms_prox_write.commit(au).expect("failed to commit");

            let mut idms_prox_read = idms.proxy_read();
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
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            // len check
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());

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

    #[test]
    fn test_idm_unixusertoken() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            // Modify admin to have posixaccount
            let me_posix = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("admin"))),
                    ModifyList::new_list(vec![
                        Modify::Present("class".to_string(), Value::new_class("posixaccount")),
                        Modify::Present("gidnumber".to_string(), Value::new_uint32(2001)),
                    ]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(au, &me_posix).is_ok());
            // Add a posix group that has the admin as a member.
            let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
                r#"{
                "attrs": {
                    "class": ["object", "group", "posixgroup"],
                    "name": ["testgroup"],
                    "uuid": ["01609135-a1c4-43d5-966b-a28227644445"],
                    "description": ["testgroup"],
                    "member": ["00000000-0000-0000-0000-000000000000"]
                }
            }"#,
            );

            let ce = CreateEvent::new_internal(vec![e.clone()]);

            assert!(idms_prox_write.qs_write.create(au, &ce).is_ok());

            idms_prox_write.commit(au).expect("failed to commit");

            let mut idms_prox_read = idms.proxy_read();

            let ugte = UnixGroupTokenEvent::new_internal(
                Uuid::parse_str("01609135-a1c4-43d5-966b-a28227644445")
                    .expect("failed to parse uuid"),
            );
            let tok_g = idms_prox_read
                .get_unixgrouptoken(au, &ugte)
                .expect("Failed to generate unix group token");

            assert!(tok_g.name == "testgroup");
            assert!(tok_g.spn == "testgroup@example.com");

            let uute = UnixUserTokenEvent::new_internal(UUID_ADMIN.clone());
            let tok_r = idms_prox_read
                .get_unixusertoken(au, &uute)
                .expect("Failed to generate unix user token");

            assert!(tok_r.name == "admin");
            assert!(tok_r.spn == "admin@example.com");
            assert!(tok_r.groups.len() == 2);
            assert!(tok_r.groups[0].name == "admin");
            assert!(tok_r.groups[1].name == "testgroup");

            // Show we can get the admin as a unix group token too
            let ugte = UnixGroupTokenEvent::new_internal(
                Uuid::parse_str("00000000-0000-0000-0000-000000000000")
                    .expect("failed to parse uuid"),
            );
            let tok_g = idms_prox_read
                .get_unixgrouptoken(au, &ugte)
                .expect("Failed to generate unix group token");

            assert!(tok_g.name == "admin");
            assert!(tok_g.spn == "admin@example.com");
        })
    }

    #[test]
    fn test_idm_simple_unix_password_reset() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            // make the admin a valid posix account
            let me_posix = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("admin"))),
                    ModifyList::new_list(vec![
                        Modify::Present("class".to_string(), Value::new_class("posixaccount")),
                        Modify::Present("gidnumber".to_string(), Value::new_uint32(2001)),
                    ]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(au, &me_posix).is_ok());

            let pce = UnixPasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);

            assert!(idms_prox_write.set_unix_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.set_unix_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.commit(au).is_ok());

            let mut idms_write = idms.write();
            // Check auth verification of the password

            let uuae_good = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
            let a1 = idms_write.auth_unix(au, &uuae_good, Duration::from_secs(TEST_CURRENT_TIME));
            match a1 {
                Ok(Some(_tok)) => {}
                _ => assert!(false),
            };
            // Check bad password
            let uuae_bad = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD_INC);
            let a2 = idms_write.auth_unix(au, &uuae_bad, Duration::from_secs(TEST_CURRENT_TIME));
            match a2 {
                Ok(None) => {}
                _ => assert!(false),
            };
            assert!(idms_write.commit(au).is_ok());

            // Check deleting the password
            let idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            let me_purge_up = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("admin"))),
                    ModifyList::new_list(vec![Modify::Purged("unix_password".to_string())]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(au, &me_purge_up).is_ok());
            assert!(idms_prox_write.commit(au).is_ok());

            // And auth should now fail due to the lack of PW material
            let mut idms_write = idms.write();
            let a3 = idms_write.auth_unix(au, &uuae_good, Duration::from_secs(TEST_CURRENT_TIME));
            match a3 {
                Ok(None) => {}
                _ => assert!(false),
            };
            assert!(idms_write.commit(au).is_ok());
        })
    }

    #[test]
    fn test_idm_totp_registration() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let ct = duration_from_epoch_now();
            let expire = Duration::from_secs(ct.as_secs() + MFAREG_SESSION_TIMEOUT + 2);
            let mut idms_prox_write = idms.proxy_write(ct.clone());

            // verify with no session (fail)
            let vte1 = VerifyTOTPEvent::new_internal(UUID_ADMIN.clone(), Uuid::new_v4(), 0);

            match idms_prox_write.verify_account_totp(au, &vte1, ct.clone()) {
                Err(e) => {
                    assert!(e == OperationError::InvalidRequestState);
                }
                _ => panic!(),
            };

            // reg, expire session, attempt verify (fail)
            let gte1 = GenerateTOTPEvent::new_internal(UUID_ADMIN.clone());

            let res = idms_prox_write
                .generate_account_totp(au, &gte1, ct.clone())
                .unwrap();
            let sesid = match res {
                SetCredentialResponse::TOTPCheck(id, _) => id,
                _ => panic!("invalid state!"),
            };
            idms_prox_write.expire_mfareg_sessions(expire.clone());

            let vte2 = VerifyTOTPEvent::new_internal(UUID_ADMIN.clone(), sesid, 0);

            match idms_prox_write.verify_account_totp(au, &vte1, ct.clone()) {
                Err(e) => {
                    assert!(e == OperationError::InvalidRequestState);
                }
                _ => panic!(),
            };

            // == Test TOTP on account with no password (fail)
            let res = idms_prox_write
                .generate_account_totp(au, &gte1, ct.clone())
                .unwrap();
            let (sesid, tok) = match res {
                SetCredentialResponse::TOTPCheck(id, tok) => (id, tok),
                _ => panic!("invalid state!"),
            };
            // get the correct otp
            let r_tok: TOTP = tok.into();
            let chal = r_tok
                .do_totp_duration_from_epoch(&ct)
                .expect("Failed to do totp?");
            // attempt the verify
            let vte3 = VerifyTOTPEvent::new_internal(UUID_ADMIN.clone(), sesid, chal);

            match idms_prox_write.verify_account_totp(au, &vte3, ct.clone()) {
                Err(e) => assert!(e == OperationError::InvalidState),
                _ => panic!(),
            };

            // Expire the session to allow it to reset.
            idms_prox_write.expire_mfareg_sessions(expire.clone());

            // Set a password.
            let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD, None);
            assert!(idms_prox_write.set_account_password(au, &pce).is_ok());

            // == reg, but change the event source part way in the process (failure)
            let res = idms_prox_write
                .generate_account_totp(au, &gte1, ct.clone())
                .unwrap();
            let (sesid, tok) = match res {
                SetCredentialResponse::TOTPCheck(id, tok) => (id, tok),
                _ => panic!("invalid state!"),
            };
            // get the correct otp
            let r_tok: TOTP = tok.into();
            let chal = r_tok
                .do_totp_duration_from_epoch(&ct)
                .expect("Failed to do totp?");
            // attempt the verify
            let vte3 = VerifyTOTPEvent::new_internal(UUID_ANONYMOUS.clone(), sesid, chal);

            match idms_prox_write.verify_account_totp(au, &vte3, ct.clone()) {
                Err(e) => assert!(e == OperationError::InvalidRequestState),
                _ => panic!(),
            };

            // == reg, verify w_ incorrect totp (fail)
            let res = idms_prox_write
                .generate_account_totp(au, &gte1, ct.clone())
                .unwrap();
            let (_sesid, _tok) = match res {
                SetCredentialResponse::TOTPCheck(id, tok) => (id, tok),
                _ => panic!("invalid state!"),
            };

            // We can reuse the OTP/Vte2 from before, since we want the invalid otp.
            match idms_prox_write.verify_account_totp(au, &vte2, ct.clone()) {
                // On failure we get back another attempt to setup the token.
                Ok(SetCredentialResponse::TOTPCheck(_id, _tok)) => {}
                _ => panic!(),
            };
            idms_prox_write.expire_mfareg_sessions(expire.clone());

            // Turn the pts into an otp
            // == reg, verify w_ correct totp (success)
            let res = idms_prox_write
                .generate_account_totp(au, &gte1, ct.clone())
                .unwrap();
            let (sesid, tok) = match res {
                SetCredentialResponse::TOTPCheck(id, tok) => (id, tok),
                _ => panic!("invalid state!"),
            };
            // We can't reuse the OTP/Vte from before, since the token seed changes
            let r_tok: TOTP = tok.into();
            let chal = r_tok
                .do_totp_duration_from_epoch(&ct)
                .expect("Failed to do totp?");
            // attempt the verify
            let vte3 = VerifyTOTPEvent::new_internal(UUID_ADMIN.clone(), sesid, chal);

            match idms_prox_write.verify_account_totp(au, &vte3, ct.clone()) {
                Ok(SetCredentialResponse::Success) => {}
                _ => panic!(),
            };
            idms_prox_write.expire_mfareg_sessions(expire.clone());

            assert!(idms_prox_write.commit(au).is_ok());
        })
    }

    #[test]
    fn test_idm_simple_password_upgrade() {
        run_idm_test!(|qs: &QueryServer,
                       idms: &IdmServer,
                       idms_delayed: &mut IdmServerDelayed,
                       au: &mut AuditScope| {
            // Assert the delayed action queue is empty
            idms_delayed.is_empty_or_panic();
            // Setup the admin w_ an imported password.
            {
                let qs_write = qs.write(duration_from_epoch_now());
                // now modify and provide a primary credential.
                let me_inv_m = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![Modify::Present(
                            "password_import".to_string(),
                            Value::from("{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM")
                        )]),
                    )
                };
                // go!
                assert!(qs_write.modify(au, &me_inv_m).is_ok());
                qs_write.commit(au).expect("failed to commit");
            }
            // Still empty
            idms_delayed.is_empty_or_panic();
            // Do an auth, this will trigger the action to send.
            check_admin_password(idms, au, "password");
            // process it.
            let da = idms_delayed.try_recv().expect("invalid");
            assert!(Ok(true) == idms.delayed_action(au, duration_from_epoch_now(), da));
            // Check the admin pw still matches
            check_admin_password(idms, au, "password");
            // No delayed action was queued.
            idms_delayed.is_empty_or_panic();
        })
    }

    #[test]
    fn test_idm_unix_password_upgrade() {
        run_idm_test!(|qs: &QueryServer,
                       idms: &IdmServer,
                       idms_delayed: &mut IdmServerDelayed,
                       au: &mut AuditScope| {
            // Assert the delayed action queue is empty
            idms_delayed.is_empty_or_panic();
            // Setup the admin with an imported unix pw.
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());

            let im_pw = "{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM";
            let pw = Password::try_from(im_pw).expect("failed to parse");
            let cred = Credential::new_from_password(pw);
            let v_cred = Value::new_credential("unix", cred);

            let me_posix = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("admin"))),
                    ModifyList::new_list(vec![
                        Modify::Present("class".to_string(), Value::new_class("posixaccount")),
                        Modify::Present("gidnumber".to_string(), Value::new_uint32(2001)),
                        Modify::Present("unix_password".to_string(), v_cred),
                    ]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(au, &me_posix).is_ok());
            assert!(idms_prox_write.commit(au).is_ok());
            idms_delayed.is_empty_or_panic();
            // Get the auth ready.
            let uuae = UnixUserAuthEvent::new_internal(&UUID_ADMIN, "password");
            let mut idms_write = idms.write();
            let a1 = idms_write.auth_unix(au, &uuae, Duration::from_secs(TEST_CURRENT_TIME));
            match a1 {
                Ok(Some(_tok)) => {}
                _ => assert!(false),
            };
            idms_write.commit(au).expect("Must not fail");
            // The upgrade was queued
            // Process it.
            let da = idms_delayed.try_recv().expect("invalid");
            assert!(Ok(true) == idms.delayed_action(au, duration_from_epoch_now(), da));
            // Go again
            let mut idms_write = idms.write();
            let a2 = idms_write.auth_unix(au, &uuae, Duration::from_secs(TEST_CURRENT_TIME));
            match a2 {
                Ok(Some(_tok)) => {}
                _ => assert!(false),
            };
            idms_write.commit(au).expect("Must not fail");
            // No delayed action was queued.
            idms_delayed.is_empty_or_panic();
        })
    }
}

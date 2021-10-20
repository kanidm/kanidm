use crate::credential::policy::CryptoPolicy;
use crate::credential::softlock::CredSoftLock;
use crate::credential::webauthn::WebauthnDomainConfig;
use crate::credential::BackupCodes;
use crate::event::{AuthEvent, AuthEventStep, AuthResult};
use crate::identity::{IdentType, IdentUser, Limits};
use crate::idm::account::Account;
use crate::idm::authsession::AuthSession;
use crate::idm::event::{
    AcceptSha1TotpEvent, CredentialStatusEvent, GeneratePasswordEvent, GenerateTotpEvent,
    LdapAuthEvent, PasswordChangeEvent, RadiusAuthTokenEvent, RegenerateRadiusSecretEvent,
    RemoveTotpEvent, RemoveWebauthnEvent, UnixGroupTokenEvent, UnixPasswordChangeEvent,
    UnixUserAuthEvent, UnixUserTokenEvent, VerifyTotpEvent, WebauthnDoRegisterEvent,
    WebauthnInitRegisterEvent,
};
use crate::idm::mfareg::{MfaRegCred, MfaRegNext, MfaRegSession};
use crate::idm::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, AuthorisePermitSuccess,
    ConsentRequest, Oauth2Error, Oauth2ResourceServers, Oauth2ResourceServersReadTransaction,
    Oauth2ResourceServersWriteTransaction,
};
use crate::idm::radius::RadiusAccount;
use crate::idm::unix::{UnixGroup, UnixUserAccount};
use crate::idm::AuthState;
use crate::ldap::LdapBoundToken;
use crate::prelude::*;
use crate::tracing_tree;
use crate::utils::{
    backup_code_from_random, password_from_random, readable_password_from_random,
    uuid_from_duration, Sid,
};

use crate::actors::v1_write::QueryServerWriteV1;
use crate::idm::delayed::{
    DelayedAction, PasswordUpgrade, UnixPasswordUpgrade, WebauthnCounterIncrement,
};

use hashbrown::HashSet;
use kanidm_proto::v1::{
    AuthType, BackupCodesView, CredentialStatus, RadiusAuthToken, SetCredentialResponse,
    UnixGroupToken, UnixUserToken, UserAuthToken,
};
use std::str::FromStr;

use bundy::hs512::HS512;

use tokio::sync::mpsc::{
    unbounded_channel as unbounded, UnboundedReceiver as Receiver, UnboundedSender as Sender,
};
use tokio::sync::Semaphore;

use async_std::task;

use core::task::{Context, Poll};
use futures::task as futures_task;

use concread::{
    bptree::{BptreeMap, BptreeMapWriteTxn},
    CowCell,
};
use concread::{
    cowcell::{CowCellReadTxn, CowCellWriteTxn},
    hashmap::HashMap,
};
use rand::prelude::*;
use std::convert::TryFrom;
use std::{sync::Arc, time::Duration};
use url::Url;

use webauthn_rs::Webauthn;

use super::delayed::BackupCodeRemoval;
use super::event::{GenerateBackupCodeEvent, ReadBackupCodeEvent, RemoveBackupCodeEvent};

use tracing::trace;

pub struct IdmServer {
    // There is a good reason to keep this single thread - it
    // means that limits to sessions can be easily applied and checked to
    // variaous accounts, and we have a good idea of how to structure the
    // in memory caches related to locking.
    session_ticket: Semaphore,
    sessions: BptreeMap<Uuid, AuthSession>,
    // Do we need a softlock ticket?
    softlock_ticket: Semaphore,
    softlocks: HashMap<Uuid, CredSoftLock>,
    /// A set of in progress MFA registrations
    mfareg_sessions: BptreeMap<Uuid, MfaRegSession>,
    /// Reference to the query server.
    qs: QueryServer,
    /// The configured crypto policy for the IDM server. Later this could be transactional and loaded from the db similar to access. But today it's just to allow dynamic pbkdf2rounds
    crypto_policy: CryptoPolicy,
    async_tx: Sender<DelayedAction>,
    /// [Webauthn] verifier/config
    webauthn: Webauthn<WebauthnDomainConfig>,
    pw_badlist_cache: Arc<CowCell<HashSet<String>>>,
    oauth2rs: Arc<Oauth2ResourceServers>,
    uat_bundy_hmac: Arc<CowCell<HS512>>,
}

/// Contains methods that require writes, but in the context of writing to the idm in memory structures (maybe the query server too). This is things like authentication.
pub struct IdmServerAuthTransaction<'a> {
    session_ticket: &'a Semaphore,
    sessions: &'a BptreeMap<Uuid, AuthSession>,

    softlock_ticket: &'a Semaphore,
    softlocks: &'a HashMap<Uuid, CredSoftLock>,
    pub qs_read: QueryServerReadTransaction<'a>,
    /// Thread/Server ID
    sid: Sid,
    // For flagging eventual actions.
    async_tx: Sender<DelayedAction>,
    webauthn: &'a Webauthn<WebauthnDomainConfig>,
    pw_badlist_cache: CowCellReadTxn<HashSet<String>>,
    uat_bundy_hmac: CowCellReadTxn<HS512>,
}

/// This contains read-only methods, like getting users, groups and other structured content.
pub struct IdmServerProxyReadTransaction<'a> {
    pub qs_read: QueryServerReadTransaction<'a>,
    uat_bundy_hmac: CowCellReadTxn<HS512>,
    oauth2rs: Oauth2ResourceServersReadTransaction,
}

pub struct IdmServerProxyWriteTransaction<'a> {
    // This does NOT take any read to the memory content, allowing safe
    // qs operations to occur through this interface.
    pub qs_write: QueryServerWriteTransaction<'a>,
    /// Associate to an event origin ID, which has a TS and a UUID instead
    mfareg_sessions: BptreeMapWriteTxn<'a, Uuid, MfaRegSession>,
    sid: Sid,
    crypto_policy: &'a CryptoPolicy,
    webauthn: &'a Webauthn<WebauthnDomainConfig>,
    pw_badlist_cache: CowCellWriteTxn<'a, HashSet<String>>,
    uat_bundy_hmac: CowCellWriteTxn<'a, HS512>,
    oauth2rs: Oauth2ResourceServersWriteTransaction<'a>,
}

pub struct IdmServerDelayed {
    async_rx: Receiver<DelayedAction>,
}

impl IdmServer {
    // TODO: Make number of authsessions configurable!!!
    pub fn new(
        qs: QueryServer,
        origin: String,
        // ct: Duration,
    ) -> Result<(IdmServer, IdmServerDelayed), OperationError> {
        // This is calculated back from:
        //  500 auths / thread -> 0.002 sec per op
        //      we can then spend up to ~0.001s hashing
        //      that means an attacker could possibly have
        //      1000 attempts/sec on a compromised pw.
        // overtime, we could increase this as auth parallelism
        // improves.
        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(1));
        let (async_tx, async_rx) = unbounded();

        // Get the domain name, as the relying party id.
        let (rp_id, token_key, pw_badlist_set, oauth2rs_set) = {
            let qs_read = task::block_on(qs.read_async());
            (
                qs_read.get_domain_name()?,
                qs_read.get_domain_token_key()?,
                qs_read.get_password_badlist()?,
                // Add a read/reload of all oauth2 configurations.
                qs_read.get_oauth2rs_set()?,
            )
        };

        // Check that it gels with our origin.
        let origin_url = Url::parse(origin.as_str())
            .map_err(|_e| {
                admin_error!("Unable to parse origin URL - refusing to start. You must correct the value for origin. {:?}", origin);
                OperationError::InvalidState
            })
            .and_then(|url| {
                let valid = url.domain().map(|effective_domain| {
                    effective_domain.ends_with(&rp_id)
                }).unwrap_or(false);

                if valid {
                    Ok(url)
                } else {
                    admin_error!("Effective domain is not a descendent of server domain name (rp_id). You must change origin or domain name to be consistent. ed: {:?} - rp_id: {:?}", origin, rp_id);
                    Err(OperationError::InvalidState)
                }
            })?;

        // Now clone to rp_name.
        let rp_name = rp_id.clone();

        let webauthn = Webauthn::new(WebauthnDomainConfig {
            rp_name,
            origin: origin_url,
            rp_id,
        });

        // Setup our auth token signing key.
        let bundy_handle = HS512::from_str(&token_key).map_err(|e| {
            admin_error!("Failed to generate uat_bundy_hmac - {:?}", e);
            OperationError::InvalidState
        })?;
        let uat_bundy_hmac = Arc::new(CowCell::new(bundy_handle));

        let oauth2rs = Oauth2ResourceServers::try_from(oauth2rs_set).map_err(|e| {
            admin_error!("Failed to load oauth2 resource servers - {:?}", e);
            e
        })?;

        Ok((
            IdmServer {
                session_ticket: Semaphore::new(1),
                sessions: BptreeMap::new(),
                softlock_ticket: Semaphore::new(1),
                softlocks: HashMap::new(),
                mfareg_sessions: BptreeMap::new(),
                qs,
                crypto_policy,
                async_tx,
                webauthn,
                pw_badlist_cache: Arc::new(CowCell::new(pw_badlist_set)),
                uat_bundy_hmac,
                oauth2rs: Arc::new(oauth2rs),
            },
            IdmServerDelayed { async_rx },
        ))
    }

    #[cfg(test)]
    pub fn auth(&self) -> IdmServerAuthTransaction {
        task::block_on(self.auth_async())
    }

    pub async fn auth_async(&self) -> IdmServerAuthTransaction<'_> {
        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);

        // let session_ticket = self.session_ticket.acquire().await;
        let qs_read = self.qs.read_async().await;

        IdmServerAuthTransaction {
            // _session_ticket: session_ticket,
            // sessions: self.sessions.write(),
            session_ticket: &self.session_ticket,
            sessions: &self.sessions,
            softlock_ticket: &self.softlock_ticket,
            softlocks: &self.softlocks,
            qs_read,
            sid,
            async_tx: self.async_tx.clone(),
            webauthn: &self.webauthn,
            pw_badlist_cache: self.pw_badlist_cache.read(),
            uat_bundy_hmac: self.uat_bundy_hmac.read(),
        }
    }

    #[cfg(test)]
    pub fn proxy_read<'a>(&'a self) -> IdmServerProxyReadTransaction<'a> {
        task::block_on(self.proxy_read_async())
    }

    pub async fn proxy_read_async(&self) -> IdmServerProxyReadTransaction<'_> {
        IdmServerProxyReadTransaction {
            qs_read: self.qs.read_async().await,
            uat_bundy_hmac: self.uat_bundy_hmac.read(),
            oauth2rs: self.oauth2rs.read(),
        }
    }

    #[cfg(test)]
    pub fn proxy_write(&self, ts: Duration) -> IdmServerProxyWriteTransaction {
        task::block_on(self.proxy_write_async(ts))
    }

    pub async fn proxy_write_async(&self, ts: Duration) -> IdmServerProxyWriteTransaction<'_> {
        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);
        let qs_write = self.qs.write_async(ts).await;

        IdmServerProxyWriteTransaction {
            mfareg_sessions: self.mfareg_sessions.write(),
            qs_write,
            sid,
            crypto_policy: &self.crypto_policy,
            webauthn: &self.webauthn,
            pw_badlist_cache: self.pw_badlist_cache.write(),
            uat_bundy_hmac: self.uat_bundy_hmac.write(),
            oauth2rs: self.oauth2rs.write(),
        }
    }

    #[cfg(test)]
    pub(crate) async fn delayed_action(
        &self,
        ts: Duration,
        da: DelayedAction,
    ) -> Result<bool, OperationError> {
        let mut pw = self.proxy_write_async(ts).await;
        pw.process_delayedaction(da)
            .and_then(|_| pw.commit())
            .map(|()| true)
    }
}

impl IdmServerDelayed {
    pub(crate) fn is_empty_or_panic(&mut self) {
        let waker = futures_task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match self.async_rx.poll_recv(&mut cx) {
            Poll::Pending | Poll::Ready(None) => {}
            Poll::Ready(Some(_m)) => panic!("Task queue not empty"),
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&mut self) -> Result<DelayedAction, OperationError> {
        let waker = futures_task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match self.async_rx.poll_recv(&mut cx) {
            Poll::Pending => Err(OperationError::InvalidState),
            Poll::Ready(None) => Err(OperationError::QueueDisconnected),
            Poll::Ready(Some(m)) => Ok(m),
        }
    }

    pub(crate) async fn process_all(&mut self, server: &'static QueryServerWriteV1) {
        loop {
            match self.async_rx.recv().await {
                // process it.
                Some(da) => server.handle_delayedaction(da).await,
                // Channel has closed
                None => return,
            }
        }
    }
}

pub trait IdmServerTransaction<'a> {
    type QsTransactionType: QueryServerTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType;

    fn get_uat_bundy_txn(&self) -> &HS512;

    // ! TRACING INTEGRATED
    fn validate_and_parse_uat(
        &self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<UserAuthToken, OperationError> {
        // Given the token string, validate and recreate the UAT
        let bref = self.get_uat_bundy_txn();

        let uat: UserAuthToken =
            token
                .ok_or(OperationError::NotAuthenticated)
                .and_then(|token| {
                    bref.verify(token).map_err(|e| {
                        security_info!(?e, "Unable to verify token");
                        OperationError::NotAuthenticated
                    })
                })?;

        if time::OffsetDateTime::unix_epoch() + ct >= uat.expiry {
            security_info!("Session expired");
            Err(OperationError::SessionExpired)
        } else {
            Ok(uat)
        }
    }

    // ! TRACING INTEGRATED
    fn process_uat_to_identity(
        &self,
        uat: &UserAuthToken,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        // From a UAT, get the current identity and associated information.
        let entry = self
            .get_qs_txn()
            .internal_search_uuid(&uat.uuid)
            .map_err(|e| {
                admin_error!(?e, "from_ro_uat failed");
                e
            })?;

        // #59: If the account is expired, do not allow the event
        // to proceed
        let valid = Account::check_within_valid_time(
            ct,
            entry.get_ava_single_datetime("account_valid_from").as_ref(),
            entry.get_ava_single_datetime("account_expire").as_ref(),
        );

        if !valid {
            security_info!("Account has expired or is not yet valid, not allowing to proceed");
            return Err(OperationError::SessionExpired);
        }

        // #64: Now apply claims from the uat into the Entry
        // to allow filtering.
        /*
        entry.insert_claim(match &uat.auth_type {
            AuthType::Anonymous => "authtype_anonymous",
            AuthType::UnixPassword => "authtype_unixpassword",
            AuthType::Password => "authtype_password",
            AuthType::GeneratedPassword => "authtype_generatedpassword",
            AuthType::Webauthn => "authtype_webauthn",
            AuthType::PasswordMfa => "authtype_passwordmfa",
        });

        match &uat.auth_type {
            AuthType::Anonymous | AuthType::UnixPassword | AuthType::Password => {}
            AuthType::GeneratedPassword | AuthType::Webauthn | AuthType::PasswordMfa => {
                entry.insert_claim("authlevel_strong")
            }
        };

        match &uat.auth_type {
            AuthType::Anonymous => {}
            AuthType::UnixPassword
            | AuthType::Password
            | AuthType::GeneratedPassword
            | AuthType::Webauthn => entry.insert_claim("authclass_single"),
            AuthType::PasswordMfa => entry.insert_claim("authclass_mfa"),
        };
        */

        trace!(claims = ?entry.get_ava_set("claim"), "Applied claims");

        let limits = Limits::from_uat(uat);
        Ok(Identity {
            origin: IdentType::User(IdentUser { entry }),
            limits,
        })
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerAuthTransaction<'a> {
    type QsTransactionType = QueryServerReadTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType {
        &self.qs_read
    }

    fn get_uat_bundy_txn(&self) -> &HS512 {
        &*self.uat_bundy_hmac
    }
}

impl<'a> IdmServerAuthTransaction<'a> {
    #[cfg(test)]
    pub fn is_sessionid_present(&self, sessionid: &Uuid) -> bool {
        let session_read = self.sessions.read();
        session_read.contains_key(sessionid)
    }

    pub async fn expire_auth_sessions(&mut self, ct: Duration) {
        // ct is current time - sub the timeout. and then split.
        let expire = ct - Duration::from_secs(AUTH_SESSION_TIMEOUT);
        let split_at = uuid_from_duration(expire, self.sid);
        // Removes older sessions in place.
        let _session_ticket = self.session_ticket.acquire().await;
        let mut session_write = self.sessions.write();
        session_write.split_off_lt(&split_at);
        // expired will now be dropped, and can't be used by future sessions.
        session_write.commit();
    }

    // ! TRACING INTEGRATED
    pub async fn auth(
        &mut self,
        ae: &AuthEvent,
        ct: Duration,
    ) -> Result<AuthResult, OperationError> {
        trace!(?ae, "Recieved");
        // Match on the auth event, to see what we need to do.

        match &ae.step {
            AuthEventStep::Init(init) => {
                // lperf_segment!("idm::server::auth<Init>", || {
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
                let euuid = self.qs_read.name_to_uuid(init.name.as_str())?; // I CAN'T TRACE WHERE AUDITSCOPE GOES :(((

                // Get the first / single entry we expect here ....
                let entry = self.qs_read.internal_search_uuid(&euuid)?;

                security_info!(
                    ?entry,
                    uuid = %euuid,
                    "Initiating Authentication Session",
                );

                // Now, convert the Entry to an account - this gives us some stronger
                // typing and functionality so we can assess what auth types can
                // continue, and helps to keep non-needed entry specific data
                // out of the session tree.
                let account = Account::try_from_entry_ro(entry.as_ref(), &mut self.qs_read)?;

                // Check the credential that the auth_session will attempt to
                // use.
                let is_valid = {
                    let cred_uuid = account.primary_cred_uuid();
                    // Acquire the softlock map
                    let _softlock_ticket = self.softlock_ticket.acquire().await;
                    let mut softlock_write = self.softlocks.write();
                    // Does it exist?
                    let r = softlock_write
                        .get_mut(&cred_uuid)
                        .map(|slock| {
                            // Apply the current time.
                            slock.apply_time_step(ct);
                            // Now check the results
                            slock.is_valid()
                        })
                        .unwrap_or(true);
                    softlock_write.commit();
                    r
                };

                let (auth_session, state) = if is_valid {
                    AuthSession::new(account, self.webauthn, ct)
                } else {
                    // it's softlocked, don't even bother.
                    security_info!("Account is softlocked.");
                    (
                        None,
                        AuthState::Denied("Account is temporarily locked".to_string()),
                    )
                };

                match auth_session {
                    Some(auth_session) => {
                        // Now acquire the session tree for writing.
                        let _session_ticket = self.session_ticket.acquire().await;
                        let mut session_write = self.sessions.write();
                        spanned!("idm::server::auth<Init> -> sessions", {
                            if session_write.contains_key(&sessionid) {
                                Err(OperationError::InvalidSessionState)
                            } else {
                                session_write.insert(sessionid, auth_session);
                                // Debugging: ensure we really inserted ...
                                debug_assert!(session_write.get(&sessionid).is_some());
                                Ok(())
                            }
                        })?;
                        session_write.commit();
                    }
                    None => {
                        security_info!("Authentication Session Unable to begin");
                    }
                };

                // TODO: Change this william!
                // For now ...
                let delay = None;

                // If we have a session of the same id, return an error (despite how
                // unlikely this is ...

                Ok(AuthResult {
                    sessionid,
                    state,
                    delay,
                })
            } // AuthEventStep::Init
            AuthEventStep::Begin(mech) => {
                // lperf_segment!("idm::server::auth<Begin>", || {
                let _session_ticket = self.session_ticket.acquire().await;
                let _softlock_ticket = self.softlock_ticket.acquire().await;

                let mut session_write = self.sessions.write();
                // Do we have a session?
                let auth_session = session_write
                    // Why is the session missing?
                    .get_mut(&mech.sessionid)
                    .ok_or_else(|| {
                        admin_error!("Invalid Session State (no present session uuid)");
                        OperationError::InvalidSessionState
                    })?;

                // From the auth_session, determine if the current account
                // credential that we are using has become softlocked or not.
                let mut softlock_write = self.softlocks.write();

                let cred_uuid = auth_session.get_account().primary_cred_uuid();

                let is_valid = softlock_write
                    .get_mut(&cred_uuid)
                    .map(|slock| {
                        // Apply the current time.
                        slock.apply_time_step(ct);
                        // Now check the results
                        slock.is_valid()
                    })
                    .unwrap_or(true);

                let r = if is_valid {
                    // Indicate to the session which auth mech we now want to proceed with.
                    auth_session.start_session(&mech.mech)
                } else {
                    // Fail the session
                    auth_session.end_session("Account is temporarily locked")
                }
                .map(|aus| {
                    let delay = None;
                    AuthResult {
                        sessionid: mech.sessionid,
                        state: aus,
                        delay,
                    }
                });
                softlock_write.commit();
                session_write.commit();
                r
            } // End AuthEventStep::Mech
            AuthEventStep::Cred(creds) => {
                // lperf_segment!("idm::server::auth<Creds>", || {
                let _session_ticket = self.session_ticket.acquire().await;
                let _softlock_ticket = self.softlock_ticket.acquire().await;

                let mut session_write = self.sessions.write();
                // Do we have a session?
                let auth_session = session_write
                    // Why is the session missing?
                    .get_mut(&creds.sessionid)
                    .ok_or_else(|| {
                        admin_error!("Invalid Session State (no present session uuid)");
                        OperationError::InvalidSessionState
                    })?;

                // From the auth_session, determine if the current account
                // credential that we are using has become softlocked or not.
                let mut softlock_write = self.softlocks.write();

                let cred_uuid = auth_session.get_account().primary_cred_uuid();

                let is_valid = softlock_write
                    .get_mut(&cred_uuid)
                    .map(|slock| {
                        // Apply the current time.
                        slock.apply_time_step(ct);
                        // Now check the results
                        slock.is_valid()
                    })
                    .unwrap_or(true);

                let r = if is_valid {
                    // Process the credentials here as required.
                    // Basically throw them at the auth_session and see what
                    // falls out.
                    let pw_badlist_cache = Some(&(*self.pw_badlist_cache));
                    auth_session
                        .validate_creds(
                            &creds.cred,
                            &ct,
                            &self.async_tx,
                            self.webauthn,
                            pw_badlist_cache,
                            &*self.uat_bundy_hmac,
                        )
                        .map(|aus| {
                            // Inspect the result:
                            // if it was a failure, we need to inc the softlock.
                            if let AuthState::Denied(_) = &aus {
                                if let Some(slock) = softlock_write.get_mut(&cred_uuid) {
                                    // Update it.
                                    slock.record_failure(ct);
                                } else {
                                    // Create if not exist, and the cred type supports softlocking.
                                    if let Some(policy) =
                                        auth_session.get_account().primary_cred_softlock_policy()
                                    {
                                        let mut slock = CredSoftLock::new(policy);
                                        slock.record_failure(ct);
                                        softlock_write.insert(cred_uuid, slock);
                                    }
                                }
                            };
                            aus
                        })
                } else {
                    // Fail the session
                    auth_session.end_session("Account is temporarily locked")
                }
                .map(|aus| {
                    // TODO: Change this william!
                    // For now ...
                    let delay = None;
                    AuthResult {
                        // Is this right?
                        sessionid: creds.sessionid,
                        state: aus,
                        delay,
                    }
                });
                softlock_write.commit();
                session_write.commit();
                r
            } // End AuthEventStep::Cred
        }
    }

    // ! TRACING INTEGRATED
    pub async fn auth_unix(
        &mut self,
        uae: &UnixUserAuthEvent,
        ct: Duration,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        // Get the entry/target we are working on.
        let account = self
            .qs_read
            .internal_search_uuid(&uae.target)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to start auth unix -> {:?}", e);
                e
            })?;

        if !account.is_within_valid_time(ct) {
            security_info!("Account is not within valid time period");
            return Ok(None);
        }

        let _softlock_ticket = self.softlock_ticket.acquire().await;
        let mut softlock_write = self.softlocks.write();

        let cred_uuid = account.unix_cred_uuid();
        let is_valid = if let Some(cu) = cred_uuid.as_ref() {
            // Advanced and then check the softlock.
            softlock_write
                .get_mut(cu)
                .map(|slock| {
                    // Apply the current time.
                    slock.apply_time_step(ct);
                    // Now check the results
                    slock.is_valid()
                })
                // No sl, it's valid.
                .unwrap_or(true)
        } else {
            // No cred id? It'll fail in verify ...
            true
        };

        // Validate the unix_pw - this checks the account/cred lock states.
        let res = if is_valid {
            // Account is unlocked, can proceed.
            account
                .verify_unix_credential(uae.cleartext.as_str(), &self.async_tx, ct)
                .map(|res| {
                    if res.is_none() {
                        if let Some(cu) = cred_uuid.as_ref() {
                            // Update the cred failure.
                            if let Some(slock) = softlock_write.get_mut(cu) {
                                // Update it.
                                slock.record_failure(ct);
                            } else if let Some(policy) = account.unix_cred_softlock_policy() {
                                let mut slock = CredSoftLock::new(policy);
                                slock.record_failure(ct);
                                softlock_write.insert(*cu, slock);
                            };
                        }
                    };
                    res
                })
        } else {
            // Account is slocked!
            security_info!("Account is softlocked.");
            Ok(None)
        };

        softlock_write.commit();
        res
    }

    // TODO: tracing
    pub async fn auth_ldap(
        &mut self,
        lae: &LdapAuthEvent,
        ct: Duration,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        let account_entry = self
            .qs_read
            .internal_search_uuid(&lae.target)
            .map_err(|e| {
                admin_error!("Failed to start auth ldap -> {:?}", e);
                e
            })?;

        // if anonymous
        if lae.target == UUID_ANONYMOUS {
            let account = Account::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)?;
            // Check if the anon account has been locked.
            if !account.is_within_valid_time(ct) {
                security_info!("Account is not within valid time period");
                return Ok(None);
            }

            let tracing_id = tracing_tree::operation_id().unwrap_or_else(|| {
                admin_warn!("Recoverable - Invalid Tracing Operation ID State");
                Uuid::new_v4()
            });

            // Account must be anon, so we can gen the uat.
            Ok(Some(LdapBoundToken {
                uuid: UUID_ANONYMOUS,
                effective_uat: account
                    .to_userauthtoken(tracing_id, ct, AuthType::Anonymous)
                    .ok_or(OperationError::InvalidState)
                    .map_err(|e| {
                        admin_error!("Unable to generate effective_uat -> {:?}", e);
                        e
                    })?,
                spn: account.spn,
            }))
        } else {
            let account =
                UnixUserAccount::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)?;

            if !account.is_within_valid_time(ct) {
                security_info!("Account is not within valid time period");
                return Ok(None);
            }

            let _softlock_ticket = self.softlock_ticket.acquire().await;
            let mut softlock_write = self.softlocks.write();

            let cred_uuid = account.unix_cred_uuid();
            let is_valid = if let Some(cu) = cred_uuid.as_ref() {
                // Advanced and then check the softlock.
                softlock_write
                    .get_mut(cu)
                    .map(|slock| {
                        // Apply the current time.
                        slock.apply_time_step(ct);
                        // Now check the results
                        slock.is_valid()
                    })
                    // No sl, it's valid.
                    .unwrap_or(true)
            } else {
                // No cred id? It'll fail in verify ...
                true
            };

            let res = if is_valid {
                if account
                    .verify_unix_credential(lae.cleartext.as_str(), &self.async_tx, ct)?
                    .is_some()
                {
                    // Get the anon uat
                    let anon_entry =
                        self.qs_read
                            .internal_search_uuid(&UUID_ANONYMOUS)
                            .map_err(|e| {
                                admin_error!(
                                    "Failed to find effective uat for auth ldap -> {:?}",
                                    e
                                );
                                e
                            })?;
                    let anon_account =
                        Account::try_from_entry_ro(anon_entry.as_ref(), &mut self.qs_read)?;

                    let tracing_id = tracing_tree::operation_id().unwrap_or_else(|| {
                        admin_warn!("Recoverable - Invalid Tracing Operation ID State");
                        Uuid::new_v4()
                    });

                    Ok(Some(LdapBoundToken {
                        spn: account.spn,
                        uuid: account.uuid,
                        effective_uat: anon_account
                            .to_userauthtoken(tracing_id, ct, AuthType::UnixPassword)
                            .ok_or(OperationError::InvalidState)
                            .map_err(|e| {
                                admin_error!("Unable to generate effective_uat -> {:?}", e);
                                e
                            })?,
                    }))
                } else {
                    // PW failure, update softlock.
                    if let Some(cu) = cred_uuid.as_ref() {
                        // Update the cred failure.
                        if let Some(slock) = softlock_write.get_mut(cu) {
                            // Update it.
                            slock.record_failure(ct);
                        } else if let Some(policy) = account.unix_cred_softlock_policy() {
                            let mut slock = CredSoftLock::new(policy);
                            slock.record_failure(ct);
                            softlock_write.insert(*cu, slock);
                        };
                    };
                    Ok(None)
                }
            } else {
                // Account is slocked!
                security_info!("Account is softlocked.");
                Ok(None)
            };

            softlock_write.commit();
            res
        }
    }

    pub fn commit(self) -> Result<(), OperationError> {
        /*
        lperf_trace_segment!("idm::server::IdmServerAuthTransaction::commit", || {
            self.sessions.commit();
            Ok(())
        })*/
        Ok(())
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerProxyReadTransaction<'a> {
    type QsTransactionType = QueryServerReadTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType {
        &self.qs_read
    }

    fn get_uat_bundy_txn(&self) -> &HS512 {
        &*self.uat_bundy_hmac
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    // TODO: tracing
    pub fn get_radiusauthtoken(
        &mut self,
        rate: &RadiusAuthTokenEvent,
        ct: Duration,
    ) -> Result<RadiusAuthToken, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(&rate.target, &rate.ident)
            .and_then(|account_entry| {
                RadiusAccount::try_from_entry_reduced(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to start radius auth token {:?}", e);
                e
            })?;

        account.to_radiusauthtoken(ct)
    }

    // TODO: tracing
    pub fn get_unixusertoken(
        &mut self,
        uute: &UnixUserTokenEvent,
        ct: Duration,
    ) -> Result<UnixUserToken, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_uuid(&uute.target, &uute.ident)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_ro(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to start unix user token -> {:?}", e);
                e
            })?;

        account.to_unixusertoken(ct)
    }

    // TODO: tracing
    pub fn get_unixgrouptoken(
        &mut self,
        uute: &UnixGroupTokenEvent,
    ) -> Result<UnixGroupToken, OperationError> {
        let group = self
            .qs_read
            .impersonate_search_ext_uuid(&uute.target, &uute.ident)
            .and_then(|e| UnixGroup::try_from_entry_reduced(&e))
            .map_err(|e| {
                admin_error!("Failed to start unix group token {:?}", e);
                e
            })?;
        group.to_unixgrouptoken()
    }

    // TODO: tracing
    pub fn get_credentialstatus(
        &mut self,
        cse: &CredentialStatusEvent,
    ) -> Result<CredentialStatus, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(&cse.target, &cse.ident)
            .and_then(|account_entry| {
                Account::try_from_entry_reduced(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;

        account.to_credentialstatus()
    }

    // TODO: tracing
    pub fn get_backup_codes(
        &mut self,
        rbce: &ReadBackupCodeEvent,
    ) -> Result<BackupCodesView, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(&rbce.target, &rbce.ident)
            .and_then(|account_entry| {
                Account::try_from_entry_reduced(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;

        account.to_backupcodesview()
    }

    pub fn check_oauth2_authorisation(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        auth_req: &AuthorisationRequest,
        ct: Duration,
    ) -> Result<ConsentRequest, Oauth2Error> {
        self.oauth2rs
            .check_oauth2_authorisation(ident, uat, auth_req, ct)
    }

    pub fn check_oauth2_authorise_permit(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        consent_req: &str,
        ct: Duration,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        self.oauth2rs
            .check_oauth2_authorise_permit(ident, uat, consent_req, ct)
    }

    pub fn check_oauth2_token_exchange(
        &self,
        client_authz: &str,
        token_req: &AccessTokenRequest,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        self.oauth2rs
            .check_oauth2_token_exchange(client_authz, token_req, ct)
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerProxyWriteTransaction<'a> {
    type QsTransactionType = QueryServerWriteTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType {
        &self.qs_write
    }

    fn get_uat_bundy_txn(&self) -> &HS512 {
        &*self.uat_bundy_hmac
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

    // TODO: tracing
    fn check_password_quality(
        &mut self,
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
            admin_error!("zxcvbn check failure (password empty?) {:?}", e);
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
                    security_info!("zxcvbn returned no feedback when score < 3");
                    e
                })?;

            security_info!(?feedback, "pw quality feedback");

            // return Err(OperationError::PasswordTooWeak(feedback))
            return Err(OperationError::PasswordTooWeak);
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        // also, when pw_badlist_cache is read from DB, it is read as Value (iutf8 lowercase)
        if (&*self.pw_badlist_cache).contains(&cleartext.to_lowercase()) {
            security_info!("Password found in badlist, rejecting");
            Err(OperationError::PasswordBadListed)
        } else {
            Ok(())
        }
    }

    pub(crate) fn target_to_account(&mut self, target: &Uuid) -> Result<Account, OperationError> {
        // Get the account
        let account = self
            .qs_write
            .internal_search_uuid(target)
            .and_then(|account_entry| {
                Account::try_from_entry_rw(&account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            admin_warn!("Unable to convert anonymous to account during write txn");
            Err(OperationError::SystemProtectedObject)
        } else {
            Ok(account)
        }
    }

    pub fn set_account_password(
        &mut self,
        pce: &PasswordChangeEvent,
    ) -> Result<(), OperationError> {
        let account = self.target_to_account(&pce.target)?;

        // Get the modifications we *want* to perform.
        let modlist = account
            .gen_password_mod(pce.cleartext.as_str(), self.crypto_policy)
            .map_err(|e| {
                admin_error!("Failed to generate password mod {:?}", e);
                e
            })?;
        trace!(?modlist, "processing change");

        // Check with the QS if we would be ALLOWED to do this change.

        let me = self
            .qs_write
            .impersonate_modify_gen_event(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                &modlist,
                &pce.ident,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        let mp = unsafe {
            self.qs_write
                .modify_pre_apply(&me)
                .and_then(|opt_mp| opt_mp.ok_or(OperationError::NoMatchingEntries))
                .map_err(|e| {
                    request_error!(error = ?e);
                    e
                })?
        };

        // If we got here, then pre-apply succedded, and that means access control
        // passed. Now we can do the extra checks.

        // Check the password quality.
        // Ask if tis all good - this step checks pwpolicy and such
        // Get related inputs, such as account name, email, etc.
        let mut related_inputs: Vec<&str> = vec![
            account.name.as_str(),
            account.displayname.as_str(),
            account.spn.as_str(),
        ];

        if let Some(s) = account.radius_secret.as_ref() {
            related_inputs.push(s.as_str())
        };

        self.check_password_quality(pce.cleartext.as_str(), related_inputs.as_slice())
            .map_err(|e| {
                request_error!(err = ?e, "check_password_quality");
                e
            })?;

        // And actually really apply it now.
        self.qs_write.modify_apply(mp).map_err(|e| {
            request_error!(error = ?e);
            e
        })?;

        Ok(())
    }

    pub fn set_unix_account_password(
        &mut self,
        pce: &UnixPasswordChangeEvent,
    ) -> Result<(), OperationError> {
        // Get the account
        let account = self
            .qs_write
            .internal_search_uuid(&pce.target)
            .and_then(|account_entry| {
                // Assert the account is unix and valid.
                UnixUserAccount::try_from_entry_rw(&account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                admin_error!("Failed to start set unix account password {:?}", e);
                e
            })?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            return Err(OperationError::SystemProtectedObject);
        }

        let modlist = account
            .gen_password_mod(pce.cleartext.as_str(), self.crypto_policy)
            .map_err(|e| {
                admin_error!(?e, "Unable to generate password change modlist");
                e
            })?;
        trace!(?modlist, "processing change");

        // Check with the QS if we would be ALLOWED to do this change.

        let me = self
            .qs_write
            .impersonate_modify_gen_event(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pce.target))),
                &modlist,
                &pce.ident,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        let mp = unsafe {
            self.qs_write
                .modify_pre_apply(&me)
                .and_then(|opt_mp| opt_mp.ok_or(OperationError::NoMatchingEntries))
                .map_err(|e| {
                    request_error!(error = ?e);
                    e
                })?
        };

        // If we got here, then pre-apply succedded, and that means access control
        // passed. Now we can do the extra checks.

        // Get related inputs, such as account name, email, etc.
        let mut related_inputs: Vec<&str> = vec![
            account.name.as_str(),
            account.displayname.as_str(),
            account.spn.as_str(),
        ];

        if let Some(s) = account.radius_secret.as_ref() {
            related_inputs.push(s.as_str())
        };

        self.check_password_quality(pce.cleartext.as_str(), related_inputs.as_slice())
            .map_err(|e| {
                admin_error!(?e, "Failed to checked password quality");
                e
            })?;

        // And actually really apply it now.
        self.qs_write.modify_apply(mp).map_err(|e| {
            request_error!(error = ?e);
            e
        })?;

        Ok(())
    }

    // TODO: tracing
    pub fn recover_account(
        &mut self,
        name: &str,
        cleartext: Option<&str>,
    ) -> Result<String, OperationError> {
        // name to uuid
        let target = self.qs_write.name_to_uuid(name).map_err(|e| {
            admin_error!(?e, "name to uuid failed");
            e
        })?;

        let account = self.target_to_account(&target)?;

        let cleartext = cleartext
            .map(|s| s.to_string())
            .unwrap_or_else(password_from_random);

        let modlist = account
            .gen_generatedpassword_recover_mod(&cleartext, self.crypto_policy)
            .map_err(|e| {
                admin_error!("Failed to generate password mod {:?}", e);
                e
            })?;
        trace!(?modlist, "processing change");

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&target))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        Ok(cleartext)
    }

    // TODO: tracing
    pub fn generate_account_password(
        &mut self,
        gpe: &GeneratePasswordEvent,
    ) -> Result<String, OperationError> {
        let account = self.target_to_account(&gpe.target)?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Generate a new random, long pw.
        // Because this is generated, we can bypass policy checks!
        let cleartext = password_from_random();

        // check a password badlist - even if generated, we still don't want to
        // reuse something that has been disclosed.

        // it returns a modify
        let modlist = account
            .gen_generatedpassword_recover_mod(cleartext.as_str(), self.crypto_policy)
            .map_err(|e| {
                admin_error!("Unable to generate password mod {:?}", e);
                e
            })?;

        trace!(?modlist, "processing change");
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&gpe.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&gpe.target))),
                &modlist,
                // Provide the event to impersonate
                &gpe.ident,
            )
            .map(|_| cleartext)
            .map_err(|e| {
                admin_error!("Failed to generate account password {:?}", e);
                e
            })
    }

    // TODO: tracing
    /// Generate a new set of backup code and remove the old ones.
    pub fn generate_backup_code(
        &mut self,
        gbe: &GenerateBackupCodeEvent,
    ) -> Result<Vec<String>, OperationError> {
        let account = self.target_to_account(&gbe.target)?;

        // Generate a new set of backup code.
        let s = backup_code_from_random();

        // it returns a modify
        let modlist = account
            .gen_backup_code_mod(BackupCodes::new(s.clone()))
            .map_err(|e| {
                admin_error!("Unable to generate backup code mod {:?}", e);
                e
            })?;

        trace!(?modlist, "processing change");
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&gbe.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&gbe.target))),
                &modlist,
                // Provide the event to impersonate
                &gbe.ident,
            )
            .map(|_| s.into_iter().collect())
            .map_err(|e| {
                admin_error!("Failed to generate backup code {:?}", e);
                e
            })
    }

    // TODO: tracing
    pub fn remove_backup_code(
        &mut self,
        rte: &RemoveBackupCodeEvent,
    ) -> Result<SetCredentialResponse, OperationError> {
        trace!(target = ?rte.target, "Attempting to remove backup code");

        let account = self.target_to_account(&rte.target)?;
        let modlist = account.gen_backup_code_remove_mod().map_err(|e| {
            admin_error!("Failed to gen backup code remove mod {:?}", e);
            e
        })?;
        // Perform the mod
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&account.uuid))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&account.uuid))),
                &modlist,
                &rte.ident,
            )
            .map_err(|e| {
                admin_error!("remove_backup_code {:?}", e);
                e
            })
            .map(|_| SetCredentialResponse::Success)
    }

    // TODO: tracing
    pub fn regenerate_radius_secret(
        &mut self,
        rrse: &RegenerateRadiusSecretEvent,
    ) -> Result<String, OperationError> {
        let account = self.target_to_account(&rrse.target)?;

        // Difference to the password above, this is intended to be read/copied
        // by a human wiath a keyboard in some cases.
        let cleartext = readable_password_from_random();

        // Create a modlist from the change.
        let modlist = account
            .regenerate_radius_secret_mod(cleartext.as_str())
            .map_err(|e| {
                admin_error!("Unable to generate radius secret mod {:?}", e);
                e
            })?;
        trace!(?modlist, "processing change");

        // Apply it.
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&rrse.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&rrse.target))),
                &modlist,
                // Provide the event to impersonate
                &rrse.ident,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })
            .map(|_| cleartext)
    }

    // TODO: tracing
    pub fn reg_account_webauthn_init(
        &mut self,
        wre: &WebauthnInitRegisterEvent,
        ct: Duration,
    ) -> Result<SetCredentialResponse, OperationError> {
        let account = self.target_to_account(&wre.target)?;
        let sessionid = uuid_from_duration(ct, self.sid);

        let origin = (&wre.ident.origin).into();
        let label = wre.label.clone();

        let (session, next) = MfaRegSession::webauthn_new(origin, account, label, self.webauthn)?;

        let next = next.to_proto(sessionid);

        // Add session to tree
        self.mfareg_sessions.insert(sessionid, session);
        trace!(?sessionid, "Start mfa reg session");
        Ok(next)
    }

    // TODO: tracing
    pub fn reg_account_webauthn_complete(
        &mut self,
        wre: &WebauthnDoRegisterEvent,
    ) -> Result<SetCredentialResponse, OperationError> {
        let sessionid = wre.session;
        let origin = (&wre.ident.origin).into();
        let webauthn = self.webauthn;

        // Regardless of the outcome, we purge this session, so we get it
        // from the tree instead of a mut pointer.
        let mut session = self
            .mfareg_sessions
            .remove(&sessionid)
            .ok_or(OperationError::InvalidState)
            .map_err(|e| {
                admin_error!("Failed to register webauthn -> {:?}", e);
                e
            })?;

        let (next, wan_cred) = session
            .webauthn_step(&origin, &wre.target, &wre.chal, webauthn)
            .map_err(|e| {
                admin_error!("Failed to register webauthn -> {:?}", e);
                OperationError::Webauthn
            })?;

        if let (MfaRegNext::Success, Some(MfaRegCred::Webauthn(label, cred))) = (&next, wan_cred) {
            // Persist the credential
            let modlist = session.account.gen_webauthn_mod(label, cred).map_err(|e| {
                admin_error!("Failed to gen webauthn mod {:?}", e);
                e
            })?;
            // Perform the mod
            self.qs_write
                .impersonate_modify(
                    // Filter as executed
                    &filter!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    // Filter as intended (acp)
                    &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    &modlist,
                    &wre.ident,
                )
                .map_err(|e| {
                    admin_error!("reg_account_webauthn_complete {:?}", e);
                    e
                })?;
        }

        let next = next.to_proto(sessionid);
        Ok(next)
    }

    // TODO: tracing
    pub fn remove_account_webauthn(
        &mut self,
        rwe: &RemoveWebauthnEvent,
    ) -> Result<SetCredentialResponse, OperationError> {
        trace!(
            "Attempting to remove webauthn {:?} -> {:?}",
            rwe.label,
            rwe.target
        );

        let account = self.target_to_account(&rwe.target)?;
        let modlist = account
            .gen_webauthn_remove_mod(rwe.label.as_str())
            .map_err(|e| {
                admin_error!("Failed to gen webauthn remove mod {:?}", e);
                e
            })?;
        // Perform the mod
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&account.uuid))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&account.uuid))),
                &modlist,
                &rwe.ident,
            )
            .map_err(|e| {
                admin_error!("remove_account_webauthn {:?}", e);
                e
            })
            .map(|_| SetCredentialResponse::Success)
    }

    // TODO: tracing
    pub fn generate_account_totp(
        &mut self,
        gte: &GenerateTotpEvent,
        ct: Duration,
    ) -> Result<SetCredentialResponse, OperationError> {
        let account = self.target_to_account(&gte.target)?;
        let sessionid = uuid_from_duration(ct, self.sid);

        let origin = (&gte.ident.origin).into();
        let (session, next) = MfaRegSession::totp_new(origin, account).map_err(|e| {
            admin_error!("Unable to start totp MfaRegSession {:?}", e);
            e
        })?;

        let next = next.to_proto(sessionid);

        // Add session to tree
        self.mfareg_sessions.insert(sessionid, session);
        trace!(?sessionid, "Start mfa reg session");
        Ok(next)
    }

    // TODO: tracing
    pub fn verify_account_totp(
        &mut self,
        vte: &VerifyTotpEvent,
        ct: Duration,
    ) -> Result<SetCredentialResponse, OperationError> {
        let sessionid = vte.session;
        let origin = (&vte.ident.origin).into();
        let chal = vte.chal;

        trace!(?sessionid, "Attempting to find mfareg_session");

        let (next, opt_cred) = self
            .mfareg_sessions
            .get_mut(&sessionid)
            .ok_or(OperationError::InvalidRequestState)
            .and_then(|session| session.totp_step(&origin, &vte.target, chal, &ct))
            .map_err(|e| {
                admin_error!("Failed to verify totp {:?}", e);
                e
            })?;

        if let (MfaRegNext::Success, Some(MfaRegCred::Totp(token))) = (&next, opt_cred) {
            // Purge the session.
            let session = self
                .mfareg_sessions
                .remove(&sessionid)
                .ok_or(OperationError::InvalidState)
                .map_err(|e| {
                    admin_error!("Session within transaction vanished!");
                    e
                })?;
            // reg the token
            let modlist = session.account.gen_totp_mod(token).map_err(|e| {
                admin_error!("Failed to gen totp mod {:?}", e);
                e
            })?;
            // Perform the mod
            self.qs_write
                .impersonate_modify(
                    // Filter as executed
                    &filter!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    // Filter as intended (acp)
                    &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    &modlist,
                    &vte.ident,
                )
                .map_err(|e| {
                    admin_error!("verify_account_totp {:?}", e);
                    e
                })?;
        };

        let next = next.to_proto(sessionid);
        Ok(next)
    }

    // TODO: tracing
    pub fn accept_account_sha1_totp(
        &mut self,
        aste: &AcceptSha1TotpEvent,
    ) -> Result<SetCredentialResponse, OperationError> {
        let sessionid = aste.session;
        let origin = (&aste.ident.origin).into();

        trace!(?sessionid, "Attempting to find mfareg_session");

        let (next, opt_cred) = self
            .mfareg_sessions
            .get_mut(&sessionid)
            .ok_or(OperationError::InvalidRequestState)
            .and_then(|session| session.totp_accept_sha1(&origin, &aste.target))
            .map_err(|e| {
                admin_error!("Failed to accept sha1 totp {:?}", e);
                e
            })?;

        if let (MfaRegNext::Success, Some(MfaRegCred::Totp(token))) = (&next, opt_cred) {
            // Purge the session.
            let session = self
                .mfareg_sessions
                .remove(&sessionid)
                .ok_or(OperationError::InvalidState)
                .map_err(|e| {
                    admin_error!("Session within transaction vanished!");
                    e
                })?;
            // reg the token
            let modlist = session.account.gen_totp_mod(token).map_err(|e| {
                admin_error!("Failed to gen totp mod {:?}", e);
                e
            })?;
            // Perform the mod
            self.qs_write
                .impersonate_modify(
                    // Filter as executed
                    &filter!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    // Filter as intended (acp)
                    &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
                    &modlist,
                    &aste.ident,
                )
                .map_err(|e| {
                    admin_error!("accept_account_sha1_totp {:?}", e);
                    e
                })?;
        };

        let next = next.to_proto(sessionid);
        Ok(next)
    }

    // TODO: tracing
    pub fn remove_account_totp(
        &mut self,
        rte: &RemoveTotpEvent,
    ) -> Result<SetCredentialResponse, OperationError> {
        trace!(target = ?rte.target, "Attempting to remove totp");

        let account = self.target_to_account(&rte.target)?;
        let modlist = account.gen_totp_remove_mod().map_err(|e| {
            admin_error!("Failed to gen totp remove mod {:?}", e);
            e
        })?;
        // Perform the mod
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&account.uuid))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&account.uuid))),
                &modlist,
                &rte.ident,
            )
            .map_err(|e| {
                admin_error!("remove_account_totp {:?}", e);
                e
            })
            .map(|_| SetCredentialResponse::Success)
    }

    // TODO: tracing
    // -- delayed action processing --
    fn process_pwupgrade(&mut self, pwu: &PasswordUpgrade) -> Result<(), OperationError> {
        // get the account
        let account = self.target_to_account(&pwu.target_uuid)?;

        // check, does the pw still match?
        let same = account.check_credential_pw(pwu.existing_password.as_str())?;

        // if yes, gen the pw mod and apply.
        if same {
            let modlist = account
                .gen_password_mod(pwu.existing_password.as_str(), self.crypto_policy)
                .map_err(|e| {
                    admin_error!("Unable to generate password mod {:?}", e);
                    e
                })?;

            self.qs_write.internal_modify(
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pwu.target_uuid))),
                &modlist,
            )
        } else {
            // No action needed, it's probably been changed/updated already.
            Ok(())
        }
    }

    // TODO: tracing
    fn process_unixpwupgrade(&mut self, pwu: &UnixPasswordUpgrade) -> Result<(), OperationError> {
        let account = self
            .qs_write
            .internal_search_uuid(&pwu.target_uuid)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_rw(&account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                admin_error!("Failed to start unix pw upgrade -> {:?}", e);
                e
            })?;

        let same = account.check_existing_pw(pwu.existing_password.as_str())?;

        if same {
            let modlist = account
                .gen_password_mod(pwu.existing_password.as_str(), self.crypto_policy)
                .map_err(|e| {
                    admin_error!("Unable to generate password mod {:?}", e);
                    e
                })?;

            self.qs_write.internal_modify(
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&pwu.target_uuid))),
                &modlist,
            )
        } else {
            Ok(())
        }
    }

    // TODO: tracing
    pub(crate) fn process_webauthncounterinc(
        &mut self,
        wci: &WebauthnCounterIncrement,
    ) -> Result<(), OperationError> {
        let account = self.target_to_account(&wci.target_uuid)?;

        // Generate an optional mod and then attempt to apply it.
        let opt_modlist = account
            .gen_webauthn_counter_mod(&wci.cid, wci.counter)
            .map_err(|e| {
                admin_error!("Unable to generate webauthn counter mod {:?}", e);
                e
            })?;

        if let Some(modlist) = opt_modlist {
            self.qs_write.internal_modify(
                &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&wci.target_uuid))),
                &modlist,
            )
        } else {
            // No mod needed.
            trace!("No modification required");
            Ok(())
        }
    }

    // TODO: tracing
    pub(crate) fn process_backupcoderemoval(
        &mut self,
        bcr: &BackupCodeRemoval,
    ) -> Result<(), OperationError> {
        let account = self.target_to_account(&bcr.target_uuid)?;
        // Generate an optional mod and then attempt to apply it.
        let modlist = account
            .invalidate_backup_code_mod(&bcr.code_to_remove)
            .map_err(|e| {
                admin_error!("Unable to generate backup code mod {:?}", e);
                e
            })?;

        self.qs_write.internal_modify(
            &filter_all!(f_eq("uuid", PartialValue::new_uuidr(&bcr.target_uuid))),
            &modlist,
        )
    }

    // TODO: tracing
    pub(crate) fn process_delayedaction(
        &mut self,
        da: DelayedAction,
    ) -> Result<(), OperationError> {
        match da {
            DelayedAction::PwUpgrade(pwu) => self.process_pwupgrade(&pwu),
            DelayedAction::UnixPwUpgrade(upwu) => self.process_unixpwupgrade(&upwu),
            DelayedAction::WebauthnCounterIncrement(wci) => self.process_webauthncounterinc(&wci),
            DelayedAction::BackupCodeRemoval(bcr) => self.process_backupcoderemoval(&bcr),
        }
    }

    pub fn commit(mut self) -> Result<(), OperationError> {
        spanned!("idm::server::IdmServerProxyWriteTransaction::commit", {
            if self
                .qs_write
                .get_changed_uuids()
                .contains(&UUID_SYSTEM_CONFIG)
            {
                self.reload_password_badlist()?;
            };
            if self.qs_write.get_changed_ouath2() {
                self.qs_write
                    .get_oauth2rs_set()
                    .and_then(|oauth2rs_set| self.oauth2rs.reload(oauth2rs_set))?;
            }
            if self.qs_write.get_changed_domain() {
                // reload token_key?
                self.qs_write
                    .get_domain_token_key()
                    .and_then(|token_key| {
                        HS512::from_str(&token_key).map_err(|e| {
                            admin_error!("Failed to generate uat_bundy_hmac - {:?}", e);
                            OperationError::InvalidState
                        })
                    })
                    .map(|new_handle| {
                        *self.uat_bundy_hmac = new_handle;
                    })?;
            }
            // Commit everything.
            self.oauth2rs.commit();
            self.uat_bundy_hmac.commit();
            self.pw_badlist_cache.commit();
            self.mfareg_sessions.commit();
            self.qs_write.commit()
        })
    }

    fn reload_password_badlist(&mut self) -> Result<(), OperationError> {
        match self.qs_write.get_password_badlist() {
            Ok(badlist_entry) => {
                *self.pw_badlist_cache = badlist_entry;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

// Need tests of the sessions and the auth ...

#[cfg(test)]
mod tests {
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::Totp;
    use crate::credential::{Credential, Password};
    use crate::event::{AuthEvent, AuthResult, CreateEvent, ModifyEvent};
    use crate::idm::delayed::{BackupCodeRemoval, DelayedAction, WebauthnCounterIncrement};
    use crate::idm::event::{
        AcceptSha1TotpEvent, GenerateBackupCodeEvent, GenerateTotpEvent, PasswordChangeEvent,
        RadiusAuthTokenEvent, RegenerateRadiusSecretEvent, RemoveTotpEvent, RemoveWebauthnEvent,
        UnixGroupTokenEvent, UnixPasswordChangeEvent, UnixUserAuthEvent, UnixUserTokenEvent,
        VerifyTotpEvent, WebauthnDoRegisterEvent, WebauthnInitRegisterEvent,
    };
    use crate::idm::AuthState;
    use crate::modify::{Modify, ModifyList};
    use crate::prelude::*;
    use kanidm_proto::v1::OperationError;
    use kanidm_proto::v1::SetCredentialResponse;
    use kanidm_proto::v1::{AuthAllowed, AuthMech, AuthType};

    use crate::idm::server::{IdmServer, IdmServerTransaction};
    // , IdmServerDelayed;
    use crate::utils::duration_from_epoch_now;
    use async_std::task;
    use smartstring::alias::String as AttrString;
    use std::convert::TryFrom;
    use std::time::Duration;
    use uuid::Uuid;
    use webauthn_authenticator_rs::{softtok::U2FSoft, WebauthnAuthenticator};

    const TEST_PASSWORD: &'static str = "ntaoeuntnaoeuhraohuercahu😍";
    const TEST_PASSWORD_INC: &'static str = "ntaoentu nkrcgaeunhibwmwmqj;k wqjbkx ";
    const TEST_CURRENT_TIME: u64 = 6000;
    const TEST_CURRENT_EXPIRE: u64 = TEST_CURRENT_TIME + AUTH_SESSION_TIMEOUT + 1;

    #[test]
    fn test_idm_anonymous_auth() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let sid = {
                    // Start and test anonymous auth.
                    let mut idms_auth = idms.auth();
                    // Send the initial auth event for initialising the session
                    let anon_init = AuthEvent::anonymous_init();
                    // Expect success
                    let r1 = task::block_on(
                        idms_auth.auth(&anon_init, Duration::from_secs(TEST_CURRENT_TIME)),
                    );
                    /* Some weird lifetime things happen here ... */

                    let sid = match r1 {
                        Ok(ar) => {
                            let AuthResult {
                                sessionid,
                                state,
                                delay,
                            } = ar;
                            debug_assert!(delay.is_none());
                            match state {
                                AuthState::Choose(mut conts) => {
                                    // Should only be one auth mech
                                    assert!(conts.len() == 1);
                                    // And it should be anonymous
                                    let m = conts.pop().expect("Should not fail");
                                    assert!(m == AuthMech::Anonymous);
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

                    idms_auth.commit().expect("Must not fail");

                    sid
                };
                {
                    let mut idms_auth = idms.auth();
                    let anon_begin = AuthEvent::begin_mech(sid, AuthMech::Anonymous);

                    let r2 = task::block_on(
                        idms_auth.auth(&anon_begin, Duration::from_secs(TEST_CURRENT_TIME)),
                    );
                    debug!("r2 ==> {:?}", r2);

                    match r2 {
                        Ok(ar) => {
                            let AuthResult {
                                sessionid: _,
                                state,
                                delay,
                            } = ar;

                            debug_assert!(delay.is_none());
                            match state {
                                AuthState::Continue(allowed) => {
                                    // Check the uat.
                                    assert!(allowed.len() == 1);
                                    assert!(allowed.first() == Some(&AuthAllowed::Anonymous));
                                }
                                _ => {
                                    error!(
                                    "A critical error has occured! We have a non-continue result!"
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

                    idms_auth.commit().expect("Must not fail");
                };
                {
                    let mut idms_auth = idms.auth();
                    // Now send the anonymous request, given the session id.
                    let anon_step = AuthEvent::cred_step_anonymous(sid);

                    // Expect success
                    let r2 = task::block_on(
                        idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                    );
                    debug!("r2 ==> {:?}", r2);

                    match r2 {
                        Ok(ar) => {
                            let AuthResult {
                                sessionid: _,
                                state,
                                delay,
                            } = ar;

                            debug_assert!(delay.is_none());
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

                    idms_auth.commit().expect("Must not fail");
                }
            }
        );
    }

    // Test sending anonymous but with no session init.
    #[test]
    fn test_idm_anonymous_auth_invalid_states() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                {
                    let mut idms_auth = idms.auth();
                    let sid = Uuid::new_v4();
                    let anon_step = AuthEvent::cred_step_anonymous(sid);

                    // Expect failure
                    let r2 = task::block_on(
                        idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                    );
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
            }
        )
    }

    fn init_admin_w_password(qs: &QueryServer, pw: &str) -> Result<(), OperationError> {
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw)?;
        let v_cred = Value::new_credential("primary", cred);
        let qs_write = qs.write(duration_from_epoch_now());

        // now modify and provide a primary credential.
        let me_inv_m = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("admin"))),
                ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("primary_credential"),
                    v_cred,
                )]),
            )
        };
        // go!
        assert!(qs_write.modify(&me_inv_m).is_ok());

        qs_write.commit()
    }

    fn init_admin_authsession_sid(idms: &IdmServer, ct: Duration, name: &str) -> Uuid {
        let mut idms_auth = idms.auth();
        let admin_init = AuthEvent::named_init(name);

        let r1 = task::block_on(idms_auth.auth(&admin_init, ct));
        let ar = r1.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay,
        } = ar;

        debug_assert!(delay.is_none());
        match state {
            AuthState::Choose(_) => {}
            _ => {
                error!("Sessions was not initialised");
                panic!();
            }
        };

        // Now push that we want the Password Mech.
        let admin_begin = AuthEvent::begin_mech(sessionid, AuthMech::Password);

        let r2 = task::block_on(idms_auth.auth(&admin_begin, ct));
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay,
        } = ar;

        debug_assert!(delay.is_none());

        match state {
            AuthState::Continue(_) => {}
            _ => {
                error!("Sessions was not initialised");
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        sessionid
    }

    fn check_admin_password(idms: &IdmServer, pw: &str) -> String {
        let sid = init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME), "admin");

        let mut idms_auth = idms.auth();
        let anon_step = AuthEvent::cred_step_password(sid, pw);

        // Expect success
        let r2 = task::block_on(idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)));
        debug!("r2 ==> {:?}", r2);

        let token = match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                    delay,
                } = ar;

                debug_assert!(delay.is_none());

                match state {
                    AuthState::Success(token) => {
                        // Check the uat.
                        token
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

        idms_auth.commit().expect("Must not fail");
        token
    }

    #[test]
    fn test_idm_simple_password_auth() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                check_admin_password(idms, TEST_PASSWORD);
            }
        )
    }

    #[test]
    fn test_idm_simple_password_spn_auth() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");

                let sid = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    "admin@example.com",
                );

                let mut idms_auth = idms.auth();
                let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD);

                // Expect success
                let r2 = task::block_on(
                    idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                debug!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                            delay,
                        } = ar;
                        debug_assert!(delay.is_none());
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

                idms_auth.commit().expect("Must not fail");
            }
        )
    }

    #[test]
    fn test_idm_simple_password_invalid() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                let sid = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    "admin",
                );
                let mut idms_auth = idms.auth();
                let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD_INC);

                // Expect success
                let r2 = task::block_on(
                    idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                debug!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                            delay,
                        } = ar;
                        debug_assert!(delay.is_none());
                        match state {
                            AuthState::Denied(_reason) => {
                                // Check the uat.
                            }
                            _ => {
                                error!(
                                    "A critical error has occured! We have a non-denied result!"
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

                idms_auth.commit().expect("Must not fail");
            }
        )
    }

    #[test]
    fn test_idm_simple_password_reset() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);

                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                assert!(idms_prox_write.set_account_password(&pce).is_ok());
                assert!(idms_prox_write.set_account_password(&pce).is_ok());
                assert!(idms_prox_write.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_anonymous_set_password_denied() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let pce = PasswordChangeEvent::new_internal(&UUID_ANONYMOUS, TEST_PASSWORD);

                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                assert!(idms_prox_write.set_account_password(&pce).is_err());
                assert!(idms_prox_write.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_session_expire() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                let sid = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    "admin",
                );
                let mut idms_auth = idms.auth();
                assert!(idms_auth.is_sessionid_present(&sid));
                // Expire like we are currently "now". Should not affect our session.
                task::block_on(
                    idms_auth.expire_auth_sessions(Duration::from_secs(TEST_CURRENT_TIME)),
                );
                assert!(idms_auth.is_sessionid_present(&sid));
                // Expire as though we are in the future.
                task::block_on(
                    idms_auth.expire_auth_sessions(Duration::from_secs(TEST_CURRENT_EXPIRE)),
                );
                assert!(!idms_auth.is_sessionid_present(&sid));
                assert!(idms_auth.commit().is_ok());
                let idms_auth = idms.auth();
                assert!(!idms_auth.is_sessionid_present(&sid));
            }
        )
    }

    #[test]
    fn test_idm_regenerate_radius_secret() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());

                // Generates a new credential when none exists
                let r1 = idms_prox_write
                    .regenerate_radius_secret(&rrse)
                    .expect("Failed to reset radius credential 1");
                // Regenerates and overwrites the radius credential
                let r2 = idms_prox_write
                    .regenerate_radius_secret(&rrse)
                    .expect("Failed to reset radius credential 2");
                assert!(r1 != r2);
            }
        )
    }

    #[test]
    fn test_idm_radius_secret_rejected_from_account_credential() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());

                let r1 = idms_prox_write
                    .regenerate_radius_secret(&rrse)
                    .expect("Failed to reset radius credential 1");

                // Try and set that as the main account password, should fail.
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, r1.as_str());
                let e = idms_prox_write.set_account_password(&pce);
                assert!(e.is_err());

                let pce = UnixPasswordChangeEvent::new_internal(&UUID_ADMIN, r1.as_str());
                let e = idms_prox_write.set_unix_account_password(&pce);
                assert!(e.is_err());

                assert!(idms_prox_write.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_radiusauthtoken() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());
                let r1 = idms_prox_write
                    .regenerate_radius_secret(&rrse)
                    .expect("Failed to reset radius credential 1");
                idms_prox_write.commit().expect("failed to commit");

                let mut idms_prox_read = idms.proxy_read();
                let rate = RadiusAuthTokenEvent::new_internal(UUID_ADMIN.clone());
                let tok_r = idms_prox_read
                    .get_radiusauthtoken(&rate, duration_from_epoch_now())
                    .expect("Failed to generate radius auth token");

                // view the token?
                assert!(r1 == tok_r.secret);
            }
        )
    }

    #[test]
    fn test_idm_simple_password_reject_weak() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                // len check
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());

                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "password");
                let e = idms_prox_write.set_account_password(&pce);
                assert!(e.is_err());

                // zxcvbn check
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "password1234");
                let e = idms_prox_write.set_account_password(&pce);
                assert!(e.is_err());

                // Check the "name" checking works too (I think admin may hit a common pw rule first)
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "admin_nta");
                let e = idms_prox_write.set_account_password(&pce);
                assert!(e.is_err());

                // Check that the demo badlist password is rejected.
                let pce = PasswordChangeEvent::new_internal(
                    &UUID_ADMIN,
                    "demo_badlist_shohfie3aeci2oobur0aru9uushah6EiPi2woh4hohngoighaiRuepieN3ongoo1",
                );
                let e = idms_prox_write.set_account_password(&pce);
                assert!(e.is_err());

                assert!(idms_prox_write.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_simple_password_reject_badlist() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());

                // Check that the badlist password inserted is rejected.
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, "bad@no3IBTyqHu$list");
                let e = idms_prox_write.set_account_password(&pce);
                assert!(e.is_err());

                assert!(idms_prox_write.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_unixusertoken() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                // Modify admin to have posixaccount
                let me_posix = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![
                            Modify::Present(
                                AttrString::from("class"),
                                Value::new_class("posixaccount"),
                            ),
                            Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                        ]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());
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

                assert!(idms_prox_write.qs_write.create(&ce).is_ok());

                idms_prox_write.commit().expect("failed to commit");

                let mut idms_prox_read = idms.proxy_read();

                let ugte = UnixGroupTokenEvent::new_internal(
                    Uuid::parse_str("01609135-a1c4-43d5-966b-a28227644445")
                        .expect("failed to parse uuid"),
                );
                let tok_g = idms_prox_read
                    .get_unixgrouptoken(&ugte)
                    .expect("Failed to generate unix group token");

                assert!(tok_g.name == "testgroup");
                assert!(tok_g.spn == "testgroup@example.com");

                let uute = UnixUserTokenEvent::new_internal(UUID_ADMIN.clone());
                let tok_r = idms_prox_read
                    .get_unixusertoken(&uute, duration_from_epoch_now())
                    .expect("Failed to generate unix user token");

                assert!(tok_r.name == "admin");
                assert!(tok_r.spn == "admin@example.com");
                assert!(tok_r.groups.len() == 2);
                assert!(tok_r.groups[0].name == "admin");
                assert!(tok_r.groups[1].name == "testgroup");
                assert!(tok_r.valid == true);

                // Show we can get the admin as a unix group token too
                let ugte = UnixGroupTokenEvent::new_internal(
                    Uuid::parse_str("00000000-0000-0000-0000-000000000000")
                        .expect("failed to parse uuid"),
                );
                let tok_g = idms_prox_read
                    .get_unixgrouptoken(&ugte)
                    .expect("Failed to generate unix group token");

                assert!(tok_g.name == "admin");
                assert!(tok_g.spn == "admin@example.com");
            }
        )
    }

    #[test]
    fn test_idm_simple_unix_password_reset() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                // make the admin a valid posix account
                let me_posix = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![
                            Modify::Present(
                                AttrString::from("class"),
                                Value::new_class("posixaccount"),
                            ),
                            Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                        ]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

                let pce = UnixPasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);

                assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
                assert!(idms_prox_write.commit().is_ok());

                let mut idms_auth = idms.auth();
                // Check auth verification of the password

                let uuae_good = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                let a1 = task::block_on(
                    idms_auth.auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a1 {
                    Ok(Some(_tok)) => {}
                    _ => assert!(false),
                };
                // Check bad password
                let uuae_bad = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD_INC);
                let a2 = task::block_on(
                    idms_auth.auth_unix(&uuae_bad, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a2 {
                    Ok(None) => {}
                    _ => assert!(false),
                };
                assert!(idms_auth.commit().is_ok());

                // Check deleting the password
                let idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let me_purge_up = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![Modify::Purged(AttrString::from(
                            "unix_password",
                        ))]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_purge_up).is_ok());
                assert!(idms_prox_write.commit().is_ok());

                // And auth should now fail due to the lack of PW material (note that
                // softlocking WONT kick in because the cred_uuid is gone!)
                let mut idms_auth = idms.auth();
                let a3 = task::block_on(
                    idms_auth.auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a3 {
                    Ok(None) => {}
                    _ => assert!(false),
                };
                assert!(idms_auth.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_totp_registration() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let ct = duration_from_epoch_now();
                let expire = Duration::from_secs(ct.as_secs() + MFAREG_SESSION_TIMEOUT + 2);
                let mut idms_prox_write = idms.proxy_write(ct.clone());

                // verify with no session (fail)
                let vte1 = VerifyTotpEvent::new_internal(UUID_ADMIN.clone(), Uuid::new_v4(), 0);

                match idms_prox_write.verify_account_totp(&vte1, ct.clone()) {
                    Err(e) => {
                        assert!(e == OperationError::InvalidRequestState);
                    }
                    _ => panic!(),
                };

                // reg, expire session, attempt verify (fail)
                let gte1 = GenerateTotpEvent::new_internal(UUID_ADMIN.clone());

                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let sesid = match res {
                    SetCredentialResponse::TotpCheck(id, _) => id,
                    _ => panic!("invalid state!"),
                };
                idms_prox_write.expire_mfareg_sessions(expire.clone());

                let vte2 = VerifyTotpEvent::new_internal(UUID_ADMIN.clone(), sesid, 0);

                match idms_prox_write.verify_account_totp(&vte1, ct.clone()) {
                    Err(e) => {
                        assert!(e == OperationError::InvalidRequestState);
                    }
                    _ => panic!(),
                };

                // == Test TOTP on account with no password (fail)
                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let (sesid, tok) = match res {
                    SetCredentialResponse::TotpCheck(id, tok) => (id, tok),
                    _ => panic!("invalid state!"),
                };
                // get the correct otp
                let r_tok: Totp = tok.into();
                let chal = r_tok
                    .do_totp_duration_from_epoch(&ct)
                    .expect("Failed to do totp?");
                // attempt the verify
                let vte3 = VerifyTotpEvent::new_internal(UUID_ADMIN.clone(), sesid, chal);

                match idms_prox_write.verify_account_totp(&vte3, ct.clone()) {
                    Err(e) => assert!(e == OperationError::InvalidState),
                    _ => panic!(),
                };

                // Expire the session to allow it to reset.
                idms_prox_write.expire_mfareg_sessions(expire.clone());

                // Set a password.
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                assert!(idms_prox_write.set_account_password(&pce).is_ok());

                // == reg, but change the event source part way in the process (failure)
                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let (sesid, tok) = match res {
                    SetCredentialResponse::TotpCheck(id, tok) => (id, tok),
                    _ => panic!("invalid state!"),
                };
                // get the correct otp
                let r_tok: Totp = tok.into();
                let chal = r_tok
                    .do_totp_duration_from_epoch(&ct)
                    .expect("Failed to do totp?");
                // attempt the verify
                let vte3 = VerifyTotpEvent::new_internal(UUID_ANONYMOUS.clone(), sesid, chal);

                match idms_prox_write.verify_account_totp(&vte3, ct.clone()) {
                    Err(e) => assert!(e == OperationError::InvalidRequestState),
                    _ => panic!(),
                };

                // == reg, verify w_ incorrect totp (fail)
                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let (_sesid, _tok) = match res {
                    SetCredentialResponse::TotpCheck(id, tok) => (id, tok),
                    _ => panic!("invalid state!"),
                };

                // We can reuse the OTP/Vte2 from before, since we want the invalid otp.
                match idms_prox_write.verify_account_totp(&vte2, ct.clone()) {
                    // On failure we get back another attempt to setup the token.
                    Ok(SetCredentialResponse::TotpCheck(_id, _tok)) => {}
                    _ => panic!(),
                };
                idms_prox_write.expire_mfareg_sessions(expire.clone());

                // Turn the pts into an otp
                // == reg, verify w_ correct totp (success)
                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let (sesid, tok) = match res {
                    SetCredentialResponse::TotpCheck(id, tok) => (id, tok),
                    _ => panic!("invalid state!"),
                };
                // We can't reuse the OTP/Vte from before, since the token seed changes
                let r_tok: Totp = tok.into();
                let chal = r_tok
                    .do_totp_duration_from_epoch(&ct)
                    .expect("Failed to do totp?");
                // attempt the verify
                let vte3 = VerifyTotpEvent::new_internal(UUID_ADMIN.clone(), sesid, chal);

                match idms_prox_write.verify_account_totp(&vte3, ct.clone()) {
                    Ok(SetCredentialResponse::Success) => {}
                    _ => panic!(),
                };
                idms_prox_write.expire_mfareg_sessions(expire.clone());

                // Test removing the TOTP and then authing with password only.
                let rte = RemoveTotpEvent::new_internal(UUID_ADMIN.clone());
                idms_prox_write.remove_account_totp(&rte).unwrap();
                assert!(idms_prox_write.commit().is_ok());

                check_admin_password(idms, TEST_PASSWORD);
                // All done!
            }
        )
    }

    #[test]
    fn test_idm_totp_sha1_registration() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                let ct = duration_from_epoch_now();
                let mut idms_prox_write = idms.proxy_write(ct.clone());

                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                assert!(idms_prox_write.set_account_password(&pce).is_ok());

                // Start registering the TOTP
                let gte1 = GenerateTotpEvent::new_internal(UUID_ADMIN.clone());
                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let (sesid, tok) = match res {
                    SetCredentialResponse::TotpCheck(id, tok) => (id, tok),
                    _ => panic!("invalid state!"),
                };

                let r_tok: Totp = tok.into();
                // Now, assert that the Totp is NOT sha1 (correct default behaviour).
                assert!(!r_tok.is_legacy_algo());
                // Mutate the tok to a legacy token.
                let legacy_tok = r_tok.downgrade_to_legacy();

                let chal = legacy_tok
                    .do_totp_duration_from_epoch(&ct)
                    .expect("Failed to do totp?");
                // attempt the verify
                let vte3 = VerifyTotpEvent::new_internal(UUID_ADMIN.clone(), sesid, chal);

                match idms_prox_write.verify_account_totp(&vte3, ct.clone()) {
                    Ok(SetCredentialResponse::TotpInvalidSha1(_)) => {}
                    _ => panic!(),
                };

                let aste = AcceptSha1TotpEvent::new_internal(UUID_ADMIN.clone(), sesid);

                match idms_prox_write.accept_account_sha1_totp(&aste) {
                    Ok(SetCredentialResponse::Success) => {}
                    _ => panic!(),
                };

                // Done!
            }
        )
    }

    #[test]
    fn test_idm_simple_password_upgrade() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
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
                            AttrString::from("password_import"),
                            Value::from("{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM")
                        )]),
                    )
                    };
                    // go!
                    assert!(qs_write.modify(&me_inv_m).is_ok());
                    qs_write.commit().expect("failed to commit");
                }
                // Still empty
                idms_delayed.is_empty_or_panic();
                // Do an auth, this will trigger the action to send.
                check_admin_password(idms, "password");
                // process it.
                let da = idms_delayed.try_recv().expect("invalid");
                let r = task::block_on(idms.delayed_action(duration_from_epoch_now(), da));
                assert!(Ok(true) == r);
                // Check the admin pw still matches
                check_admin_password(idms, "password");
                // No delayed action was queued.
                idms_delayed.is_empty_or_panic();
            }
        )
    }

    #[test]
    fn test_idm_unix_password_upgrade() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
                // Assert the delayed action queue is empty
                idms_delayed.is_empty_or_panic();
                // Setup the admin with an imported unix pw.
                let idms_prox_write = idms.proxy_write(duration_from_epoch_now());

                let im_pw = "{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM";
                let pw = Password::try_from(im_pw).expect("failed to parse");
                let cred = Credential::new_from_password(pw);
                let v_cred = Value::new_credential("unix", cred);

                let me_posix = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![
                            Modify::Present(
                                AttrString::from("class"),
                                Value::new_class("posixaccount"),
                            ),
                            Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                            Modify::Present(AttrString::from("unix_password"), v_cred),
                        ]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());
                assert!(idms_prox_write.commit().is_ok());
                idms_delayed.is_empty_or_panic();
                // Get the auth ready.
                let uuae = UnixUserAuthEvent::new_internal(&UUID_ADMIN, "password");
                let mut idms_auth = idms.auth();
                let a1 = task::block_on(
                    idms_auth.auth_unix(&uuae, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a1 {
                    Ok(Some(_tok)) => {}
                    _ => assert!(false),
                };
                idms_auth.commit().expect("Must not fail");
                // The upgrade was queued
                // Process it.
                let da = idms_delayed.try_recv().expect("invalid");
                let _r = task::block_on(idms.delayed_action(duration_from_epoch_now(), da));
                // Go again
                let mut idms_auth = idms.auth();
                let a2 = task::block_on(
                    idms_auth.auth_unix(&uuae, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a2 {
                    Ok(Some(_tok)) => {}
                    _ => assert!(false),
                };
                idms_auth.commit().expect("Must not fail");
                // No delayed action was queued.
                idms_delayed.is_empty_or_panic();
            }
        )
    }

    // For testing the timeouts
    // We need times on this scale
    //    not yet valid <-> valid from time <-> current_time <-> expire time <-> expired
    const TEST_NOT_YET_VALID_TIME: u64 = TEST_CURRENT_TIME - 240;
    const TEST_VALID_FROM_TIME: u64 = TEST_CURRENT_TIME - 120;
    const TEST_EXPIRE_TIME: u64 = TEST_CURRENT_TIME + 120;
    const TEST_AFTER_EXPIRY: u64 = TEST_CURRENT_TIME + 240;

    fn set_admin_valid_time(qs: &QueryServer) {
        let qs_write = qs.write(duration_from_epoch_now());

        let v_valid_from = Value::new_datetime_epoch(Duration::from_secs(TEST_VALID_FROM_TIME));
        let v_expire = Value::new_datetime_epoch(Duration::from_secs(TEST_EXPIRE_TIME));

        // now modify and provide a primary credential.
        let me_inv_m = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq("name", PartialValue::new_iname("admin"))),
                ModifyList::new_list(vec![
                    Modify::Present(AttrString::from("account_expire"), v_expire),
                    Modify::Present(AttrString::from("account_valid_from"), v_valid_from),
                ]),
            )
        };
        // go!
        assert!(qs_write.modify(&me_inv_m).is_ok());

        qs_write.commit().expect("Must not fail");
    }

    #[test]
    fn test_idm_account_valid_from_expire() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                // Any account taht is not yet valrid / expired can't auth.

                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                // Set the valid bounds high/low
                // TEST_VALID_FROM_TIME/TEST_EXPIRE_TIME
                set_admin_valid_time(qs);

                let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
                let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

                let mut idms_auth = idms.auth();
                let admin_init = AuthEvent::named_init("admin");
                let r1 = task::block_on(idms_auth.auth(&admin_init, time_low));

                let ar = r1.unwrap();
                let AuthResult {
                    sessionid: _,
                    state,
                    delay,
                } = ar;

                debug_assert!(delay.is_none());
                match state {
                    AuthState::Denied(_) => {}
                    _ => {
                        panic!();
                    }
                };

                idms_auth.commit().expect("Must not fail");

                // And here!
                let mut idms_auth = idms.auth();
                let admin_init = AuthEvent::named_init("admin");
                let r1 = task::block_on(idms_auth.auth(&admin_init, time_high));

                let ar = r1.unwrap();
                let AuthResult {
                    sessionid: _,
                    state,
                    delay,
                } = ar;

                debug_assert!(delay.is_none());
                match state {
                    AuthState::Denied(_) => {}
                    _ => {
                        panic!();
                    }
                };

                idms_auth.commit().expect("Must not fail");
            }
        )
    }

    #[test]
    fn test_idm_unix_valid_from_expire() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                // Any account that is expired can't unix auth.
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                set_admin_valid_time(qs);

                let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
                let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

                // make the admin a valid posix account
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let me_posix = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![
                            Modify::Present(
                                AttrString::from("class"),
                                Value::new_class("posixaccount"),
                            ),
                            Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                        ]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

                let pce = UnixPasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);

                assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
                assert!(idms_prox_write.commit().is_ok());

                // Now check auth when the time is too high or too low.
                let mut idms_auth = idms.auth();
                let uuae_good = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);

                let a1 = task::block_on(idms_auth.auth_unix(&uuae_good, time_low));
                // Should this actually send an error with the details? Or just silently act as
                // badpw?
                match a1 {
                    Ok(None) => {}
                    _ => assert!(false),
                };

                let a2 = task::block_on(idms_auth.auth_unix(&uuae_good, time_high));
                match a2 {
                    Ok(None) => {}
                    _ => assert!(false),
                };

                idms_auth.commit().expect("Must not fail");
                // Also check the generated unix tokens are invalid.
                let mut idms_prox_read = idms.proxy_read();
                let uute = UnixUserTokenEvent::new_internal(UUID_ADMIN.clone());

                let tok_r = idms_prox_read
                    .get_unixusertoken(&uute, time_low)
                    .expect("Failed to generate unix user token");

                assert!(tok_r.name == "admin");
                assert!(tok_r.valid == false);

                let tok_r = idms_prox_read
                    .get_unixusertoken(&uute, time_high)
                    .expect("Failed to generate unix user token");

                assert!(tok_r.name == "admin");
                assert!(tok_r.valid == false);
            }
        )
    }

    #[test]
    fn test_idm_radius_valid_from_expire() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                // Any account not valid/expiry should not return
                // a radius packet.
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                set_admin_valid_time(qs);

                let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
                let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN.clone());
                let _r1 = idms_prox_write
                    .regenerate_radius_secret(&rrse)
                    .expect("Failed to reset radius credential 1");
                idms_prox_write.commit().expect("failed to commit");

                let mut idms_prox_read = idms.proxy_read();
                let rate = RadiusAuthTokenEvent::new_internal(UUID_ADMIN.clone());
                let tok_r = idms_prox_read.get_radiusauthtoken(&rate, time_low);

                if let Err(_) = tok_r {
                    // Ok?
                } else {
                    assert!(false);
                }

                let tok_r = idms_prox_read.get_radiusauthtoken(&rate, time_high);

                if let Err(_) = tok_r {
                    // Ok?
                } else {
                    assert!(false);
                }
            }
        )
    }

    #[test]
    fn test_idm_account_softlocking() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");

                // Auth invalid, no softlock present.
                let sid = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    "admin",
                );
                let mut idms_auth = idms.auth();
                let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD_INC);

                let r2 = task::block_on(
                    idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                debug!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                            delay,
                        } = ar;
                        debug_assert!(delay.is_none());
                        match state {
                            AuthState::Denied(reason) => {
                                assert!(reason != "Account is temporarily locked");
                            }
                            _ => {
                                error!(
                                    "A critical error has occured! We have a non-denied result!"
                                );
                                panic!();
                            }
                        }
                    }
                    Err(e) => {
                        error!("A critical error has occured! {:?}", e);
                        panic!();
                    }
                };
                idms_auth.commit().expect("Must not fail");

                // Auth init, softlock present, count == 1, same time (so before unlock_at)
                // aka Auth valid immediate, (ct < exp), autofail
                // aka Auth invalid immediate, (ct < exp), autofail
                let mut idms_auth = idms.auth();
                let admin_init = AuthEvent::named_init("admin");

                let r1 = task::block_on(
                    idms_auth.auth(&admin_init, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                let ar = r1.unwrap();
                let AuthResult {
                    sessionid: _,
                    state,
                    delay,
                } = ar;

                debug_assert!(delay.is_none());
                match state {
                    AuthState::Denied(reason) => {
                        assert!(reason == "Account is temporarily locked");
                    }
                    _ => {
                        error!("Sessions was not denied (softlock)");
                        panic!();
                    }
                };

                idms_auth.commit().expect("Must not fail");

                // Auth invalid once softlock pass (count == 2, exp_at grows)
                // Tested in the softlock state machine.

                // Auth valid once softlock pass, valid. Count remains.
                let sid = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME + 2),
                    "admin",
                );

                let mut idms_auth = idms.auth();
                let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD);

                // Expect success
                let r2 = task::block_on(
                    idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME + 2)),
                );
                debug!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                            delay,
                        } = ar;
                        debug_assert!(delay.is_none());
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

                idms_auth.commit().expect("Must not fail");
                // Auth valid after reset at, count == 0.
                // Tested in the softlock state machine.

                // Auth invalid, softlock present, count == 1
                // Auth invalid after reset at, count == 0 and then to count == 1
                // Tested in the softlock state machine.
            }
        )
    }

    #[test]
    fn test_idm_account_softlocking_interleaved() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");

                // Start an *early* auth session.
                let sid_early = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    "admin",
                );

                // Start a second auth session
                let sid_later = init_admin_authsession_sid(
                    idms,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    "admin",
                );
                // Get the detail wrong in sid_later.
                let mut idms_auth = idms.auth();
                let anon_step = AuthEvent::cred_step_password(sid_later, TEST_PASSWORD_INC);

                let r2 = task::block_on(
                    idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                debug!("r2 ==> {:?}", r2);

                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                            delay,
                        } = ar;
                        debug_assert!(delay.is_none());
                        match state {
                            AuthState::Denied(reason) => {
                                assert!(reason != "Account is temporarily locked");
                            }
                            _ => {
                                error!(
                                    "A critical error has occured! We have a non-denied result!"
                                );
                                panic!();
                            }
                        }
                    }
                    Err(e) => {
                        error!("A critical error has occured! {:?}", e);
                        panic!();
                    }
                };
                idms_auth.commit().expect("Must not fail");

                // Now check that sid_early is denied due to softlock.
                let mut idms_auth = idms.auth();
                let anon_step = AuthEvent::cred_step_password(sid_early, TEST_PASSWORD);

                // Expect success
                let r2 = task::block_on(
                    idms_auth.auth(&anon_step, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                debug!("r2 ==> {:?}", r2);
                match r2 {
                    Ok(ar) => {
                        let AuthResult {
                            sessionid: _,
                            state,
                            delay,
                        } = ar;
                        debug_assert!(delay.is_none());
                        match state {
                            AuthState::Denied(reason) => {
                                assert!(reason == "Account is temporarily locked");
                            }
                            _ => {
                                error!(
                                    "A critical error has occured! We have a non-denied result!"
                                );
                                panic!();
                            }
                        }
                    }
                    Err(e) => {
                        error!("A critical error has occured! {:?}", e);
                        panic!();
                    }
                };
                idms_auth.commit().expect("Must not fail");
            }
        )
    }

    #[test]
    fn test_idm_account_unix_softlocking() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                // make the admin a valid posix account
                let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
                let me_posix = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("name", PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![
                            Modify::Present(
                                AttrString::from("class"),
                                Value::new_class("posixaccount"),
                            ),
                            Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                        ]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

                let pce = UnixPasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
                assert!(idms_prox_write.commit().is_ok());

                let mut idms_auth = idms.auth();
                let uuae_good = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                let uuae_bad = UnixUserAuthEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD_INC);

                let a2 = task::block_on(
                    idms_auth.auth_unix(&uuae_bad, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a2 {
                    Ok(None) => {}
                    _ => assert!(false),
                };

                // Now if we immediately auth again, should fail at same time due to SL
                let a1 = task::block_on(
                    idms_auth.auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                match a1 {
                    Ok(None) => {}
                    _ => assert!(false),
                };

                // And then later, works because of SL lifting.
                let a1 = task::block_on(
                    idms_auth.auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME + 2)),
                );
                match a1 {
                    Ok(Some(_tok)) => {}
                    _ => assert!(false),
                };

                assert!(idms_auth.commit().is_ok());
            }
        )
    }

    #[test]
    fn test_idm_webauthn_registration_and_counter_inc() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
                let ct = duration_from_epoch_now();
                let mut idms_prox_write = idms.proxy_write(ct.clone());

                let mut wa_softtok = WebauthnAuthenticator::new(U2FSoft::new());

                let wrei = WebauthnInitRegisterEvent::new_internal(
                    UUID_ADMIN.clone(),
                    "softtoken".to_string(),
                );

                let (sessionid, ccr) = match idms_prox_write.reg_account_webauthn_init(&wrei, ct) {
                    Ok(SetCredentialResponse::WebauthnCreateChallenge(sessionid, ccr)) => {
                        (sessionid, ccr)
                    }
                    _ => {
                        panic!();
                    }
                };

                let rego = wa_softtok
                    .do_registration("https://idm.example.com", ccr)
                    .expect("Failed to register to softtoken");

                let wdre =
                    WebauthnDoRegisterEvent::new_internal(UUID_ADMIN.clone(), sessionid, rego);

                match idms_prox_write.reg_account_webauthn_complete(&wdre) {
                    Ok(SetCredentialResponse::Success) => {}
                    _ => {
                        panic!();
                    }
                };

                // Get the account now so we can peek at the registered credential.
                let account = idms_prox_write
                    .target_to_account(&UUID_ADMIN)
                    .expect("account must exist");

                let cred = account.primary.expect("Must exist.");

                let wcred = cred
                    .webauthn_ref()
                    .expect("must have webauthn")
                    .values()
                    .next()
                    .map(|c| c.clone())
                    .expect("must have a webauthn credential");

                assert!(idms_prox_write.commit().is_ok());

                // ===
                // Assert we can increment the counter if needed.

                // Assert the delayed action queue is empty
                idms_delayed.is_empty_or_panic();

                // Generate a fake counter increment
                let da = DelayedAction::WebauthnCounterIncrement(WebauthnCounterIncrement {
                    target_uuid: UUID_ADMIN.clone(),
                    counter: wcred.counter + 1,
                    cid: wcred.cred_id,
                });
                let r = task::block_on(idms.delayed_action(duration_from_epoch_now(), da));
                assert!(Ok(true) == r);

                // Check we can remove the webauthn device - provided we set a pw.
                let mut idms_prox_write = idms.proxy_write(ct.clone());
                let rwe =
                    RemoveWebauthnEvent::new_internal(UUID_ADMIN.clone(), "softtoken".to_string());
                // This fails because the acc is webauthn only.
                match idms_prox_write.remove_account_webauthn(&rwe) {
                    Err(OperationError::InvalidAttribute(_)) => {
                        //ok
                    }
                    _ => assert!(false),
                };
                // Reg a pw.
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                assert!(idms_prox_write.set_account_password(&pce).is_ok());
                // Now remove, it will work.
                idms_prox_write
                    .remove_account_webauthn(&rwe)
                    .expect("Failed to remove webauthn");

                assert!(idms_prox_write.commit().is_ok());

                check_admin_password(idms, TEST_PASSWORD);
                // All done!
            }
        )
    }

    #[test]
    fn test_idm_backup_code_removal_delayed_action() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
                let ct = duration_from_epoch_now();
                let expire = ct - Duration::from_secs(AUTH_SESSION_TIMEOUT);
                let mut idms_prox_write = idms.proxy_write(ct.clone());

                // let mut wa_softtok = WebauthnAuthenticator::new(U2FSoft::new());

                // The account must has primary credential + uses MFA before generating backup codes
                // Set a password.
                let pce = PasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);
                assert!(idms_prox_write.set_account_password(&pce).is_ok());
                // Generate TOTP
                let gte1 = GenerateTotpEvent::new_internal(UUID_ADMIN.clone());
                // == reg, verify w_ correct totp (success)
                let res = idms_prox_write
                    .generate_account_totp(&gte1, ct.clone())
                    .unwrap();
                let (sesid, tok) = match res {
                    SetCredentialResponse::TotpCheck(id, tok) => (id, tok),
                    _ => panic!("invalid state!"),
                };
                let r_tok: Totp = tok.into();
                let chal = r_tok
                    .do_totp_duration_from_epoch(&ct)
                    .expect("Failed to do totp?");
                // attempt the verify
                let vte3 = VerifyTotpEvent::new_internal(UUID_ADMIN.clone(), sesid, chal);

                match idms_prox_write.verify_account_totp(&vte3, ct.clone()) {
                    Ok(SetCredentialResponse::Success) => {}
                    _ => panic!(),
                };
                idms_prox_write.expire_mfareg_sessions(expire.clone());

                // Generate backup codes
                let gbe = GenerateBackupCodeEvent::new_internal(UUID_ADMIN.clone());

                let backup_codes_vec = idms_prox_write.generate_backup_code(&gbe).unwrap();
                let code_for_test = &backup_codes_vec[0];
                // Get the account now so we can peek at the registered credential.
                let account = idms_prox_write
                    .target_to_account(&UUID_ADMIN)
                    .expect("account must exist");

                let cred = account.primary.expect("Must exist.");

                let backup_codes_view = cred.get_backup_code_view().expect("must have view");
                assert!(backup_codes_view.backup_codes.contains(code_for_test));
                assert!(idms_prox_write.commit().is_ok());

                // Assert the delayed action queue is empty
                idms_delayed.is_empty_or_panic();

                // Generate a fake action to remove one backup code
                let da = DelayedAction::BackupCodeRemoval(BackupCodeRemoval {
                    target_uuid: UUID_ADMIN.clone(),
                    code_to_remove: code_for_test.to_string(),
                });
                let r = task::block_on(idms.delayed_action(duration_from_epoch_now(), da));
                assert!(Ok(true) == r);

                // Check the removed backup code is no longer in the set
                let mut idms_prox_write = idms.proxy_write(ct.clone());

                let account = idms_prox_write
                    .target_to_account(&UUID_ADMIN)
                    .expect("account must exist");

                let cred = account.primary.expect("Must exist.");

                let backup_codes_view = cred.get_backup_code_view().expect("must have view");
                assert!(!backup_codes_view.backup_codes.contains(code_for_test));
            }
        )
    }

    #[test]
    fn test_idm_bundy_uat_expiry() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                let ct = Duration::from_secs(TEST_CURRENT_TIME);
                let expiry = ct + Duration::from_secs(AUTH_SESSION_EXPIRY + 1);
                // Do an authenticate
                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                let token = check_admin_password(idms, TEST_PASSWORD);

                let idms_prox_read = idms.proxy_read();

                // Check it's valid.
                idms_prox_read
                    .validate_and_parse_uat(Some(token.as_str()), ct)
                    .expect("Failed to validate");

                // In X time it should be INVALID
                match idms_prox_read.validate_and_parse_uat(Some(token.as_str()), expiry) {
                    Err(OperationError::SessionExpired) => {}
                    _ => assert!(false),
                }
            }
        )
    }

    #[test]
    fn test_idm_uat_claim_insertion() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = idms.proxy_write(ct.clone());

            // get an account.
            let account = idms_prox_write
                .target_to_account(&UUID_ADMIN)
                .expect("account must exist");

            // Create some fake UATs, then process them and see what claims fall out 🥳
            let session_id = uuid::Uuid::new_v4();

            // For the different auth types, check that we get the correct claims:

            // == anonymous
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::Anonymous)
                .expect("Unable to create uat");
            let ident = idms_prox_write
                .process_uat_to_identity(&uat, ct)
                .expect("Unable to process uat");

            assert!(!ident.has_claim("authtype_anonymous"));
            // Does NOT have this
            assert!(!ident.has_claim("authlevel_strong"));
            assert!(!ident.has_claim("authclass_single"));
            assert!(!ident.has_claim("authclass_mfa"));

            // == unixpassword
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::UnixPassword)
                .expect("Unable to create uat");
            let ident = idms_prox_write
                .process_uat_to_identity(&uat, ct)
                .expect("Unable to process uat");

            assert!(!ident.has_claim("authtype_unixpassword"));
            assert!(!ident.has_claim("authclass_single"));
            // Does NOT have this
            assert!(!ident.has_claim("authlevel_strong"));
            assert!(!ident.has_claim("authclass_mfa"));

            // == password
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::Password)
                .expect("Unable to create uat");
            let ident = idms_prox_write
                .process_uat_to_identity(&uat, ct)
                .expect("Unable to process uat");

            assert!(!ident.has_claim("authtype_password"));
            assert!(!ident.has_claim("authclass_single"));
            // Does NOT have this
            assert!(!ident.has_claim("authlevel_strong"));
            assert!(!ident.has_claim("authclass_mfa"));

            // == generatedpassword
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::GeneratedPassword)
                .expect("Unable to create uat");
            let ident = idms_prox_write
                .process_uat_to_identity(&uat, ct)
                .expect("Unable to process uat");

            assert!(!ident.has_claim("authtype_generatedpassword"));
            assert!(!ident.has_claim("authclass_single"));
            assert!(!ident.has_claim("authlevel_strong"));
            // Does NOT have this
            assert!(!ident.has_claim("authclass_mfa"));

            // == webauthn
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::Webauthn)
                .expect("Unable to create uat");
            let ident = idms_prox_write
                .process_uat_to_identity(&uat, ct)
                .expect("Unable to process uat");

            assert!(!ident.has_claim("authtype_webauthn"));
            assert!(!ident.has_claim("authclass_single"));
            assert!(!ident.has_claim("authlevel_strong"));
            // Does NOT have this
            assert!(!ident.has_claim("authclass_mfa"));

            // == passwordmfa
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::PasswordMfa)
                .expect("Unable to create uat");
            let ident = idms_prox_write
                .process_uat_to_identity(&uat, ct)
                .expect("Unable to process uat");

            assert!(!ident.has_claim("authtype_passwordmfa"));
            assert!(!ident.has_claim("authlevel_strong"));
            assert!(!ident.has_claim("authclass_mfa"));
            // Does NOT have this
            assert!(!ident.has_claim("authclass_single"));
        })
    }

    #[test]
    fn test_idm_bundy_uat_token_key_reload() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                let ct = Duration::from_secs(TEST_CURRENT_TIME);

                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                let token = check_admin_password(idms, TEST_PASSWORD);
                let idms_prox_read = idms.proxy_read();

                // Check it's valid.
                idms_prox_read
                    .validate_and_parse_uat(Some(token.as_str()), ct)
                    .expect("Failed to validate");

                drop(idms_prox_read);

                // Now reset the token_key - we can cheat and push this
                // through the migrate 3 to 4 code.
                let idms_prox_write = idms.proxy_write(ct.clone());
                idms_prox_write
                    .qs_write
                    .migrate_3_to_4()
                    .expect("Failed to reset domain token key");
                assert!(idms_prox_write.commit().is_ok());
                // Check the old token is invalid, due to reload.
                let new_token = check_admin_password(idms, TEST_PASSWORD);

                let idms_prox_read = idms.proxy_read();
                assert!(idms_prox_read
                    .validate_and_parse_uat(Some(token.as_str()), ct)
                    .is_err());
                // A new token will work due to the matching key.
                idms_prox_read
                    .validate_and_parse_uat(Some(new_token.as_str()), ct)
                    .expect("Failed to validate");
            }
        )
    }
}

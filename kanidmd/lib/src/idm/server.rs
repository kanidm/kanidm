use core::task::{Context, Poll};
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_std::task;
use compact_jwt::{Jws, JwsSigner, JwsUnverified, JwsValidator};
use concread::bptree::{BptreeMap, BptreeMapReadTxn, BptreeMapWriteTxn};
use concread::cowcell::{CowCellReadTxn, CowCellWriteTxn};
use concread::hashmap::HashMap;
use concread::CowCell;
use fernet::Fernet;
// #[cfg(any(test,bench))]
use futures::task as futures_task;
use hashbrown::HashSet;
use kanidm_proto::v1::{
    ApiToken, BackupCodesView, CredentialStatus, PasswordFeedback, RadiusAuthToken, UnixGroupToken,
    UnixUserToken, UserAuthToken,
};
use rand::prelude::*;
use tokio::sync::mpsc::{
    unbounded_channel as unbounded, UnboundedReceiver as Receiver, UnboundedSender as Sender,
};
use tokio::sync::{Mutex, Semaphore};
use tracing::trace;
use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

use super::delayed::BackupCodeRemoval;
use super::event::ReadBackupCodeEvent;
use crate::credential::policy::CryptoPolicy;
use crate::credential::softlock::CredSoftLock;
use crate::event::{AuthEvent, AuthEventStep, AuthResult};
use crate::identity::{IdentType, IdentUser, Limits};
use crate::idm::account::Account;
use crate::idm::authsession::AuthSession;
use crate::idm::credupdatesession::CredentialUpdateSessionMutex;
use crate::idm::delayed::{
    DelayedAction, Oauth2ConsentGrant, PasswordUpgrade, UnixPasswordUpgrade,
    WebauthnCounterIncrement,
};
#[cfg(test)]
use crate::idm::event::PasswordChangeEvent;
use crate::idm::event::{
    CredentialStatusEvent, GeneratePasswordEvent, LdapAuthEvent, LdapTokenAuthEvent,
    RadiusAuthTokenEvent, RegenerateRadiusSecretEvent, UnixGroupTokenEvent,
    UnixPasswordChangeEvent, UnixUserAuthEvent, UnixUserTokenEvent,
};
use crate::idm::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationRequest, AuthorisePermitSuccess, AuthoriseResponse,
    JwkKeySet, Oauth2Error, Oauth2ResourceServers, Oauth2ResourceServersReadTransaction,
    Oauth2ResourceServersWriteTransaction, OidcDiscoveryResponse, OidcToken,
};
use crate::idm::radius::RadiusAccount;
use crate::idm::serviceaccount::ServiceAccount;
use crate::idm::unix::{UnixGroup, UnixUserAccount};
use crate::idm::AuthState;
use crate::ldap::{LdapBoundToken, LdapSession};
use crate::prelude::*;
use crate::utils::{password_from_random, readable_password_from_random, uuid_from_duration, Sid};

type AuthSessionMutex = Arc<Mutex<AuthSession>>;
type CredSoftLockMutex = Arc<Mutex<CredSoftLock>>;

pub struct IdmServer {
    // There is a good reason to keep this single thread - it
    // means that limits to sessions can be easily applied and checked to
    // various accounts, and we have a good idea of how to structure the
    // in memory caches related to locking.
    session_ticket: Semaphore,
    sessions: BptreeMap<Uuid, AuthSessionMutex>,
    softlocks: HashMap<Uuid, CredSoftLockMutex>,
    /// A set of in progress credential registrations
    cred_update_sessions: BptreeMap<Uuid, CredentialUpdateSessionMutex>,
    /// Reference to the query server.
    qs: QueryServer,
    /// The configured crypto policy for the IDM server. Later this could be transactional and loaded from the db similar to access. But today it's just to allow dynamic pbkdf2rounds
    crypto_policy: CryptoPolicy,
    async_tx: Sender<DelayedAction>,
    /// [Webauthn] verifier/config
    webauthn: Webauthn,
    pw_badlist_cache: Arc<CowCell<HashSet<String>>>,
    oauth2rs: Arc<Oauth2ResourceServers>,

    uat_jwt_signer: Arc<CowCell<JwsSigner>>,
    uat_jwt_validator: Arc<CowCell<JwsValidator>>,
    token_enc_key: Arc<CowCell<Fernet>>,
}

/// Contains methods that require writes, but in the context of writing to the idm in memory structures (maybe the query server too). This is things like authentication.
pub struct IdmServerAuthTransaction<'a> {
    session_ticket: &'a Semaphore,
    sessions: &'a BptreeMap<Uuid, AuthSessionMutex>,
    softlocks: &'a HashMap<Uuid, CredSoftLockMutex>,

    pub qs_read: QueryServerReadTransaction<'a>,
    /// Thread/Server ID
    sid: Sid,
    // For flagging eventual actions.
    async_tx: Sender<DelayedAction>,
    webauthn: &'a Webauthn,
    pw_badlist_cache: CowCellReadTxn<HashSet<String>>,
    uat_jwt_signer: CowCellReadTxn<JwsSigner>,
    uat_jwt_validator: CowCellReadTxn<JwsValidator>,
}

pub struct IdmServerCredUpdateTransaction<'a> {
    pub(crate) _qs_read: QueryServerReadTransaction<'a>,
    // sid: Sid,
    pub(crate) webauthn: &'a Webauthn,
    pub(crate) pw_badlist_cache: CowCellReadTxn<HashSet<String>>,
    pub(crate) cred_update_sessions: BptreeMapReadTxn<'a, Uuid, CredentialUpdateSessionMutex>,
    pub(crate) token_enc_key: CowCellReadTxn<Fernet>,
    pub(crate) crypto_policy: &'a CryptoPolicy,
}

/// This contains read-only methods, like getting users, groups and other structured content.
pub struct IdmServerProxyReadTransaction<'a> {
    pub qs_read: QueryServerReadTransaction<'a>,
    uat_jwt_validator: CowCellReadTxn<JwsValidator>,
    oauth2rs: Oauth2ResourceServersReadTransaction,
    async_tx: Sender<DelayedAction>,
}

pub struct IdmServerProxyWriteTransaction<'a> {
    // This does NOT take any read to the memory content, allowing safe
    // qs operations to occur through this interface.
    pub qs_write: QueryServerWriteTransaction<'a>,
    /// Associate to an event origin ID, which has a TS and a UUID instead
    pub(crate) cred_update_sessions: BptreeMapWriteTxn<'a, Uuid, CredentialUpdateSessionMutex>,
    pub(crate) sid: Sid,
    crypto_policy: &'a CryptoPolicy,
    webauthn: &'a Webauthn,
    pw_badlist_cache: CowCellWriteTxn<'a, HashSet<String>>,
    uat_jwt_signer: CowCellWriteTxn<'a, JwsSigner>,
    uat_jwt_validator: CowCellWriteTxn<'a, JwsValidator>,
    pub(crate) token_enc_key: CowCellWriteTxn<'a, Fernet>,
    oauth2rs: Oauth2ResourceServersWriteTransaction<'a>,
}

pub struct IdmServerDelayed {
    pub(crate) async_rx: Receiver<DelayedAction>,
}

impl IdmServer {
    // TODO: Make number of authsessions configurable!!!
    pub fn new(
        qs: QueryServer,
        origin: &str,
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
        let (rp_id, rp_name, fernet_private_key, es256_private_key, pw_badlist_set, oauth2rs_set) = {
            let qs_read = task::block_on(qs.read_async());
            (
                qs_read.get_domain_name().to_string(),
                qs_read.get_domain_display_name().to_string(),
                qs_read.get_domain_fernet_private_key()?,
                qs_read.get_domain_es256_private_key()?,
                qs_read.get_password_badlist()?,
                // Add a read/reload of all oauth2 configurations.
                qs_read.get_oauth2rs_set()?,
            )
        };

        // Check that it gels with our origin.
        let origin_url = Url::parse(origin)
            .map_err(|_e| {
                admin_error!("Unable to parse origin URL - refusing to start. You must correct the value for origin. {:?}", origin);
                OperationError::InvalidState
            })
            .and_then(|url| {
                let valid = url.domain().map(|effective_domain| {
                    // We need to prepend the '.' here to ensure that myexample.com != example.com,
                    // rather than just ends with.
                    effective_domain.ends_with(&format!(".{}", rp_id))
                    || effective_domain == rp_id
                }).unwrap_or(false);

                if valid {
                    Ok(url)
                } else {
                    admin_error!("Effective domain is not a descendent of server domain name (rp_id).");
                    admin_error!("You must change origin or domain name to be consistent. ed: {:?} - rp_id: {:?}", origin, rp_id);
                    admin_error!("To change the origin or domain name see: https://kanidm.github.io/kanidm/server_configuration.html");
                    Err(OperationError::InvalidState)
                }
            })?;

        let webauthn = WebauthnBuilder::new(&rp_id, &origin_url)
            .and_then(|builder| builder.allow_subdomains(true).rp_name(&rp_name).build())
            .map_err(|e| {
                admin_error!("Invalid Webauthn Configuration - {:?}", e);
                OperationError::InvalidState
            })?;

        // Setup our auth token signing key.
        let fernet_key = Fernet::new(&fernet_private_key).ok_or_else(|| {
            admin_error!("Unable to load Fernet encryption key");
            OperationError::CryptographyError
        })?;
        let token_enc_key = Arc::new(CowCell::new(fernet_key));

        let jwt_signer = JwsSigner::from_es256_der(&es256_private_key).map_err(|e| {
            admin_error!(err = ?e, "Unable to load ES256 JwsSigner from DER");
            OperationError::CryptographyError
        })?;

        let jwt_validator = jwt_signer.get_validator().map_err(|e| {
            admin_error!(err = ?e, "Unable to load ES256 JwsValidator from JwsSigner");
            OperationError::CryptographyError
        })?;

        let uat_jwt_signer = Arc::new(CowCell::new(jwt_signer));
        let uat_jwt_validator = Arc::new(CowCell::new(jwt_validator));

        let oauth2rs =
            Oauth2ResourceServers::try_from((oauth2rs_set, origin_url)).map_err(|e| {
                admin_error!("Failed to load oauth2 resource servers - {:?}", e);
                e
            })?;

        Ok((
            IdmServer {
                session_ticket: Semaphore::new(1),
                sessions: BptreeMap::new(),
                softlocks: HashMap::new(),
                cred_update_sessions: BptreeMap::new(),
                qs,
                crypto_policy,
                async_tx,
                webauthn,
                pw_badlist_cache: Arc::new(CowCell::new(pw_badlist_set)),
                uat_jwt_signer,
                uat_jwt_validator,
                token_enc_key,
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

        let qs_read = self.qs.read_async().await;

        IdmServerAuthTransaction {
            session_ticket: &self.session_ticket,
            sessions: &self.sessions,
            softlocks: &self.softlocks,
            qs_read,
            sid,
            async_tx: self.async_tx.clone(),
            webauthn: &self.webauthn,
            pw_badlist_cache: self.pw_badlist_cache.read(),
            uat_jwt_signer: self.uat_jwt_signer.read(),
            uat_jwt_validator: self.uat_jwt_validator.read(),
        }
    }

    /// Perform a blocking read transaction on the database.
    #[cfg(test)]
    pub fn proxy_read<'a>(&'a self) -> IdmServerProxyReadTransaction<'a> {
        task::block_on(self.proxy_read_async())
    }

    /// Read from the database, in a transaction.
    #[instrument(level = "debug", skip_all)]
    pub async fn proxy_read_async(&self) -> IdmServerProxyReadTransaction<'_> {
        IdmServerProxyReadTransaction {
            qs_read: self.qs.read_async().await,
            uat_jwt_validator: self.uat_jwt_validator.read(),
            oauth2rs: self.oauth2rs.read(),
            async_tx: self.async_tx.clone(),
        }
    }

    #[cfg(test)]
    pub fn proxy_write(&self, ts: Duration) -> IdmServerProxyWriteTransaction {
        task::block_on(self.proxy_write_async(ts))
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn proxy_write_async(&self, ts: Duration) -> IdmServerProxyWriteTransaction<'_> {
        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);
        let qs_write = self.qs.write_async(ts).await;

        IdmServerProxyWriteTransaction {
            cred_update_sessions: self.cred_update_sessions.write(),
            qs_write,
            sid,
            crypto_policy: &self.crypto_policy,
            webauthn: &self.webauthn,
            pw_badlist_cache: self.pw_badlist_cache.write(),
            uat_jwt_signer: self.uat_jwt_signer.write(),
            uat_jwt_validator: self.uat_jwt_validator.write(),
            token_enc_key: self.token_enc_key.write(),
            oauth2rs: self.oauth2rs.write(),
        }
    }

    #[cfg(test)]
    pub fn cred_update_transaction(&self) -> IdmServerCredUpdateTransaction<'_> {
        task::block_on(self.cred_update_transaction_async())
    }

    pub async fn cred_update_transaction_async(&self) -> IdmServerCredUpdateTransaction<'_> {
        IdmServerCredUpdateTransaction {
            _qs_read: self.qs.read_async().await,
            // sid: Sid,
            webauthn: &self.webauthn,
            pw_badlist_cache: self.pw_badlist_cache.read(),
            cred_update_sessions: self.cred_update_sessions.read(),
            token_enc_key: self.token_enc_key.read(),
            crypto_policy: &self.crypto_policy,
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
    // #[cfg(any(test,bench))]
    pub(crate) fn check_is_empty_or_panic(&mut self) {
        let waker = futures_task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match self.async_rx.poll_recv(&mut cx) {
            Poll::Pending | Poll::Ready(None) => {}
            Poll::Ready(Some(_m)) => panic!("Task queue not empty"),
        }
    }

    #[cfg(test)]
    pub(crate) fn blocking_recv(&mut self) -> Option<DelayedAction> {
        self.async_rx.blocking_recv()
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

    pub async fn next(&mut self) -> Option<DelayedAction> {
        self.async_rx.recv().await
    }
}

pub enum Token {
    UserAuthToken(UserAuthToken),
    ApiToken(ApiToken, Arc<EntrySealedCommitted>),
}

pub trait IdmServerTransaction<'a> {
    type QsTransactionType: QueryServerTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType;

    fn get_uat_validator_txn(&self) -> &JwsValidator;

    /// This is the preferred method to transform and securely verify a token into
    /// an identity that can be used for operations and access enforcement. This
    /// function *is* aware of the various classes of tokens that may exist, and can
    /// appropriately check them.
    ///
    /// The primary method of verification selection is the use of the KID parameter
    /// that we internally sign with. We can use this to select the appropriate token type
    /// and validation method.
    #[instrument(level = "info", skip_all)]
    fn validate_and_parse_token_to_ident(
        &self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        match self.validate_and_parse_token_to_token(token, ct)? {
            Token::UserAuthToken(uat) => self.process_uat_to_identity(&uat, ct),
            Token::ApiToken(apit, entry) => self.process_apit_to_identity(&apit, entry, ct),
        }
    }

    fn validate_and_parse_token_to_token(
        &self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<Token, OperationError> {
        let jwsu = token
            .ok_or_else(|| {
                security_info!("No token provided");
                OperationError::NotAuthenticated
            })
            .and_then(|s| {
                JwsUnverified::from_str(s).map_err(|e| {
                    security_info!(?e, "Unable to decode token");
                    OperationError::NotAuthenticated
                })
            })?;

        // Frow the unverified token we can now get the kid, and use that to locate the correct
        // key to id the token.
        let jws_validator = self.get_uat_validator_txn();
        let kid = jwsu.get_jwk_kid().ok_or_else(|| {
            security_info!("Token does not contain a valid kid");
            OperationError::NotAuthenticated
        })?;

        let jwsv_kid = jws_validator.get_jwk_kid().ok_or_else(|| {
            security_info!("JWS validator does not contain a valid kid");
            OperationError::NotAuthenticated
        })?;

        if kid == jwsv_kid {
            // It's signed by the primary jws, so it's probably a UserAuthToken.
            let uat = jwsu
                .validate(jws_validator)
                .map_err(|e| {
                    security_info!(?e, "Unable to verify token");
                    OperationError::NotAuthenticated
                })
                .map(|t: Jws<UserAuthToken>| t.into_inner())?;

            if time::OffsetDateTime::unix_epoch() + ct >= uat.expiry {
                security_info!("Session expired");
                Err(OperationError::SessionExpired)
            } else {
                Ok(Token::UserAuthToken(uat))
            }
        } else {
            // It's a per-user key, get their validator.
            let entry = self
                .get_qs_txn()
                .internal_search(filter!(f_eq(
                    "jws_es256_private_key",
                    PartialValue::new_iutf8(&kid)
                )))
                .and_then(|mut vs| match vs.pop() {
                    Some(entry) if vs.is_empty() => Ok(entry),
                    _ => {
                        admin_error!(
                            ?kid,
                            "entries was empty, or matched multiple results for kid"
                        );
                        Err(OperationError::NotAuthenticated)
                    }
                })?;

            let user_signer = entry
                .get_ava_single_jws_key_es256("jws_es256_private_key")
                .ok_or_else(|| {
                    admin_error!(
                        ?kid,
                        "A kid was present on entry {} but it does not contain a signing key",
                        entry.get_uuid()
                    );
                    OperationError::NotAuthenticated
                })?;

            let user_validator = user_signer.get_validator().map_err(|e| {
                security_info!(?e, "Unable to access token verifier");
                OperationError::NotAuthenticated
            })?;

            let apit = jwsu
                .validate(&user_validator)
                .map_err(|e| {
                    security_info!(?e, "Unable to verify token");
                    OperationError::NotAuthenticated
                })
                .map(|t: Jws<ApiToken>| t.into_inner())?;

            if let Some(expiry) = apit.expiry {
                if time::OffsetDateTime::unix_epoch() + ct >= expiry {
                    security_info!("Session expired");
                    return Err(OperationError::SessionExpired);
                }
            }

            Ok(Token::ApiToken(apit, entry))
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn validate_and_parse_uat(
        &self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<UserAuthToken, OperationError> {
        // Given the token string, validate and recreate the UAT
        let jws_validator = self.get_uat_validator_txn();

        let uat: UserAuthToken = token
            .ok_or(OperationError::NotAuthenticated)
            .and_then(|s| {
                JwsUnverified::from_str(s).map_err(|e| {
                    security_info!(?e, "Unable to decode token");
                    OperationError::NotAuthenticated
                })
            })
            .and_then(|jwtu| {
                jwtu.validate(jws_validator)
                    .map_err(|e| {
                        security_info!(?e, "Unable to verify token");
                        OperationError::NotAuthenticated
                    })
                    .map(|t: Jws<UserAuthToken>| t.into_inner())
            })?;

        if time::OffsetDateTime::unix_epoch() + ct >= uat.expiry {
            security_info!("Session expired");
            Err(OperationError::SessionExpired)
        } else {
            Ok(uat)
        }
    }

    fn check_account_uuid_valid(
        &self,
        uuid: &Uuid,
        ct: Duration,
    ) -> Result<Option<Account>, OperationError> {
        let entry = self.get_qs_txn().internal_search_uuid(uuid).map_err(|e| {
            admin_error!(?e, "check_account_uuid_valid failed");
            e
        })?;

        if Account::check_within_valid_time(
            ct,
            entry.get_ava_single_datetime("account_valid_from").as_ref(),
            entry.get_ava_single_datetime("account_expire").as_ref(),
        ) {
            Account::try_from_entry_no_groups(entry.as_ref()).map(Some)
        } else {
            Ok(None)
        }
    }

    /// For any event/operation to proceed, we need to attach an identity to the
    /// event for security and access processing. When that event is externally
    /// triggered via one of our various api layers, we process some type of
    /// account token into this identity. In the current server this is the
    /// UserAuthToken. For a UserAuthToken to be provided it MUST have been
    /// cryptographically verified meaning it is now a *trusted* source of
    /// data that we previously issued.
    ///
    /// This is the function that is responsible for converting that UAT into
    /// something we can pin access controls and other limits and references to.
    /// This is why it is the location where validity windows are checked and other
    /// relevant session information is injected.
    #[instrument(level = "debug", skip_all)]
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

        let limits = Limits::default();
        Ok(Identity {
            origin: IdentType::User(IdentUser { entry }),
            limits,
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn process_apit_to_identity(
        &self,
        apit: &ApiToken,
        entry: Arc<EntrySealedCommitted>,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        let valid = ServiceAccount::check_api_token_valid(ct, apit, &entry);

        if !valid {
            // Check_api token logs this.
            return Err(OperationError::SessionExpired);
        }

        let limits = Limits::default();
        Ok(Identity {
            origin: IdentType::User(IdentUser { entry }),
            limits,
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn validate_ldap_session(
        &self,
        session: &LdapSession,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        match session {
            LdapSession::UnixBind(uuid) => {
                let anon_entry = self
                    .get_qs_txn()
                    .internal_search_uuid(&UUID_ANONYMOUS)
                    .map_err(|e| {
                        admin_error!("Failed to validate ldap session -> {:?}", e);
                        e
                    })?;

                let entry = if uuid == &UUID_ANONYMOUS {
                    anon_entry.clone()
                } else {
                    self.get_qs_txn().internal_search_uuid(&uuid).map_err(|e| {
                        admin_error!("Failed to start auth ldap -> {:?}", e);
                        e
                    })?
                };

                if Account::check_within_valid_time(
                    ct,
                    entry.get_ava_single_datetime("account_valid_from").as_ref(),
                    entry.get_ava_single_datetime("account_expire").as_ref(),
                ) {
                    // Good to go
                    let limits = Limits::default();
                    Ok(Identity {
                        origin: IdentType::User(IdentUser { entry: anon_entry }),
                        limits,
                    })
                } else {
                    // Nope, expired
                    Err(OperationError::SessionExpired)
                }
            }
            LdapSession::UserAuthToken(uat) => self.process_uat_to_identity(&uat, ct),
            LdapSession::ApiToken(apit) => {
                let entry = self
                    .get_qs_txn()
                    .internal_search_uuid(&apit.account_id)
                    .map_err(|e| {
                        admin_error!("Failed to validate ldap session -> {:?}", e);
                        e
                    })?;

                self.process_apit_to_identity(&apit, entry, ct)
            }
        }
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerAuthTransaction<'a> {
    type QsTransactionType = QueryServerReadTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType {
        &self.qs_read
    }

    fn get_uat_validator_txn(&self) -> &JwsValidator {
        &*self.uat_jwt_validator
    }
}

impl<'a> IdmServerAuthTransaction<'a> {
    #[cfg(test)]
    pub fn is_sessionid_present(&self, sessionid: &Uuid) -> bool {
        let session_read = self.sessions.read();
        session_read.contains_key(sessionid)
    }

    #[instrument(level = "trace", skip(self))]
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
                let euuid = self.qs_read.name_to_uuid(init.name.as_str())?;

                // Get the first / single entry we expect here ....
                let entry = self.qs_read.internal_search_uuid(&euuid)?;

                security_info!(
                    name = %init.name,
                    uuid = %euuid,
                    "Initiating Authentication Session",
                );

                // Now, convert the Entry to an account - this gives us some stronger
                // typing and functionality so we can assess what auth types can
                // continue, and helps to keep non-needed entry specific data
                // out of the session tree.
                let account = Account::try_from_entry_ro(entry.as_ref(), &mut self.qs_read)?;

                trace!(?account.primary);

                // Intent to take both trees to write.
                let _session_ticket = self.session_ticket.acquire().await;

                // We don't actually check the softlock here. We just initialise
                // it under the write lock we currently have, so that we can validate
                // it once we understand what auth mech we will be using.
                //
                // NOTE: Very careful use of await here to avoid an issue with write.
                let _maybe_slock_ref =
                    account
                        .primary_cred_uuid_and_policy()
                        .map(|(cred_uuid, policy)| {
                            // Acquire the softlock map
                            //
                            // We have no issue calling this with .write here, since we
                            // already hold the session_ticket above.
                            let mut softlock_write = self.softlocks.write();
                            let slock_ref: CredSoftLockMutex =
                                if let Some(slock_ref) = softlock_write.get(&cred_uuid) {
                                    slock_ref.clone()
                                } else {
                                    // Create if not exist, and the cred type supports softlocking.
                                    let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                                    softlock_write.insert(cred_uuid, slock.clone());
                                    slock
                                };
                            softlock_write.commit();
                            slock_ref
                        });

                /*
                let mut maybe_slock = if let Some(slock_ref) = maybe_slock_ref.as_ref() {
                    Some(slock_ref.lock().await)
                } else {
                    None
                };

                // Need to as_mut here so that we hold the slock for the whole operation.
                let is_valid = if let Some(slock) = maybe_slock.as_mut() {
                    slock.apply_time_step(ct);
                    slock.is_valid()
                } else {
                    false
                };
                */

                /*
                let (auth_session, state) = if is_valid {
                    AuthSession::new(account, self.webauthn, ct)
                } else {
                    // it's softlocked, don't even bother.
                    security_info!("Account is softlocked, or has no credentials associated.");
                    (
                        None,
                        AuthState::Denied("Account is temporarily locked".to_string()),
                    )
                };
                */

                let (auth_session, state) = AuthSession::new(account, self.webauthn, ct);

                match auth_session {
                    Some(auth_session) => {
                        let mut session_write = self.sessions.write();
                        if session_write.contains_key(&sessionid) {
                            Err(OperationError::InvalidSessionState)
                        } else {
                            session_write.insert(sessionid, Arc::new(Mutex::new(auth_session)));
                            // Debugging: ensure we really inserted ...
                            debug_assert!(session_write.get(&sessionid).is_some());
                            Ok(())
                        }?;
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
                // let _session_ticket = self.session_ticket.acquire().await;

                let session_read = self.sessions.read();
                // Do we have a session?
                let auth_session_ref = session_read
                    // Why is the session missing?
                    .get(&mech.sessionid)
                    .cloned()
                    .ok_or_else(|| {
                        admin_error!("Invalid Session State (no present session uuid)");
                        OperationError::InvalidSessionState
                    })?;

                let mut auth_session = auth_session_ref.lock().await;

                // Indicate to the session which auth mech we now want to proceed with.
                let auth_result = auth_session.start_session(&mech.mech);

                let is_valid = match auth_session.get_credential_uuid()? {
                    Some(cred_uuid) => {
                        // From the auth_session, determine if the current account
                        // credential that we are using has become softlocked or not.
                        let softlock_read = self.softlocks.read();
                        if let Some(slock_ref) = softlock_read.get(&cred_uuid) {
                            let mut slock = slock_ref.lock().await;
                            // Apply the current time.
                            slock.apply_time_step(ct);
                            // Now check the results
                            slock.is_valid()
                        } else {
                            false
                        }
                    }
                    None => true,
                };

                if is_valid {
                    auth_result
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
                })
            } // End AuthEventStep::Mech
            AuthEventStep::Cred(creds) => {
                // lperf_segment!("idm::server::auth<Creds>", || {
                // let _session_ticket = self.session_ticket.acquire().await;

                let session_read = self.sessions.read();
                // Do we have a session?
                let auth_session_ref = session_read
                    // Why is the session missing?
                    .get(&creds.sessionid)
                    .cloned()
                    .ok_or_else(|| {
                        admin_error!("Invalid Session State (no present session uuid)");
                        OperationError::InvalidSessionState
                    })?;

                let mut auth_session = auth_session_ref.lock().await;

                let maybe_slock_ref = match auth_session.get_credential_uuid()? {
                    Some(cred_uuid) => {
                        let softlock_read = self.softlocks.read();
                        softlock_read.get(&cred_uuid).cloned()
                    }
                    None => None,
                };

                // From the auth_session, determine if the current account
                // credential that we are using has become softlocked or not.
                let mut maybe_slock = if let Some(s) = maybe_slock_ref.as_ref() {
                    Some(s.lock().await)
                } else {
                    None
                };

                let is_valid = if let Some(ref mut slock) = maybe_slock {
                    // Apply the current time.
                    slock.apply_time_step(ct);
                    // Now check the results
                    slock.is_valid()
                } else {
                    // No slock is present for this cred_uuid
                    true
                };

                if is_valid {
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
                            &*self.uat_jwt_signer,
                        )
                        .map(|aus| {
                            // Inspect the result:
                            // if it was a failure, we need to inc the softlock.
                            if let AuthState::Denied(_) = &aus {
                                // Update it.
                                if let Some(ref mut slock) = maybe_slock {
                                    slock.record_failure(ct);
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
                })
            } // End AuthEventStep::Cred
        }
    }

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

        let maybe_slock_ref = match account.unix_cred_uuid_and_policy() {
            Some((cred_uuid, policy)) => {
                let softlock_read = self.softlocks.read();
                let slock_ref = match softlock_read.get(&cred_uuid) {
                    Some(slock_ref) => slock_ref.clone(),
                    None => {
                        let _session_ticket = self.session_ticket.acquire().await;
                        let mut softlock_write = self.softlocks.write();
                        let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                        softlock_write.insert(cred_uuid, slock.clone());
                        softlock_write.commit();
                        slock
                    }
                };
                Some(slock_ref)
            }
            None => None,
        };

        let maybe_slock = if let Some(s) = maybe_slock_ref.as_ref() {
            Some(s.lock().await)
        } else {
            None
        };

        let maybe_valid = if let Some(mut slock) = maybe_slock {
            // Apply the current time.
            slock.apply_time_step(ct);
            // Now check the results
            if slock.is_valid() {
                Some(slock)
            } else {
                None
            }
        } else {
            None
        };

        // Validate the unix_pw - this checks the account/cred lock states.
        let res = if let Some(mut slock) = maybe_valid {
            // Account is unlocked, can proceed.
            account
                .verify_unix_credential(uae.cleartext.as_str(), &self.async_tx, ct)
                .map(|res| {
                    if res.is_none() {
                        // Update it.
                        slock.record_failure(ct);
                    };
                    res
                })
        } else {
            // Account is slocked!
            security_info!("Account is softlocked.");
            Ok(None)
        };
        res
    }

    pub async fn token_auth_ldap(
        &mut self,
        lae: &LdapTokenAuthEvent,
        ct: Duration,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        match self.validate_and_parse_token_to_token(Some(&lae.token), ct)? {
            Token::UserAuthToken(uat) => {
                let spn = uat.spn.clone();
                Ok(Some(LdapBoundToken {
                    session_id: uat.session_id,
                    spn,
                    effective_session: LdapSession::UserAuthToken(uat),
                }))
            }
            Token::ApiToken(apit, entry) => {
                let spn = entry.get_ava_single_proto_string("spn").ok_or(
                    OperationError::InvalidAccountState("Missing attribute: spn".to_string()),
                )?;

                Ok(Some(LdapBoundToken {
                    session_id: apit.token_id,
                    spn,
                    effective_session: LdapSession::ApiToken(apit),
                }))
            }
        }
    }

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

            let session_id = Uuid::new_v4();
            security_info!(
                "Starting session {} for {} {}",
                session_id,
                account.spn,
                account.uuid
            );

            // Account must be anon, so we can gen the uat.
            Ok(Some(LdapBoundToken {
                session_id,
                spn: account.spn,
                effective_session: LdapSession::UnixBind(UUID_ANONYMOUS),
            }))
        } else {
            let account =
                UnixUserAccount::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)?;

            if !account.is_within_valid_time(ct) {
                security_info!("Account is not within valid time period");
                return Ok(None);
            }

            let maybe_slock_ref = match account.unix_cred_uuid_and_policy() {
                Some((cred_uuid, policy)) => {
                    let softlock_read = self.softlocks.read();
                    let slock_ref = match softlock_read.get(&cred_uuid) {
                        Some(slock_ref) => slock_ref.clone(),
                        None => {
                            let _session_ticket = self.session_ticket.acquire().await;
                            let mut softlock_write = self.softlocks.write();
                            let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                            softlock_write.insert(cred_uuid, slock.clone());
                            softlock_write.commit();
                            slock
                        }
                    };
                    Some(slock_ref)
                }
                None => None,
            };

            let maybe_slock = if let Some(s) = maybe_slock_ref.as_ref() {
                Some(s.lock().await)
            } else {
                None
            };

            let maybe_valid = if let Some(mut slock) = maybe_slock {
                // Apply the current time.
                slock.apply_time_step(ct);
                // Now check the results
                if slock.is_valid() {
                    Some(slock)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(mut slock) = maybe_valid {
                if account
                    .verify_unix_credential(lae.cleartext.as_str(), &self.async_tx, ct)?
                    .is_some()
                {
                    let session_id = Uuid::new_v4();
                    security_info!(
                        "Starting session {} for {} {}",
                        session_id,
                        account.spn,
                        account.uuid
                    );

                    Ok(Some(LdapBoundToken {
                        spn: account.spn,
                        session_id,
                        effective_session: LdapSession::UnixBind(account.uuid),
                    }))
                } else {
                    // PW failure, update softlock.
                    slock.record_failure(ct);
                    Ok(None)
                }
            } else {
                // Account is slocked!
                security_info!("Account is softlocked.");
                Ok(None)
            }
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

    fn get_uat_validator_txn(&self) -> &JwsValidator {
        &*self.uat_jwt_validator
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
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
    ) -> Result<AuthoriseResponse, Oauth2Error> {
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
            .check_oauth2_authorise_permit(ident, uat, consent_req, ct, &self.async_tx)
    }

    pub fn check_oauth2_authorise_reject(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        consent_req: &str,
        ct: Duration,
    ) -> Result<Url, OperationError> {
        self.oauth2rs
            .check_oauth2_authorise_reject(ident, uat, consent_req, ct)
    }

    pub fn check_oauth2_token_exchange(
        &self,
        client_authz: Option<&str>,
        token_req: &AccessTokenRequest,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        self.oauth2rs
            .check_oauth2_token_exchange(client_authz, token_req, ct)
    }

    pub fn check_oauth2_token_introspect(
        &self,
        client_authz: &str,
        intr_req: &AccessTokenIntrospectRequest,
        ct: Duration,
    ) -> Result<AccessTokenIntrospectResponse, Oauth2Error> {
        self.oauth2rs
            .check_oauth2_token_introspect(self, client_authz, intr_req, ct)
    }

    pub fn oauth2_openid_userinfo(
        &self,
        client_id: &str,
        client_authz: &str,
        ct: Duration,
    ) -> Result<OidcToken, Oauth2Error> {
        self.oauth2rs
            .oauth2_openid_userinfo(self, client_id, client_authz, ct)
    }

    pub fn oauth2_openid_discovery(
        &self,
        client_id: &str,
    ) -> Result<OidcDiscoveryResponse, OperationError> {
        self.oauth2rs.oauth2_openid_discovery(client_id)
    }

    pub fn oauth2_openid_publickey(&self, client_id: &str) -> Result<JwkKeySet, OperationError> {
        self.oauth2rs.oauth2_openid_publickey(client_id)
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerProxyWriteTransaction<'a> {
    type QsTransactionType = QueryServerWriteTransaction<'a>;

    fn get_qs_txn(&self) -> &Self::QsTransactionType {
        &self.qs_write
    }

    fn get_uat_validator_txn(&self) -> &JwsValidator {
        &*self.uat_jwt_validator
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn get_origin(&self) -> &Url {
        self.webauthn.get_allowed_origins().get(0).unwrap()
    }

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
            return Err(OperationError::PasswordQuality(vec![
                PasswordFeedback::TooShort(PW_MIN_LENGTH),
            ]));
        }

        // does the password pass zxcvbn?

        let entropy = zxcvbn::zxcvbn(cleartext, related_inputs).map_err(|e| {
            admin_error!("zxcvbn check failure (password empty?) {:?}", e);
            OperationError::PasswordQuality(vec![PasswordFeedback::TooShort(PW_MIN_LENGTH)])
        })?;

        // Unix PW's are a single factor, so we enforce good pws
        if entropy.score() < 4 {
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
            // return Err(OperationError::PasswordTooWeak);
            return Err(OperationError::PasswordQuality(vec![
                PasswordFeedback::BadListed,
            ]));
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        // also, when pw_badlist_cache is read from DB, it is read as Value (iutf8 lowercase)
        if (&*self.pw_badlist_cache).contains(&cleartext.to_lowercase()) {
            security_info!("Password found in badlist, rejecting");
            Err(OperationError::PasswordQuality(vec![
                PasswordFeedback::BadListed,
            ]))
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

    #[cfg(test)]
    pub(crate) fn set_account_password(
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
                &filter!(f_eq("uuid", PartialValue::new_uuid(pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(pce.target))),
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

        self.check_password_quality(pce.cleartext.as_str(), account.related_inputs().as_slice())
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
                &filter!(f_eq("uuid", PartialValue::new_uuid(pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(pce.target))),
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

        self.check_password_quality(pce.cleartext.as_str(), account.related_inputs().as_slice())
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
                &filter!(f_eq("uuid", PartialValue::new_uuid(target))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        Ok(cleartext)
    }

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
                &filter!(f_eq("uuid", PartialValue::new_uuid(gpe.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(gpe.target))),
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

    /*
    /// Generate a new set of backup code and remove the old ones.
    pub(crate) fn generate_backup_code(
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
                &filter!(f_eq("uuid", PartialValue::new_uuid(gbe.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(gbe.target))),
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

    pub(crate) fn remove_backup_code(
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
                &filter!(f_eq("uuid", PartialValue::new_uuid(account.uuid))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(account.uuid))),
                &modlist,
                &rte.ident,
            )
            .map_err(|e| {
                admin_error!("remove_backup_code {:?}", e);
                e
            })
            .map(|_| SetCredentialResponse::Success)
    }
    */

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
                &filter!(f_eq("uuid", PartialValue::new_uuid(rrse.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(rrse.target))),
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
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(pwu.target_uuid))),
                &modlist,
            )
        } else {
            // No action needed, it's probably been changed/updated already.
            Ok(())
        }
    }

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
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(pwu.target_uuid))),
                &modlist,
            )
        } else {
            Ok(())
        }
    }

    pub(crate) fn process_webauthncounterinc(
        &mut self,
        wci: &WebauthnCounterIncrement,
    ) -> Result<(), OperationError> {
        let mut account = self.target_to_account(&wci.target_uuid)?;

        // Generate an optional mod and then attempt to apply it.
        let opt_modlist = account
            .gen_webauthn_counter_mod(&wci.auth_result)
            .map_err(|e| {
                admin_error!("Unable to generate webauthn counter mod {:?}", e);
                e
            })?;

        if let Some(modlist) = opt_modlist {
            self.qs_write.internal_modify(
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(wci.target_uuid))),
                &modlist,
            )
        } else {
            // No mod needed.
            trace!("No modification required");
            Ok(())
        }
    }

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
            &filter_all!(f_eq("uuid", PartialValue::new_uuid(bcr.target_uuid))),
            &modlist,
        )
    }

    pub(crate) fn process_oauth2consentgrant(
        &mut self,
        o2cg: &Oauth2ConsentGrant,
    ) -> Result<(), OperationError> {
        let modlist = ModifyList::new_list(vec![
            Modify::Removed(
                AttrString::from("oauth2_consent_scope_map"),
                PartialValue::Refer(o2cg.oauth2_rs_uuid),
            ),
            Modify::Present(
                AttrString::from("oauth2_consent_scope_map"),
                Value::OauthScopeMap(o2cg.oauth2_rs_uuid, o2cg.scopes.iter().cloned().collect()),
            ),
        ]);

        self.qs_write.internal_modify(
            &filter_all!(f_eq("uuid", PartialValue::new_uuid(o2cg.target_uuid))),
            &modlist,
        )
    }

    pub fn process_delayedaction(&mut self, da: DelayedAction) -> Result<(), OperationError> {
        match da {
            DelayedAction::PwUpgrade(pwu) => self.process_pwupgrade(&pwu),
            DelayedAction::UnixPwUpgrade(upwu) => self.process_unixpwupgrade(&upwu),
            DelayedAction::WebauthnCounterIncrement(wci) => self.process_webauthncounterinc(&wci),
            DelayedAction::BackupCodeRemoval(bcr) => self.process_backupcoderemoval(&bcr),
            DelayedAction::Oauth2ConsentGrant(o2cg) => self.process_oauth2consentgrant(&o2cg),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn commit(mut self) -> Result<(), OperationError> {
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
                .get_domain_fernet_private_key()
                .and_then(|token_key| {
                    Fernet::new(&token_key).ok_or_else(|| {
                        admin_error!("Failed to generate token_enc_key");
                        OperationError::InvalidState
                    })
                })
                .map(|new_handle| {
                    *self.token_enc_key = new_handle;
                })?;
            self.qs_write
                .get_domain_es256_private_key()
                .and_then(|key_der| {
                    JwsSigner::from_es256_der(&key_der).map_err(|e| {
                        admin_error!("Failed to generate uat_jwt_signer - {:?}", e);
                        OperationError::InvalidState
                    })
                })
                .and_then(|signer| {
                    signer
                        .get_validator()
                        .map_err(|e| {
                            admin_error!("Failed to generate uat_jwt_validator - {:?}", e);
                            OperationError::InvalidState
                        })
                        .map(|validator| (signer, validator))
                })
                .map(|(new_signer, new_validator)| {
                    *self.uat_jwt_signer = new_signer;
                    *self.uat_jwt_validator = new_validator;
                })?;
        }
        // Commit everything.
        self.oauth2rs.commit();
        self.uat_jwt_signer.commit();
        self.uat_jwt_validator.commit();
        self.token_enc_key.commit();
        self.pw_badlist_cache.commit();
        self.cred_update_sessions.commit();
        trace!("cred_update_session.commit");
        self.qs_write.commit()
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
    use std::convert::TryFrom;
    use std::time::Duration;

    use async_std::task;
    use kanidm_proto::v1::{AuthAllowed, AuthMech, AuthType, OperationError};
    use smartstring::alias::String as AttrString;
    use uuid::Uuid;

    use crate::credential::policy::CryptoPolicy;
    use crate::credential::{Credential, Password};
    use crate::event::{AuthEvent, AuthResult, CreateEvent, ModifyEvent};
    use crate::idm::event::{
        PasswordChangeEvent, RadiusAuthTokenEvent, RegenerateRadiusSecretEvent,
        UnixGroupTokenEvent, UnixPasswordChangeEvent, UnixUserAuthEvent, UnixUserTokenEvent,
    };
    use crate::idm::server::{IdmServer, IdmServerTransaction};
    use crate::idm::AuthState;
    use crate::modify::{Modify, ModifyList};
    use crate::prelude::*;
    use crate::utils::duration_from_epoch_now;

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
        assert!(matches!(state, AuthState::Choose(_)));

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
    fn test_idm_simple_password_upgrade() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
                // Assert the delayed action queue is empty
                idms_delayed.check_is_empty_or_panic();
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
                idms_delayed.check_is_empty_or_panic();
                // Do an auth, this will trigger the action to send.
                check_admin_password(idms, "password");
                // process it.
                let da = idms_delayed.try_recv().expect("invalid");
                let r = task::block_on(idms.delayed_action(duration_from_epoch_now(), da));
                assert!(Ok(true) == r);
                // Check the admin pw still matches
                check_admin_password(idms, "password");
                // No delayed action was queued.
                idms_delayed.check_is_empty_or_panic();
            }
        )
    }

    #[test]
    fn test_idm_unix_password_upgrade() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
                // Assert the delayed action queue is empty
                idms_delayed.check_is_empty_or_panic();
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
                idms_delayed.check_is_empty_or_panic();
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
                idms_delayed.check_is_empty_or_panic();
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
                    sessionid,
                    state,
                    delay: _,
                } = ar;
                assert!(matches!(state, AuthState::Choose(_)));

                // Soft locks only apply once a mechanism is chosen
                let admin_begin = AuthEvent::begin_mech(sessionid, AuthMech::Password);

                let r2 = task::block_on(
                    idms_auth.auth(&admin_begin, Duration::from_secs(TEST_CURRENT_TIME)),
                );
                let ar = r2.unwrap();
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
    fn test_idm_jwt_uat_expiry() {
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
                    .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
                    .expect("Failed to validate");

                // In X time it should be INVALID
                match idms_prox_read.validate_and_parse_token_to_ident(Some(token.as_str()), expiry)
                {
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
                .to_userauthtoken(session_id, ct, AuthType::Passkey)
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
    fn test_idm_jwt_uat_token_key_reload() {
        run_idm_test!(
            |qs: &QueryServer, idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed| {
                let ct = Duration::from_secs(TEST_CURRENT_TIME);

                init_admin_w_password(qs, TEST_PASSWORD).expect("Failed to setup admin account");
                let token = check_admin_password(idms, TEST_PASSWORD);
                let idms_prox_read = idms.proxy_read();

                // Check it's valid.
                idms_prox_read
                    .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
                    .expect("Failed to validate");

                drop(idms_prox_read);

                // Now reset the token_key - we can cheat and push this
                // through the migrate 3 to 4 code.
                //
                // fernet_private_key_str
                // es256_private_key_der
                let idms_prox_write = idms.proxy_write(ct.clone());
                let me_reset_tokens = unsafe {
                    ModifyEvent::new_internal_invalid(
                        filter!(f_eq("uuid", PartialValue::new_uuid(*UUID_DOMAIN_INFO))),
                        ModifyList::new_list(vec![
                            Modify::Purged(AttrString::from("fernet_private_key_str")),
                            Modify::Purged(AttrString::from("es256_private_key_der")),
                            Modify::Purged(AttrString::from("domain_token_key")),
                        ]),
                    )
                };
                assert!(idms_prox_write.qs_write.modify(&me_reset_tokens).is_ok());
                assert!(idms_prox_write.commit().is_ok());
                // Check the old token is invalid, due to reload.
                let new_token = check_admin_password(idms, TEST_PASSWORD);

                let idms_prox_read = idms.proxy_read();
                assert!(idms_prox_read
                    .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
                    .is_err());
                // A new token will work due to the matching key.
                idms_prox_read
                    .validate_and_parse_token_to_ident(Some(new_token.as_str()), ct)
                    .expect("Failed to validate");
            }
        )
    }

    #[test]
    fn test_idm_service_account_to_person() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let idms_prox_write = idms.proxy_write(ct.clone());

            let ident = Identity::from_internal();
            let target_uuid = Uuid::new_v4();

            // Create a service account
            let e = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("class", Value::new_class("service_account")),
                ("name", Value::new_iname("testaccount")),
                ("uuid", Value::new_uuid(target_uuid)),
                ("description", Value::new_utf8s("testaccount")),
                ("displayname", Value::new_utf8s("Test Account"))
            );

            let ce = CreateEvent::new_internal(vec![e]);
            let cr = idms_prox_write.qs_write.create(&ce);
            assert!(cr.is_ok());

            // Do the migrate.
            assert!(idms_prox_write
                .service_account_into_person(&ident, target_uuid)
                .is_ok());

            // Any checks?
        })
    }
}

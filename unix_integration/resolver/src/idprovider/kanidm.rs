use crate::db::KeyStoreTxn;
use crate::unix_config::KanidmConfig;
use async_trait::async_trait;
use kanidm_client::{ClientError, KanidmClient, StatusCode};
use kanidm_proto::internal::OperationError;
use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex};

use kanidm_lib_crypto::CryptoPolicy;
use kanidm_lib_crypto::DbPasswordV1;
use kanidm_lib_crypto::Password;

use super::interface::{
    tpm::{self, HmacKey, Tpm},
    AuthCredHandler, AuthRequest, AuthResult, GroupToken, GroupTokenState, Id, IdProvider,
    IdpError, ProviderOrigin, UserToken, UserTokenState,
};
use kanidm_unix_common::unix_proto::PamAuthRequest;

const KANIDM_HMAC_KEY: &str = "kanidm-hmac-key";
const KANIDM_PWV1_KEY: &str = "kanidm-pw-v1";

const OFFLINE_NEXT_CHECK: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

struct KanidmProviderInternal {
    state: CacheState,
    client: KanidmClient,
    hmac_key: HmacKey,
    crypto_policy: CryptoPolicy,
    pam_allow_groups: BTreeSet<String>,
}

pub struct KanidmProvider {
    inner: Mutex<KanidmProviderInternal>,
}

impl KanidmProvider {
    pub fn new(
        client: KanidmClient,
        config: &KanidmConfig,
        now: SystemTime,
        keystore: &mut KeyStoreTxn,
        tpm: &mut tpm::BoxedDynTpm,
        machine_key: &tpm::MachineKey,
    ) -> Result<Self, IdpError> {
        // FUTURE: Randomised jitter on next check at startup.

        // Initially retrieve our HMAC key.
        let loadable_hmac_key: Option<tpm::LoadableHmacKey> = keystore
            .get_tagged_hsm_key(KANIDM_HMAC_KEY)
            .map_err(|ks_err| {
                error!(?ks_err);
                IdpError::KeyStore
            })?;

        let loadable_hmac_key = if let Some(loadable_hmac_key) = loadable_hmac_key {
            loadable_hmac_key
        } else {
            let loadable_hmac_key = tpm.hmac_key_create(machine_key).map_err(|tpm_err| {
                error!(?tpm_err);
                IdpError::Tpm
            })?;

            keystore
                .insert_tagged_hsm_key(KANIDM_HMAC_KEY, &loadable_hmac_key)
                .map_err(|ks_err| {
                    error!(?ks_err);
                    IdpError::KeyStore
                })?;

            loadable_hmac_key
        };

        let hmac_key = tpm
            .hmac_key_load(machine_key, &loadable_hmac_key)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                IdpError::Tpm
            })?;

        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(250));

        let pam_allow_groups = config.pam_allowed_login_groups.iter().cloned().collect();

        Ok(KanidmProvider {
            inner: Mutex::new(KanidmProviderInternal {
                state: CacheState::OfflineNextCheck(now),
                client,
                hmac_key,
                crypto_policy,
                pam_allow_groups,
            }),
        })
    }
}

impl From<UnixUserToken> for UserToken {
    fn from(value: UnixUserToken) -> UserToken {
        let UnixUserToken {
            name,
            spn,
            displayname,
            gidnumber,
            uuid,
            shell,
            groups,
            sshkeys,
            valid,
        } = value;

        let groups = groups.into_iter().map(GroupToken::from).collect();

        UserToken {
            provider: ProviderOrigin::Kanidm,
            name,
            spn,
            uuid,
            gidnumber,
            displayname,
            shell,
            groups,
            sshkeys,
            valid,
            extra_keys: Default::default(),
        }
    }
}

impl From<UnixGroupToken> for GroupToken {
    fn from(value: UnixGroupToken) -> GroupToken {
        let UnixGroupToken {
            name,
            spn,
            uuid,
            gidnumber,
        } = value;

        GroupToken {
            provider: ProviderOrigin::Kanidm,
            name,
            spn,
            uuid,
            gidnumber,
            extra_keys: Default::default(),
        }
    }
}

impl UserToken {
    pub fn kanidm_update_cached_password(
        &mut self,
        crypto_policy: &CryptoPolicy,
        cred: &str,
        tpm: &mut tpm::BoxedDynTpm,
        hmac_key: &HmacKey,
    ) {
        let pw = match Password::new_argon2id_hsm(crypto_policy, cred, tpm, hmac_key) {
            Ok(pw) => pw,
            Err(reason) => {
                // Clear cached pw.
                self.extra_keys.remove(KANIDM_PWV1_KEY);
                warn!(
                    ?reason,
                    "unable to apply kdf to password, clearing cached password."
                );
                return;
            }
        };

        let pw_value = match serde_json::to_value(pw.to_dbpasswordv1()) {
            Ok(pw) => pw,
            Err(reason) => {
                // Clear cached pw.
                self.extra_keys.remove(KANIDM_PWV1_KEY);
                warn!(
                    ?reason,
                    "unable to serialise credential, clearing cached password."
                );
                return;
            }
        };

        self.extra_keys.insert(KANIDM_PWV1_KEY.into(), pw_value);
        debug!(spn = %self.spn, "Updated cached pw");
    }

    pub fn kanidm_check_cached_password(
        &self,
        cred: &str,
        tpm: &mut tpm::BoxedDynTpm,
        hmac_key: &HmacKey,
    ) -> bool {
        let pw_value = match self.extra_keys.get(KANIDM_PWV1_KEY) {
            Some(pw_value) => pw_value,
            None => {
                debug!(spn = %self.spn, "no cached pw available");
                return false;
            }
        };

        let dbpw = match serde_json::from_value::<DbPasswordV1>(pw_value.clone()) {
            Ok(dbpw) => dbpw,
            Err(reason) => {
                warn!(spn = %self.spn, ?reason, "unable to deserialise credential");
                return false;
            }
        };

        let pw = match Password::try_from(dbpw) {
            Ok(pw) => pw,
            Err(reason) => {
                warn!(spn = %self.spn, ?reason, "unable to process credential");
                return false;
            }
        };

        pw.verify_ctx(cred, Some((tpm, hmac_key)))
            .unwrap_or_default()
    }
}

impl KanidmProviderInternal {
    async fn check_online(&mut self, tpm: &mut tpm::BoxedDynTpm, now: SystemTime) -> bool {
        match self.state {
            // Proceed
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at_time) if now >= at_time => {
                // Attempt online. If fails, return token.
                self.attempt_online(tpm, now).await
            }
            CacheState::OfflineNextCheck(_) | CacheState::Offline => false,
        }
    }

    async fn attempt_online(&mut self, _tpm: &mut tpm::BoxedDynTpm, now: SystemTime) -> bool {
        match self.client.auth_anonymous().await {
            Ok(_uat) => {
                self.state = CacheState::Online;
                true
            }
            Err(ClientError::Transport(err)) => {
                warn!(?err, "transport failure");
                self.state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                false
            }
            Err(err) => {
                error!(?err, "Provider authentication failed");
                self.state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                false
            }
        }
    }
}

#[async_trait]
impl IdProvider for KanidmProvider {
    fn origin(&self) -> ProviderOrigin {
        ProviderOrigin::Kanidm
    }

    async fn attempt_online(&self, tpm: &mut tpm::BoxedDynTpm, now: SystemTime) -> bool {
        let mut inner = self.inner.lock().await;
        inner.check_online(tpm, now).await
    }

    async fn mark_next_check(&self, now: SystemTime) {
        let mut inner = self.inner.lock().await;
        inner.state = CacheState::OfflineNextCheck(now);
    }

    async fn mark_offline(&self) {
        let mut inner = self.inner.lock().await;
        inner.state = CacheState::Offline;
    }

    async fn unix_user_get(
        &self,
        id: &Id,
        token: Option<&UserToken>,
        tpm: &mut tpm::BoxedDynTpm,
        now: SystemTime,
    ) -> Result<UserTokenState, IdpError> {
        let mut inner = self.inner.lock().await;

        if !inner.check_online(tpm, now).await {
            // We are offline, return that we should use a cached token.
            return Ok(UserTokenState::UseCached);
        }

        // We are ONLINE, do the get.
        match inner
            .client
            .idm_account_unix_token_get(id.to_string().as_str())
            .await
        {
            Ok(tok) => {
                let mut ut = UserToken::from(tok);

                if let Some(previous_token) = token {
                    ut.extra_keys = previous_token.extra_keys.clone();
                }

                Ok(UserTokenState::Update(ut))
            }
            // Offline?
            Err(ClientError::Transport(err)) => {
                error!(?err, "transport error");
                inner.state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                Ok(UserTokenState::UseCached)
            }
            // Provider session error, need to re-auth
            Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                match reason {
                    Some(OperationError::NotAuthenticated) => warn!(
                        "session not authenticated - attempting reauthentication - eventid {}",
                        opid
                    ),
                    Some(OperationError::SessionExpired) => warn!(
                        "session expired - attempting reauthentication - eventid {}",
                        opid
                    ),
                    e => error!(
                        "authentication error {:?}, moving to offline - eventid {}",
                        e, opid
                    ),
                };
                inner.state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                Ok(UserTokenState::UseCached)
            }
            // 404 / Removed.
            Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::MissingAttribute(_)),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::MissingClass(_)),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::InvalidAccountState(_)),
                opid,
            )) => {
                debug!(
                    ?opid,
                    "entry has been removed or is no longer a valid posix account"
                );
                Ok(UserTokenState::NotFound)
            }
            // Something is really wrong? We did get a response though, so we are still online.
            Err(err) => {
                error!(?err, "client error");
                Err(IdpError::BadRequest)
            }
        }
    }

    async fn unix_user_online_auth_init(
        &self,
        _account_id: &str,
        _token: &UserToken,
        _tpm: &mut tpm::BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        // Not sure that I need to do much here?
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    async fn unix_unknown_user_online_auth_init(
        &self,
        _account_id: &str,
        _tpm: &mut tpm::BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<Option<(AuthRequest, AuthCredHandler)>, IdpError> {
        // We do not support unknown user auth.
        Ok(None)
    }

    async fn unix_user_online_auth_step(
        &self,
        account_id: &str,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        tpm: &mut tpm::BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<AuthResult, IdpError> {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                let inner = self.inner.lock().await;

                let auth_result = inner
                    .client
                    .idm_account_unix_cred_verify(account_id, &cred)
                    .await;

                trace!(?auth_result);

                match auth_result {
                    Ok(Some(n_tok)) => {
                        let mut token = UserToken::from(n_tok);
                        token.kanidm_update_cached_password(
                            &inner.crypto_policy,
                            cred.as_str(),
                            tpm,
                            &inner.hmac_key,
                        );

                        Ok(AuthResult::Success { token })
                    }
                    Ok(None) => {
                        // TODO: i'm not a huge fan of this rn, but currently the way we handle
                        // an expired account is we return Ok(None).
                        //
                        // We can't tell the difference between expired and incorrect password.
                        // So in these cases we have to clear the cached password. :(
                        //
                        // In future once we have domain join, we should be getting the user token
                        // at the start of the auth and checking for account validity instead.
                        Ok(AuthResult::Denied)
                    }
                    Err(ClientError::Transport(err)) => {
                        error!(?err);
                        Err(IdpError::Transport)
                    }
                    Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                        match reason {
                            Some(OperationError::NotAuthenticated) => warn!(
                                "session not authenticated - attempting reauthentication - eventid {}",
                                opid
                            ),
                            Some(OperationError::SessionExpired) => warn!(
                                "session expired - attempting reauthentication - eventid {}",
                                opid
                            ),
                            e => error!(
                                "authentication error {:?}, moving to offline - eventid {}",
                                e, opid
                            ),
                        };
                        Err(IdpError::ProviderUnauthorised)
                    }
                    Err(ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    ))
                    | Err(ClientError::Http(
                        StatusCode::NOT_FOUND,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    ))
                    | Err(ClientError::Http(
                        StatusCode::NOT_FOUND,
                        Some(OperationError::MissingAttribute(_)),
                        opid,
                    ))
                    | Err(ClientError::Http(
                        StatusCode::NOT_FOUND,
                        Some(OperationError::MissingClass(_)),
                        opid,
                    ))
                    | Err(ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::InvalidAccountState(_)),
                        opid,
                    )) => {
                        error!(
                            "unknown account or is not a valid posix account - eventid {}",
                            opid
                        );
                        Err(IdpError::NotFound)
                    }
                    Err(err) => {
                        error!(?err, "client error");
                        // Some other unknown processing error?
                        Err(IdpError::BadRequest)
                    }
                }
            }
            (
                AuthCredHandler::DeviceAuthorizationGrant,
                PamAuthRequest::DeviceAuthorizationGrant { .. },
            ) => {
                error!("DeviceAuthorizationGrant not implemented!");
                Err(IdpError::BadRequest)
            }
            _ => {
                error!("invalid authentication request state");
                Err(IdpError::BadRequest)
            }
        }
    }

    async fn unix_user_offline_auth_init(
        &self,
        _token: &UserToken,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    async fn unix_user_offline_auth_step(
        &self,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        tpm: &mut tpm::BoxedDynTpm,
    ) -> Result<AuthResult, IdpError> {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                let inner = self.inner.lock().await;

                if token.kanidm_check_cached_password(cred.as_str(), tpm, &inner.hmac_key) {
                    // TODO: We can update the token here and then do lockouts.
                    Ok(AuthResult::Success {
                        token: token.clone(),
                    })
                } else {
                    Ok(AuthResult::Denied)
                }
            }
            (
                AuthCredHandler::DeviceAuthorizationGrant,
                PamAuthRequest::DeviceAuthorizationGrant { .. },
            ) => {
                error!("DeviceAuthorizationGrant not implemented!");
                Err(IdpError::BadRequest)
            }
            _ => {
                error!("invalid authentication request state");
                Err(IdpError::BadRequest)
            }
        }
    }

    async fn unix_group_get(
        &self,
        id: &Id,
        tpm: &mut tpm::BoxedDynTpm,
        now: SystemTime,
    ) -> Result<GroupTokenState, IdpError> {
        let mut inner = self.inner.lock().await;

        if !inner.check_online(tpm, now).await {
            // We are offline, return that we should use a cached token.
            return Ok(GroupTokenState::UseCached);
        }

        match inner
            .client
            .idm_group_unix_token_get(id.to_string().as_str())
            .await
        {
            Ok(tok) => {
                let gt = GroupToken::from(tok);
                Ok(GroupTokenState::Update(gt))
            }
            // Offline?
            Err(ClientError::Transport(err)) => {
                error!(?err, "transport error");
                inner.state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                Ok(GroupTokenState::UseCached)
            }
            // Provider session error, need to re-auth
            Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                match reason {
                    Some(OperationError::NotAuthenticated) => warn!(
                        "session not authenticated - attempting reauthentication - eventid {}",
                        opid
                    ),
                    Some(OperationError::SessionExpired) => warn!(
                        "session expired - attempting reauthentication - eventid {}",
                        opid
                    ),
                    e => error!(
                        "authentication error {:?}, moving to offline - eventid {}",
                        e, opid
                    ),
                };
                inner.state = CacheState::OfflineNextCheck(now + OFFLINE_NEXT_CHECK);
                Ok(GroupTokenState::UseCached)
            }
            // 404 / Removed.
            Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::NoMatchingEntries),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::MissingAttribute(_)),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::NOT_FOUND,
                Some(OperationError::MissingClass(_)),
                opid,
            ))
            | Err(ClientError::Http(
                StatusCode::BAD_REQUEST,
                Some(OperationError::InvalidAccountState(_)),
                opid,
            )) => {
                debug!(
                    ?opid,
                    "entry has been removed or is no longer a valid posix account"
                );
                Ok(GroupTokenState::NotFound)
            }
            // Something is really wrong? We did get a response though, so we are still online.
            Err(err) => {
                error!(?err, "client error");
                Err(IdpError::BadRequest)
            }
        }
    }

    async fn unix_user_authorise(&self, token: &UserToken) -> Result<Option<bool>, IdpError> {
        let inner = self.inner.lock().await;

        if inner.pam_allow_groups.is_empty() {
            // can't allow anything if the group list is zero...
            warn!("Cannot authenticate users, no allowed groups in configuration!");
            Ok(Some(false))
        } else {
            let user_set: BTreeSet<_> = token
                .groups
                .iter()
                .flat_map(|g| [g.name.clone(), g.uuid.hyphenated().to_string()])
                .collect();

            debug!(
                "Checking if user is in allowed groups ({:?}) -> {:?}",
                inner.pam_allow_groups, user_set,
            );
            let intersection_count = user_set.intersection(&inner.pam_allow_groups).count();
            debug!("Number of intersecting groups: {}", intersection_count);
            debug!("User token is valid: {}", token.valid);

            Ok(Some(intersection_count > 0 && token.valid))
        }
    }
}

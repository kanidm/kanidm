use super::interface::{
    tpm::{
        provider::{BoxedDynTpm, TpmHmacS256},
        structures::{HmacS256Key, LoadableHmacS256Key, StorageKey},
    },
    AuthCredHandler, AuthRequest, AuthResult, GroupToken, GroupTokenState, Id, IdProvider,
    IdpError, ProviderOrigin, UserToken, UserTokenState,
};
use crate::db::KeyStoreTxn;
use async_trait::async_trait;
use hashbrown::HashMap;
use kanidm_client::{ClientError, KanidmClient, StatusCode};
use kanidm_lib_crypto::CryptoPolicy;
use kanidm_lib_crypto::DbPasswordV1;
use kanidm_lib_crypto::Password;
use kanidm_proto::internal::OperationError;
use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};
use kanidm_unix_common::constants::{
    DEFAULT_CACHE_TIMEOUT_JITTER_MS, DEFAULT_OFFLINE_PROVIDER_CHECK_TIME,
};
use kanidm_unix_common::unix_config::{GroupMap, KanidmConfig};
use kanidm_unix_common::unix_proto::PamAuthRequest;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex};

const KANIDM_HMAC_KEY: &str = "kanidm-hmac-key-v2";
const KANIDM_PWV1_KEY: &str = "kanidm-pw-v1";

fn next_offline_check(now: SystemTime) -> SystemTime {
    let jitter = rand::random_range(0..DEFAULT_CACHE_TIMEOUT_JITTER_MS);
    now + (Duration::from_secs(DEFAULT_OFFLINE_PROVIDER_CHECK_TIME) - Duration::from_millis(jitter))
}

#[derive(Debug, Clone)]
enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

struct KanidmProviderInternal {
    state: CacheState,
    client: KanidmClient,
    hmac_key: HmacS256Key,
    crypto_policy: CryptoPolicy,
    pam_allow_groups: BTreeSet<String>,
    bearer_token_set: bool,
}

pub struct KanidmProvider {
    inner: Mutex<KanidmProviderInternal>,
    // Because this value doesn't change, to support fast
    // lookup we store the extension map here.
    map_group: HashMap<String, Id>,
}

impl KanidmProvider {
    pub async fn new<'a, 'b>(
        client: KanidmClient,
        config: &KanidmConfig,
        now: SystemTime,
        keystore: &mut KeyStoreTxn<'a, 'b>,
        tpm: &mut BoxedDynTpm,
        machine_key: &StorageKey,
    ) -> Result<Self, IdpError> {
        let tpm_ctx: &mut dyn TpmHmacS256 = &mut **tpm;

        // Initially retrieve our HMAC key.
        let loadable_hmac_key: Option<LoadableHmacS256Key> = keystore
            .get_tagged_hsm_key(KANIDM_HMAC_KEY)
            .map_err(|ks_err| {
                error!(?ks_err);
                IdpError::KeyStore
            })?;

        let loadable_hmac_key = if let Some(loadable_hmac_key) = loadable_hmac_key {
            loadable_hmac_key
        } else {
            let loadable_hmac_key = tpm_ctx.hmac_s256_create(machine_key).map_err(|tpm_err| {
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

        let hmac_key = tpm_ctx
            .hmac_s256_load(machine_key, &loadable_hmac_key)
            .map_err(|tpm_err| {
                error!(?tpm_err);
                IdpError::Tpm
            })?;

        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(250));

        let pam_allow_groups = config.pam_allowed_login_groups.iter().cloned().collect();

        let map_group = config
            .map_group
            .iter()
            .cloned()
            .map(|GroupMap { local, with }| (local, Id::Name(with)))
            .collect();

        // Set the api token if one is set
        if let Some(token) = config.service_account_token.clone() {
            client.set_token(token).await;
        };
        let bearer_token_set = config.service_account_token.is_some();

        Ok(KanidmProvider {
            inner: Mutex::new(KanidmProviderInternal {
                state: CacheState::OfflineNextCheck(now),
                client,
                hmac_key,
                crypto_policy,
                pam_allow_groups,
                bearer_token_set,
            }),
            map_group,
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

        let sshkeys = sshkeys.iter().map(|s| s.to_string()).collect();

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
        tpm: &mut BoxedDynTpm,
        hmac_key: &HmacS256Key,
    ) {
        let tpm_ctx: &mut dyn TpmHmacS256 = &mut **tpm;

        let pw = match Password::new_argon2id_hsm(crypto_policy, cred, tpm_ctx, hmac_key) {
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

    pub fn kanidm_has_offline_credentials(&self) -> bool {
        self.extra_keys.contains_key(KANIDM_PWV1_KEY)
    }

    pub fn kanidm_check_cached_password(
        &self,
        cred: &str,
        tpm: &mut BoxedDynTpm,
        hmac_key: &HmacS256Key,
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

        let tpm_ctx: &mut dyn TpmHmacS256 = &mut **tpm;

        pw.verify_ctx(cred, Some((tpm_ctx, hmac_key)))
            .unwrap_or_default()
    }
}

impl KanidmProviderInternal {
    #[instrument(level = "debug", skip_all)]
    async fn check_online(&mut self, tpm: &mut BoxedDynTpm, now: SystemTime) -> bool {
        match self.state {
            // Proceed
            CacheState::Online => true,
            CacheState::OfflineNextCheck(at_time) if now >= at_time => {
                self.attempt_online(tpm, now).await
            }
            CacheState::OfflineNextCheck(_) | CacheState::Offline => false,
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn check_online_right_meow(&mut self, tpm: &mut BoxedDynTpm, now: SystemTime) -> bool {
        match self.state {
            CacheState::Online => true,
            CacheState::OfflineNextCheck(_) => self.attempt_online(tpm, now).await,
            CacheState::Offline => false,
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn is_online(&mut self) -> bool {
        matches!(self.state, CacheState::Online)
    }

    #[instrument(level = "debug", skip_all)]
    async fn attempt_online(&mut self, _tpm: &mut BoxedDynTpm, now: SystemTime) -> bool {
        let mut max_attempts = 3;
        while max_attempts > 0 {
            max_attempts -= 1;

            // If a bearer token is set, we don't want to do an auth flow and
            // remove that. Just do a whoami call, which will tell us the result.
            let check_online_result = if self.bearer_token_set {
                self.client.whoami().await.map(|_| ())
            } else {
                self.client.auth_anonymous().await
            };

            match check_online_result {
                Ok(_uat) => {
                    debug!("provider is now online");
                    self.state = CacheState::Online;
                    return true;
                }
                Err(ClientError::Http(StatusCode::UNAUTHORIZED, reason, opid)) => {
                    error!(?reason, ?opid, "Provider authentication returned unauthorized, {max_attempts} attempts remaining.");
                    // Provider needs to re-auth ASAP. We set this state value here
                    // so that if we exceed max attempts, the next caller knows to check
                    // online immediately.
                    self.state = CacheState::OfflineNextCheck(now);
                    // attempt again immediately!!!!
                    continue;
                }
                Err(err) => {
                    error!(?err, "Provider online failed");
                    self.state = CacheState::OfflineNextCheck(next_offline_check(now));
                    return false;
                }
            }
        }
        warn!("Exceeded maximum number of attempts to bring provider online");
        return false;
    }
}

#[async_trait]
impl IdProvider for KanidmProvider {
    fn origin(&self) -> ProviderOrigin {
        ProviderOrigin::Kanidm
    }

    async fn attempt_online(&self, tpm: &mut BoxedDynTpm, now: SystemTime) -> bool {
        let mut inner = self.inner.lock().await;
        inner.check_online_right_meow(tpm, now).await
    }

    async fn is_online(&self) -> bool {
        let mut inner = self.inner.lock().await;
        inner.is_online().await
    }

    async fn mark_next_check(&self, now: SystemTime) {
        let mut inner = self.inner.lock().await;
        inner.state = CacheState::OfflineNextCheck(now);
    }

    fn has_map_group(&self, local: &str) -> Option<&Id> {
        self.map_group.get(local)
    }

    async fn mark_offline(&self) {
        let mut inner = self.inner.lock().await;
        inner.state = CacheState::Offline;
    }

    #[instrument(level = "debug", skip_all, fields(id = ?id))]
    async fn unix_user_get(
        &self,
        id: &Id,
        token: Option<&UserToken>,
        tpm: &mut BoxedDynTpm,
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
                inner.state = CacheState::OfflineNextCheck(next_offline_check(now));
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
                // Provider needs to re-auth ASAP
                inner.state = CacheState::OfflineNextCheck(now);
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

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_online_auth_init(
        &self,
        _account_id: &str,
        _token: &UserToken,
        _tpm: &mut BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        // Not sure that I need to do much here?
        Ok((AuthRequest::Password, AuthCredHandler::Password))
    }

    async fn unix_unknown_user_online_auth_init(
        &self,
        _account_id: &str,
        _tpm: &mut BoxedDynTpm,
        _shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<Option<(AuthRequest, AuthCredHandler)>, IdpError> {
        // We do not support unknown user auth.
        Ok(None)
    }

    #[instrument(level = "debug", skip_all)]
    async fn unix_user_online_auth_step(
        &self,
        account_id: &str,
        current_token: Option<&UserToken>,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        tpm: &mut BoxedDynTpm,
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
                        let mut new_token = UserToken::from(n_tok);

                        // Update any keys that may have been in the db in the current
                        // token.
                        if let Some(previous_token) = current_token {
                            new_token.extra_keys = previous_token.extra_keys.clone();
                        }

                        // Set any new keys that are relevant from this authentication
                        new_token.kanidm_update_cached_password(
                            &inner.crypto_policy,
                            cred.as_str(),
                            tpm,
                            &inner.hmac_key,
                        );

                        Ok(AuthResult::SuccessUpdate { new_token })
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
                        error!(?err, "A client transport error occurred.");
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

    async fn unix_user_can_offline_auth(&self, token: &UserToken) -> bool {
        token.kanidm_has_offline_credentials()
    }

    async fn unix_user_offline_auth_init(
        &self,
        token: &UserToken,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        if token.kanidm_has_offline_credentials() {
            Ok((AuthRequest::Password, AuthCredHandler::Password))
        } else {
            Err(IdpError::NoOfflineCredentials)
        }
    }

    async fn unix_user_offline_auth_step(
        &self,
        current_token: Option<&UserToken>,
        session_token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        tpm: &mut BoxedDynTpm,
    ) -> Result<AuthResult, IdpError> {
        match (cred_handler, pam_next_req) {
            (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                let inner = self.inner.lock().await;

                if session_token.kanidm_check_cached_password(cred.as_str(), tpm, &inner.hmac_key) {
                    // Ensure we have either the latest token, or if none, at least the session token.
                    let new_token = current_token.unwrap_or(session_token).clone();

                    // TODO: We can update the token here and then do lockouts.

                    Ok(AuthResult::SuccessUpdate { new_token })
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

    #[instrument(level = "debug", skip_all)]
    async fn unix_group_get(
        &self,
        id: &Id,
        tpm: &mut BoxedDynTpm,
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
                inner.state = CacheState::OfflineNextCheck(next_offline_check(now));
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
                inner.state = CacheState::OfflineNextCheck(next_offline_check(now));
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
            warn!("NO USERS CAN LOGIN TO THIS SYSTEM! There are no `pam_allowed_login_groups` in configuration!");
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

            if intersection_count == 0 && token.valid {
                warn!("The user {} authenticated successfully but is NOT a member of a group defined in `pam_allowed_login_groups`. They have been denied access to this system.", token.spn);
            }

            Ok(Some(intersection_count > 0 && token.valid))
        }
    }
}

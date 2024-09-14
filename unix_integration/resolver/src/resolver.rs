// use async_trait::async_trait;
use hashbrown::HashMap;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::string::ToString;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lru::LruCache;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::{Cache, Db};
use crate::idprovider::interface::{
    AuthCredHandler,
    AuthResult,
    GroupToken,
    GroupTokenState,
    Id,
    IdProvider,
    IdpError,
    ProviderOrigin,
    // KeyStore,
    UserToken,
    UserTokenState,
};
use crate::idprovider::system::SystemProvider;
use crate::unix_config::{HomeAttr, UidAttr};
use kanidm_unix_common::unix_passwd::{EtcGroup, EtcShadow, EtcUser};
use kanidm_unix_common::unix_proto::{
    HomeDirectoryInfo, NssGroup, NssUser, PamAuthRequest, PamAuthResponse, ProviderStatus,
};

use kanidm_hsm_crypto::BoxedDynTpm;

use tokio::sync::broadcast;

const NXCACHE_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(128) };

pub enum AuthSession {
    Online {
        client: Arc<dyn IdProvider + Sync + Send>,
        account_id: String,
        id: Id,
        token: Option<Box<UserToken>>,
        cred_handler: AuthCredHandler,
        /// Some authentication operations may need to spawn background tasks. These tasks need
        /// to know when to stop as the caller has disconnected. This reciever allows that, so
        /// that tasks which .resubscribe() to this channel can then select! on it and be notified
        /// when they need to stop.
        shutdown_rx: broadcast::Receiver<()>,
    },
    Offline {
        client: Arc<dyn IdProvider + Sync + Send>,
        token: Box<UserToken>,
        cred_handler: AuthCredHandler,
    },
    Success,
    Denied,
}

pub struct Resolver {
    // Generic / modular types.
    db: Db,
    hsm: Mutex<BoxedDynTpm>,

    // A local passwd/shadow resolver.
    system_provider: Arc<SystemProvider>,

    // client: Box<dyn IdProvider + Sync + Send>,
    client_ids: HashMap<ProviderOrigin, Arc<dyn IdProvider + Sync + Send>>,

    // A set of remote resolvers, ordered by priority.
    clients: Vec<Arc<dyn IdProvider + Sync + Send>>,

    // The id of the primary-provider which may use name over spn.
    primary_origin: ProviderOrigin,

    pam_allow_groups: BTreeSet<String>,
    timeout_seconds: u64,
    default_shell: String,
    home_prefix: PathBuf,
    home_attr: HomeAttr,
    home_alias: Option<HomeAttr>,
    uid_attr_map: UidAttr,
    gid_attr_map: UidAttr,
    nxcache: Mutex<LruCache<Id, SystemTime>>,
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            Id::Name(s) => s.to_string(),
            Id::Gid(g) => g.to_string(),
        })
    }
}

impl Resolver {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        db: Db,
        system_provider: Arc<SystemProvider>,
        client: Arc<dyn IdProvider + Sync + Send>,
        hsm: BoxedDynTpm,
        timeout_seconds: u64,
        pam_allow_groups: Vec<String>,
        default_shell: String,
        home_prefix: PathBuf,
        home_attr: HomeAttr,
        home_alias: Option<HomeAttr>,
        uid_attr_map: UidAttr,
        gid_attr_map: UidAttr,
    ) -> Result<Self, ()> {
        let hsm = Mutex::new(hsm);

        if pam_allow_groups.is_empty() {
            warn!("Will not be able to authorise user logins, pam_allow_groups config is not configured.");
        }

        let clients: Vec<Arc<dyn IdProvider + Sync + Send>> = vec![client];

        let primary_origin = clients.first().map(|c| c.origin()).unwrap_or_default();

        let client_ids: HashMap<_, _> = clients
            .iter()
            .map(|provider| (provider.origin(), provider.clone()))
            .collect();

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(Resolver {
            db,
            hsm,
            system_provider,
            clients,
            primary_origin,
            client_ids,
            timeout_seconds,
            pam_allow_groups: pam_allow_groups.into_iter().collect(),
            default_shell,
            home_prefix,
            home_attr,
            home_alias,
            uid_attr_map,
            gid_attr_map,
            nxcache: Mutex::new(LruCache::new(NXCACHE_SIZE)),
            // system_identities,
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn mark_next_check_now(&self, now: SystemTime) {
        for c in self.clients.iter() {
            c.mark_next_check(now).await;
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn mark_offline(&self) {
        for c in self.clients.iter() {
            c.mark_offline().await;
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn clear_cache(&self) -> Result<(), ()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        let mut dbtxn = self.db.write().await;
        dbtxn.clear().and_then(|_| dbtxn.commit()).map_err(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn invalidate(&self) -> Result<(), ()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        let mut dbtxn = self.db.write().await;
        dbtxn
            .invalidate()
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn get_cached_usertokens(&self) -> Result<Vec<UserToken>, ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_accounts().map_err(|_| ())
    }

    async fn get_cached_grouptokens(&self) -> Result<Vec<GroupToken>, ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn.get_groups().map_err(|_| ())
    }

    async fn set_nxcache(&self, id: &Id) {
        let mut nxcache_txn = self.nxcache.lock().await;
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        nxcache_txn.put(id.clone(), ex_time);
    }

    pub async fn check_nxcache(&self, id: &Id) -> Option<SystemTime> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.get(id).copied()
    }

    pub async fn reload_system_identities(
        &self,
        users: Vec<EtcUser>,
        shadow: Option<Vec<EtcShadow>>,
        groups: Vec<EtcGroup>,
    ) {
        self.system_provider.reload(users, shadow, groups).await
    }

    async fn get_cached_usertoken(&self, account_id: &Id) -> Result<(bool, Option<UserToken>), ()> {
        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let mut dbtxn = self.db.write().await;
        let r = dbtxn.get_account(account_id).map_err(|err| {
            debug!("get_cached_usertoken {:?}", err);
        })?;

        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let offset = Duration::from_secs(ex);
                let ex_time = SystemTime::UNIX_EPOCH + offset;
                let now = SystemTime::now();

                if now >= ex_time {
                    Ok((true, Some(ut)))
                } else {
                    Ok((false, Some(ut)))
                }
            }
            None => {
                // it wasn't in the DB - lets see if it's in the nxcache.
                match self.check_nxcache(account_id).await {
                    Some(ex_time) => {
                        let now = SystemTime::now();
                        if now >= ex_time {
                            // It's in the LRU, but we are past the expiry so
                            // lets attempt a refresh.
                            Ok((true, None))
                        } else {
                            // It's in the LRU and still valid, so return that
                            // no check is needed.
                            Ok((false, None))
                        }
                    }
                    None => {
                        // Not in the LRU. Return that this IS expired
                        // and we have no data.
                        Ok((true, None))
                    }
                }
            }
        } // end match r
    }

    async fn get_cached_grouptoken(&self, grp_id: &Id) -> Result<(bool, Option<GroupToken>), ()> {
        // grp_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let mut dbtxn = self.db.write().await;
        let r = dbtxn.get_group(grp_id).map_err(|_| ())?;

        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let offset = Duration::from_secs(ex);
                let ex_time = SystemTime::UNIX_EPOCH + offset;
                let now = SystemTime::now();

                if now >= ex_time {
                    Ok((true, Some(ut)))
                } else {
                    Ok((false, Some(ut)))
                }
            }
            None => {
                // it wasn't in the DB - lets see if it's in the nxcache.
                match self.check_nxcache(grp_id).await {
                    Some(ex_time) => {
                        let now = SystemTime::now();
                        if now >= ex_time {
                            // It's in the LRU, but we are past the expiry so
                            // lets attempt a refresh.
                            Ok((true, None))
                        } else {
                            // It's in the LRU and still valid, so return that
                            // no check is needed.
                            Ok((false, None))
                        }
                    }
                    None => {
                        // Not in the LRU. Return that this IS expired
                        // and we have no data.
                        Ok((true, None))
                    }
                }
            }
        }
    }

    async fn set_cache_usertoken(&self, token: &mut UserToken) -> Result<(), ()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
            })?;

        // Check if requested `shell` exists on the system, else use `default_shell`
        let requested_shell_exists: bool = token
            .shell
            .as_ref()
            .map(|shell| {
                let exists = Path::new(shell).exists();
                if !exists {
                    info!(
                        "User shell is not present on this system - {}. Check `/etc/shells` for valid shell options.",
                        shell
                    )
                }
                exists
            })
            .unwrap_or_else(|| {
                info!("User has not specified a shell, using default");
                false
            });

        if !requested_shell_exists {
            token.shell = Some(self.default_shell.clone())
        }

        let mut dbtxn = self.db.write().await;
        token
            .groups
            .iter()
            // We need to add the groups first
            .try_for_each(|g| dbtxn.update_group(g, offset.as_secs()))
            .and_then(|_|
                // So that when we add the account it can make the relationships.
                dbtxn
                    .update_account(token, offset.as_secs()))
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn set_cache_grouptoken(&self, token: &GroupToken) -> Result<(), ()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
            })?;

        let mut dbtxn = self.db.write().await;
        dbtxn
            .update_group(token, offset.as_secs())
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn delete_cache_usertoken(&self, a_uuid: Uuid) -> Result<(), ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn
            .delete_account(a_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn delete_cache_grouptoken(&self, g_uuid: Uuid) -> Result<(), ()> {
        let mut dbtxn = self.db.write().await;
        dbtxn
            .delete_group(g_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn refresh_usertoken(
        &self,
        account_id: &Id,
        token: Option<UserToken>,
    ) -> Result<Option<UserToken>, ()> {
        // TODO: Move this to the caller.
        let now = SystemTime::now();

        let mut hsm_lock = self.hsm.lock().await;

        let user_get_result = if let Some(tok) = token.as_ref() {
            // Re-use the provider that the token is from.
            match self.client_ids.get(&tok.provider) {
                Some(client) => {
                    client
                        .unix_user_get(account_id, token.as_ref(), hsm_lock.deref_mut(), now)
                        .await
                }
                None => {
                    error!(provider = ?tok.provider, "Token was resolved by a provider that no longer appears to be present.");
                    // We don't know if this is permanent or transient, so just useCached, unless
                    // the admin clears tokens from providers that are no longer present.
                    Ok(UserTokenState::UseCached)
                }
            }
        } else {
            // We've never seen it before, so iterate over the providers in priority order.
            'search: {
                for client in self.clients.iter() {
                    match client
                        .unix_user_get(account_id, token.as_ref(), hsm_lock.deref_mut(), now)
                        .await
                    {
                        // Ignore this one.
                        Ok(UserTokenState::NotFound) => {}
                        result => break 'search result,
                    }
                }
                break 'search Ok(UserTokenState::NotFound);
            }
        };

        drop(hsm_lock);

        match user_get_result {
            Ok(UserTokenState::Update(mut n_tok)) => {
                // We have the token!
                self.set_cache_usertoken(&mut n_tok).await?;
                Ok(Some(n_tok))
            }
            Ok(UserTokenState::NotFound) => {
                // It previously existed, so now purge it.
                if let Some(tok) = token {
                    self.delete_cache_usertoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(account_id).await;
                Ok(None)
            }
            Ok(UserTokenState::UseCached) => Ok(token),
            Err(err) => {
                // Something went wrong, we don't know what, but lets return the token
                // anyway.
                error!(?err);
                Ok(token)
            }
        }
    }

    async fn refresh_grouptoken(
        &self,
        grp_id: &Id,
        token: Option<GroupToken>,
    ) -> Result<Option<GroupToken>, ()> {
        // TODO: Move this to the caller.
        let now = SystemTime::now();

        let mut hsm_lock = self.hsm.lock().await;

        let group_get_result = if let Some(tok) = token.as_ref() {
            // Re-use the provider that the token is from.
            match self.client_ids.get(&tok.provider) {
                Some(client) => {
                    client
                        .unix_group_get(grp_id, hsm_lock.deref_mut(), now)
                        .await
                }
                None => {
                    error!(provider = ?tok.provider, "Token was resolved by a provider that no longer appears to be present.");
                    // We don't know if this is permanent or transient, so just useCached, unless
                    // the admin clears tokens from providers that are no longer present.
                    Ok(GroupTokenState::UseCached)
                }
            }
        } else {
            // We've never seen it before, so iterate over the providers in priority order.
            'search: {
                for client in self.clients.iter() {
                    match client
                        .unix_group_get(grp_id, hsm_lock.deref_mut(), now)
                        .await
                    {
                        // Ignore this one.
                        Ok(GroupTokenState::NotFound) => {}
                        result => break 'search result,
                    }
                }
                break 'search Ok(GroupTokenState::NotFound);
            }
        };

        drop(hsm_lock);

        match group_get_result {
            Ok(GroupTokenState::Update(n_tok)) => {
                self.set_cache_grouptoken(&n_tok).await?;
                Ok(Some(n_tok))
            }
            Ok(GroupTokenState::NotFound) => {
                if let Some(tok) = token {
                    self.delete_cache_grouptoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(grp_id).await;
                Ok(None)
            }
            Ok(GroupTokenState::UseCached) => Ok(token),
            Err(err) => {
                // Some other transient error, continue with the token.
                error!(?err);
                Ok(token)
            }
        }
    }

    #[instrument(level = "debug", skip(self))]
    async fn get_usertoken(&self, account_id: &Id) -> Result<Option<UserToken>, ()> {
        // get the item from the cache
        let (expired, item) = self.get_cached_usertoken(account_id).await.map_err(|e| {
            debug!("get_usertoken error -> {:?}", e);
        })?;

        // If the token isn't found, get_cached will set expired = true.
        if expired {
            self.refresh_usertoken(account_id, item).await
        } else {
            // Still valid, return the cached entry.
            Ok(item)
        }
        .map(|t| {
            debug!("token -> {:?}", t);
            t
        })
    }

    #[instrument(level = "debug", skip(self))]
    async fn get_grouptoken(&self, grp_id: Id) -> Result<Option<GroupToken>, ()> {
        let (expired, item) = self.get_cached_grouptoken(&grp_id).await.map_err(|e| {
            debug!("get_grouptoken error -> {:?}", e);
        })?;

        if expired {
            self.refresh_grouptoken(&grp_id, item).await
        } else {
            // Still valid, return the cached entry.
            Ok(item)
        }
        .map(|t| {
            debug!("token -> {:?}", t);
            t
        })
    }

    async fn get_groupmembers(&self, g_uuid: Uuid) -> Vec<String> {
        let mut dbtxn = self.db.write().await;

        dbtxn
            .get_group_members(g_uuid)
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .map(|ut| self.token_uidattr(&ut))
            .collect()
    }

    // Get ssh keys for an account id
    #[instrument(level = "debug", skip(self))]
    pub async fn get_sshkeys(&self, account_id: &str) -> Result<Vec<String>, ()> {
        let token = self
            .get_usertoken(&Id::Name(account_id.to_string()))
            .await?;
        Ok(token
            .map(|t| {
                // Only return keys if the account is valid
                if t.valid {
                    t.sshkeys
                } else {
                    Vec::with_capacity(0)
                }
            })
            .unwrap_or_else(|| Vec::with_capacity(0)))
    }

    fn token_homedirectory_alias(&self, token: &UserToken) -> Option<String> {
        let is_primary_origin = token.provider == self.primary_origin;
        self.home_alias.map(|t| match t {
            // If we have an alias. use it.
            HomeAttr::Name if is_primary_origin => token.name.as_str().to_string(),
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn | HomeAttr::Name => token.spn.as_str().to_string(),
        })
    }

    fn token_homedirectory_attr(&self, token: &UserToken) -> String {
        let is_primary_origin = token.provider == self.primary_origin;
        match self.home_attr {
            HomeAttr::Name if is_primary_origin => token.name.as_str().to_string(),
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn | HomeAttr::Name => token.spn.as_str().to_string(),
        }
    }

    fn token_homedirectory(&self, token: &UserToken) -> String {
        self.token_homedirectory_alias(token)
            .unwrap_or_else(|| self.token_homedirectory_attr(token))
    }

    fn token_abs_homedirectory(&self, token: &UserToken) -> String {
        self.home_prefix
            .join(self.token_homedirectory(token))
            .to_string_lossy()
            .to_string()
    }

    fn token_uidattr(&self, token: &UserToken) -> String {
        let is_primary_origin = token.provider == self.primary_origin;
        match self.uid_attr_map {
            UidAttr::Name if is_primary_origin => token.name.as_str(),
            UidAttr::Spn | UidAttr::Name => token.spn.as_str(),
        }
        .to_string()
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn get_nssaccounts(&self) -> Result<Vec<NssUser>, ()> {
        // We don't need to filter the cached tokens as the cache shouldn't
        // have anything that collides with system.
        let system_nss_users = self.system_provider.get_nssaccounts().await;

        let cached = self.get_cached_usertokens().await?;

        Ok(system_nss_users
            .into_iter()
            .chain(cached.into_iter().map(|tok| NssUser {
                homedir: self.token_abs_homedirectory(&tok),
                name: self.token_uidattr(&tok),
                uid: tok.gidnumber,
                gid: tok.gidnumber,
                gecos: tok.displayname,
                shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
            }))
            .collect())
    }

    #[instrument(level = "debug", skip_all)]
    async fn get_nssaccount(&self, account_id: Id) -> Result<Option<NssUser>, ()> {
        if let Some(nss_user) = self.system_provider.get_nssaccount(&account_id).await {
            debug!("system provider satisfied request");
            return Ok(Some(nss_user));
        }

        let token = self.get_usertoken(&account_id).await?;
        Ok(token.map(|tok| NssUser {
            homedir: self.token_abs_homedirectory(&tok),
            name: self.token_uidattr(&tok),
            uid: tok.gidnumber,
            gid: tok.gidnumber,
            gecos: tok.displayname,
            shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
        }))
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssaccount_name(&self, account_id: &str) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Name(account_id.to_string())).await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssaccount_gid(&self, gid: u32) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Gid(gid)).await
    }

    fn token_gidattr(&self, token: &GroupToken) -> String {
        match self.gid_attr_map {
            UidAttr::Spn => token.spn.as_str(),
            UidAttr::Name => token.name.as_str(),
        }
        .to_string()
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn get_nssgroups(&self) -> Result<Vec<NssGroup>, ()> {
        let mut r = self.system_provider.get_nssgroups().await;

        let l = self.get_cached_grouptokens().await?;
        r.reserve(l.len());
        for tok in l.into_iter() {
            let members = self.get_groupmembers(tok.uuid).await;
            r.push(NssGroup {
                name: self.token_gidattr(&tok),
                gid: tok.gidnumber,
                members,
            })
        }
        Ok(r)
    }

    async fn get_nssgroup(&self, grp_id: Id) -> Result<Option<NssGroup>, ()> {
        if let Some(nss_group) = self.system_provider.get_nssgroup(&grp_id).await {
            debug!("system provider satisfied request");
            return Ok(Some(nss_group));
        }

        let token = self.get_grouptoken(grp_id).await?;
        // Get members set.
        match token {
            Some(tok) => {
                let members = self.get_groupmembers(tok.uuid).await;
                Ok(Some(NssGroup {
                    name: self.token_gidattr(&tok),
                    gid: tok.gidnumber,
                    members,
                }))
            }
            None => Ok(None),
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssgroup_name(&self, grp_id: &str) -> Result<Option<NssGroup>, ()> {
        self.get_nssgroup(Id::Name(grp_id.to_string())).await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_nssgroup_gid(&self, gid: u32) -> Result<Option<NssGroup>, ()> {
        self.get_nssgroup(Id::Gid(gid)).await
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn pam_account_allowed(&self, account_id: &str) -> Result<Option<bool>, ()> {
        let token = self
            .get_usertoken(&Id::Name(account_id.to_string()))
            .await?;

        if self.pam_allow_groups.is_empty() {
            // can't allow anything if the group list is zero...
            eprintln!("Cannot authenticate users, no allowed groups in configuration!");
            Ok(Some(false))
        } else {
            Ok(token.map(|tok| {
                let user_set: BTreeSet<_> = tok
                    .groups
                    .iter()
                    .flat_map(|g| [g.name.clone(), g.uuid.hyphenated().to_string()])
                    .collect();

                debug!(
                    "Checking if user is in allowed groups ({:?}) -> {:?}",
                    self.pam_allow_groups, user_set,
                );
                let intersection_count = user_set.intersection(&self.pam_allow_groups).count();
                debug!("Number of intersecting groups: {}", intersection_count);
                debug!("User token is valid: {}", tok.valid);

                intersection_count > 0 && tok.valid
            }))
        }
    }

    #[instrument(level = "debug", skip(self, shutdown_rx))]
    pub async fn pam_account_authenticate_init(
        &self,
        account_id: &str,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(AuthSession, PamAuthResponse), ()> {
        // Setup an auth session. If possible bring the resolver online.
        // Further steps won't attempt to bring the cache online to prevent
        // weird interactions - they should assume online/offline only for
        // the duration of their operation. A failure of connectivity during
        // an online operation will take the cache offline however.
        let now = SystemTime::now();

        let id = Id::Name(account_id.to_string());

        if self.system_provider.contains_account(&id).await {
            debug!("Ignoring auth request for system user");
            return Ok((AuthSession::Denied, PamAuthResponse::Unknown));
        }

        let token = self.get_usertoken(&id).await?;

        // Get the provider associated to this token.

        let mut hsm_lock = self.hsm.lock().await;

        // We don't care if we are expired - we will always attempt to go
        // online and perform this operation online if possible.

        if let Some(token) = token {
            // We have a token, we know what provider is needed
            let client = self.client_ids.get(&token.provider)
                .cloned()
                .ok_or_else(|| {
                    error!(provider = ?token.provider, "Token was resolved by a provider that no longer appears to be present.");
                })?;

            let online_at_init = client.attempt_online(hsm_lock.deref_mut(), now).await;
            // if we are online, we try and start an online auth.
            debug!(?online_at_init);

            if online_at_init {
                let init_result = client
                    .unix_user_online_auth_init(
                        account_id,
                        &token,
                        hsm_lock.deref_mut(),
                        &shutdown_rx,
                    )
                    .await;

                match init_result {
                    Ok((next_req, cred_handler)) => {
                        let auth_session = AuthSession::Online {
                            client,
                            account_id: account_id.to_string(),
                            id,
                            token: Some(Box::new(token)),
                            cred_handler,
                            shutdown_rx,
                        };
                        Ok((auth_session, next_req.into()))
                    }
                    Err(err) => {
                        error!(?err, "Unable to start authentication");
                        Err(())
                    }
                }
            } else {
                // Can the auth proceed offline?
                let init_result = client.unix_user_offline_auth_init(&token).await;

                match init_result {
                    Ok((next_req, cred_handler)) => {
                        let auth_session = AuthSession::Offline {
                            client,
                            token: Box::new(token),
                            cred_handler,
                        };
                        Ok((auth_session, next_req.into()))
                    }
                    Err(err) => {
                        error!(?err, "Unable to start authentication");
                        Err(())
                    }
                }
            }
        } else {
            // We don't know anything about this user. Can we try to auth them?

            // TODO: If any provider is offline should we fail the auth? I can imagine a possible
            // issue where if we had provides A, B, C stacked, and A was offline, then B could
            // service an auth that A *should* have serviced.

            for client in self.clients.iter() {
                let online_at_init = client.attempt_online(hsm_lock.deref_mut(), now).await;
                debug!(?online_at_init);

                if !online_at_init {
                    warn!(?account_id, "Unable to proceed with authentication, all providers must be online for unknown user authentication.");
                    return Ok((AuthSession::Denied, PamAuthResponse::Unknown));
                }
            }

            for client in self.clients.iter() {
                let init_result = client
                    .unix_unknown_user_online_auth_init(
                        account_id,
                        hsm_lock.deref_mut(),
                        &shutdown_rx,
                    )
                    .await;

                match init_result {
                    Ok(Some((next_req, cred_handler))) => {
                        let auth_session = AuthSession::Online {
                            client: client.clone(),
                            account_id: account_id.to_string(),
                            id,
                            token: None,
                            cred_handler,
                            shutdown_rx,
                        };
                        return Ok((auth_session, next_req.into()));
                    }
                    Ok(None) => {
                        // Not for us, check the next provider.
                    }
                    Err(err) => {
                        error!(?err, "Unable to start authentication");
                        return Err(());
                    }
                }
            }

            // No module signaled that they want it, bail.
            warn!("No provider is willing to service authentication of unknown account.");
            Ok((AuthSession::Denied, PamAuthResponse::Unknown))
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn pam_account_authenticate_step(
        &self,
        auth_session: &mut AuthSession,
        pam_next_req: PamAuthRequest,
    ) -> Result<PamAuthResponse, ()> {
        let maybe_err = match &mut *auth_session {
            &mut AuthSession::Online {
                ref client,
                ref account_id,
                id: _,
                token: _,
                ref mut cred_handler,
                ref shutdown_rx,
            } => {
                let mut hsm_lock = self.hsm.lock().await;
                client
                    .unix_user_online_auth_step(
                        account_id,
                        cred_handler,
                        pam_next_req,
                        hsm_lock.deref_mut(),
                        shutdown_rx,
                    )
                    .await
            }
            &mut AuthSession::Offline {
                ref client,
                ref token,
                ref mut cred_handler,
            } => {
                // We are offline, continue. Remember, authsession should have
                // *everything you need* to proceed here!
                let mut hsm_lock = self.hsm.lock().await;
                client
                    .unix_user_offline_auth_step(
                        token,
                        cred_handler,
                        pam_next_req,
                        hsm_lock.deref_mut(),
                    )
                    .await
            }
            &mut AuthSession::Success | &mut AuthSession::Denied => Err(IdpError::BadRequest),
        };

        match maybe_err {
            // What did the provider direct us to do next?
            Ok(AuthResult::Success { mut token }) => {
                debug!("provider authentication success.");
                self.set_cache_usertoken(&mut token).await?;
                *auth_session = AuthSession::Success;

                Ok(PamAuthResponse::Success)
            }
            Ok(AuthResult::Denied) => {
                *auth_session = AuthSession::Denied;

                Ok(PamAuthResponse::Denied)
            }
            Ok(AuthResult::Next(req)) => Ok(req.into()),
            Err(IdpError::NotFound) => Ok(PamAuthResponse::Unknown),
            _ => Err(()),
        }
    }

    // Can this be cfg debug/test?
    #[instrument(level = "debug", skip(self, password))]
    pub async fn pam_account_authenticate(
        &self,
        account_id: &str,
        password: &str,
    ) -> Result<Option<bool>, ()> {
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let mut auth_session = match self
            .pam_account_authenticate_init(account_id, shutdown_rx)
            .await?
        {
            (auth_session, PamAuthResponse::Password) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::DeviceAuthorizationGrant { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::MFACode { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::MFAPoll { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::MFAPollWait) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::SetupPin { .. }) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::Pin) => {
                // Can continue!
                auth_session
            }
            (_, PamAuthResponse::Unknown) => return Ok(None),
            (_, PamAuthResponse::Denied) => return Ok(Some(false)),
            (_, PamAuthResponse::Success) => {
                // Should never get here "off the rip".
                debug_assert!(false);
                return Ok(Some(true));
            }
        };

        // Now we can make the next step.
        let pam_next_req = PamAuthRequest::Password {
            cred: password.to_string(),
        };
        match self
            .pam_account_authenticate_step(&mut auth_session, pam_next_req)
            .await?
        {
            PamAuthResponse::Success => Ok(Some(true)),
            PamAuthResponse::Denied => Ok(Some(false)),
            _ => {
                // Should not be able to get here, if the user was unknown they should
                // be out. If it wants more mechanisms, we can't proceed here.
                // debug_assert!(false);
                Ok(None)
            }
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn pam_account_beginsession(
        &self,
        account_id: &str,
    ) -> Result<Option<HomeDirectoryInfo>, ()> {
        let token = self
            .get_usertoken(&Id::Name(account_id.to_string()))
            .await?;
        Ok(token.as_ref().map(|tok| HomeDirectoryInfo {
            gid: tok.gidnumber,
            name: self.token_homedirectory_attr(tok),
            aliases: self
                .token_homedirectory_alias(tok)
                .map(|s| vec![s])
                .unwrap_or_default(),
        }))
    }

    pub async fn provider_status(&self) -> Vec<ProviderStatus> {
        let now = SystemTime::now();
        let mut hsm_lock = self.hsm.lock().await;

        let mut results = Vec::with_capacity(self.clients.len());

        for client in self.clients.iter() {
            let online = client.attempt_online(hsm_lock.deref_mut(), now).await;

            let name = client.origin().to_string();

            results.push(ProviderStatus { name, online })
        }

        results
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn test_connection(&self) -> bool {
        let now = SystemTime::now();
        let mut hsm_lock = self.hsm.lock().await;

        for client in self.clients.iter() {
            let status = client.attempt_online(hsm_lock.deref_mut(), now).await;

            if !status {
                return false;
            }
        }

        // All online
        true
    }
}

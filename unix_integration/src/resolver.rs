// use async_trait::async_trait;
use hashbrown::HashSet;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::ops::{Add, Sub};
use std::path::Path;
use std::string::ToString;
use std::time::{Duration, SystemTime};

use lru::LruCache;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::{Cache, CacheTxn, Db};
use crate::idprovider::interface::{
    AuthCacheAction, AuthCredHandler, AuthResult, GroupToken, Id, IdProvider, IdpError, UserToken,
};
use crate::unix_config::{HomeAttr, UidAttr};
use crate::unix_proto::{HomeDirectoryInfo, NssGroup, NssUser, PamAuthRequest, PamAuthResponse};

// use crate::unix_passwd::{EtcUser, EtcGroup};

const NXCACHE_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(128) };

#[derive(Debug, Clone)]
enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

#[derive(Debug)]
pub enum AuthSession {
    InProgress {
        account_id: String,
        id: Id,
        token: Option<Box<UserToken>>,
        online_at_init: bool,
        // cred_type: AuthCredType,
        // next_cred: AuthNextCred,
        cred_handler: AuthCredHandler,
    },
    Success,
    Denied,
}

#[derive(Debug)]
pub struct Resolver<I>
where
    I: IdProvider + Sync,
{
    // Generic / modular types.
    db: Db,
    client: I,
    // Types to update still.
    state: Mutex<CacheState>,
    pam_allow_groups: BTreeSet<String>,
    timeout_seconds: u64,
    default_shell: String,
    home_prefix: String,
    home_attr: HomeAttr,
    home_alias: Option<HomeAttr>,
    uid_attr_map: UidAttr,
    gid_attr_map: UidAttr,
    allow_id_overrides: HashSet<Id>,
    nxset: Mutex<HashSet<Id>>,
    nxcache: Mutex<LruCache<Id, SystemTime>>,
}

impl ToString for Id {
    fn to_string(&self) -> String {
        match self {
            Id::Name(s) => s.clone(),
            Id::Gid(g) => g.to_string(),
        }
    }
}

impl<I> Resolver<I>
where
    I: IdProvider + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        db: Db,
        client: I,
        // cache timeout
        timeout_seconds: u64,
        pam_allow_groups: Vec<String>,
        default_shell: String,
        home_prefix: String,
        home_attr: HomeAttr,
        home_alias: Option<HomeAttr>,
        uid_attr_map: UidAttr,
        gid_attr_map: UidAttr,
        allow_id_overrides: Vec<String>,
    ) -> Result<Self, ()> {
        // setup and do a migrate.
        {
            let dbtxn = db.write().await;
            dbtxn.migrate().map_err(|_| ())?;
            dbtxn.commit().map_err(|_| ())?;
        }

        if pam_allow_groups.is_empty() {
            eprintln!("Will not be able to authorise user logins, pam_allow_groups config is not configured.");
        }

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(Resolver {
            db,
            client,
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            timeout_seconds,
            pam_allow_groups: pam_allow_groups.into_iter().collect(),
            default_shell,
            home_prefix,
            home_attr,
            home_alias,
            uid_attr_map,
            gid_attr_map,
            allow_id_overrides: allow_id_overrides.into_iter().map(Id::Name).collect(),
            nxset: Mutex::new(HashSet::new()),
            nxcache: Mutex::new(LruCache::new(NXCACHE_SIZE)),
        })
    }

    async fn get_cachestate(&self) -> CacheState {
        let g = self.state.lock().await;
        (*g).clone()
    }

    async fn set_cachestate(&self, state: CacheState) {
        let mut g = self.state.lock().await;
        *g = state;
    }

    // Need a way to mark online/offline.
    pub async fn attempt_online(&self) {
        self.set_cachestate(CacheState::OfflineNextCheck(SystemTime::now()))
            .await;
    }

    pub async fn mark_offline(&self) {
        self.set_cachestate(CacheState::Offline).await;
    }

    pub async fn clear_cache(&self) -> Result<(), ()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        let dbtxn = self.db.write().await;
        dbtxn.clear().and_then(|_| dbtxn.commit()).map_err(|_| ())
    }

    pub async fn invalidate(&self) -> Result<(), ()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        let dbtxn = self.db.write().await;
        dbtxn
            .invalidate()
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn get_cached_usertokens(&self) -> Result<Vec<UserToken>, ()> {
        let dbtxn = self.db.write().await;
        dbtxn.get_accounts().map_err(|_| ())
    }

    async fn get_cached_grouptokens(&self) -> Result<Vec<GroupToken>, ()> {
        let dbtxn = self.db.write().await;
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

    pub async fn reload_nxset(&self, iter: impl Iterator<Item = (String, u32)>) {
        let mut nxset_txn = self.nxset.lock().await;
        nxset_txn.clear();
        for (name, gid) in iter {
            let name = Id::Name(name);
            let gid = Id::Gid(gid);

            // Skip anything that the admin opted in to
            if !(self.allow_id_overrides.contains(&gid) || self.allow_id_overrides.contains(&name))
            {
                debug!("Adding {:?}:{:?} to resolver exclusion set", name, gid);
                nxset_txn.insert(name);
                nxset_txn.insert(gid);
            }
        }
    }

    pub async fn check_nxset(&self, name: &str, idnumber: u32) -> bool {
        let nxset_txn = self.nxset.lock().await;
        nxset_txn.contains(&Id::Gid(idnumber)) || nxset_txn.contains(&Id::Name(name.to_string()))
    }

    async fn get_cached_usertoken(&self, account_id: &Id) -> Result<(bool, Option<UserToken>), ()> {
        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let dbtxn = self.db.write().await;
        let r = dbtxn.get_account(account_id).map_err(|_| ())?;

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
        let dbtxn = self.db.write().await;
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

        // Filter out groups that are in the nxset
        {
            let nxset_txn = self.nxset.lock().await;
            token.groups.retain(|g| {
                !(nxset_txn.contains(&Id::Gid(g.gidnumber))
                    || nxset_txn.contains(&Id::Name(g.name.clone())))
            });
        }

        let dbtxn = self.db.write().await;
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

        let dbtxn = self.db.write().await;
        dbtxn
            .update_group(token, offset.as_secs())
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn delete_cache_usertoken(&self, a_uuid: Uuid) -> Result<(), ()> {
        let dbtxn = self.db.write().await;
        dbtxn
            .delete_account(a_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn delete_cache_grouptoken(&self, g_uuid: Uuid) -> Result<(), ()> {
        let dbtxn = self.db.write().await;
        dbtxn
            .delete_group(g_uuid)
            .and_then(|_| dbtxn.commit())
            .map_err(|_| ())
    }

    async fn set_cache_userpassword(&self, a_uuid: Uuid, cred: &str) -> Result<(), ()> {
        let dbtxn = self.db.write().await;
        dbtxn
            .update_account_password(a_uuid, cred)
            .and_then(|x| dbtxn.commit().map(|_| x))
            .map_err(|_| ())
    }

    async fn check_cache_userpassword(&self, a_uuid: Uuid, cred: &str) -> Result<bool, ()> {
        let dbtxn = self.db.write().await;
        dbtxn
            .check_account_password(a_uuid, cred)
            .and_then(|x| dbtxn.commit().map(|_| x))
            .map_err(|_| ())
    }

    async fn refresh_usertoken(
        &self,
        account_id: &Id,
        token: Option<UserToken>,
    ) -> Result<Option<UserToken>, ()> {
        match self.client.unix_user_get(account_id, token.as_ref()).await {
            Ok(mut n_tok) => {
                if self.check_nxset(&n_tok.name, n_tok.gidnumber).await {
                    // Refuse to release the token, it's in the denied set.
                    self.delete_cache_usertoken(n_tok.uuid).await?;
                    Ok(None)
                } else {
                    // We have the token!
                    self.set_cache_usertoken(&mut n_tok).await?;
                    Ok(Some(n_tok))
                }
            }
            Err(IdpError::Transport) => {
                error!("transport error, moving to offline");
                // Something went wrong, mark offline.
                let time = SystemTime::now().add(Duration::from_secs(15));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                Ok(token)
            }
            Err(IdpError::ProviderUnauthorised) => {
                // Something went wrong, mark offline to force a re-auth ASAP.
                let time = SystemTime::now().sub(Duration::from_secs(1));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                Ok(token)
            }
            Err(IdpError::NotFound) => {
                // We were able to contact the server but the entry has been removed, or
                // is not longer a valid posix account.
                if let Some(tok) = token {
                    self.delete_cache_usertoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(account_id).await;

                Ok(None)
            }
            Err(IdpError::BadRequest) => {
                // Some other transient error, continue with the token.
                Ok(token)
            }
        }
    }

    async fn refresh_grouptoken(
        &self,
        grp_id: &Id,
        token: Option<GroupToken>,
    ) -> Result<Option<GroupToken>, ()> {
        match self.client.unix_group_get(grp_id).await {
            Ok(n_tok) => {
                if self.check_nxset(&n_tok.name, n_tok.gidnumber).await {
                    // Refuse to release the token, it's in the denied set.
                    self.delete_cache_grouptoken(n_tok.uuid).await?;
                    Ok(None)
                } else {
                    // We have the token!
                    self.set_cache_grouptoken(&n_tok).await?;
                    Ok(Some(n_tok))
                }
            }
            Err(IdpError::Transport) => {
                error!("transport error, moving to offline");
                // Something went wrong, mark offline.
                let time = SystemTime::now().add(Duration::from_secs(15));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                Ok(token)
            }
            Err(IdpError::ProviderUnauthorised) => {
                // Something went wrong, mark offline.
                let time = SystemTime::now().add(Duration::from_secs(15));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                Ok(token)
            }
            Err(IdpError::NotFound) => {
                if let Some(tok) = token {
                    self.delete_cache_grouptoken(tok.uuid).await?;
                };
                // Cache the NX here.
                self.set_nxcache(grp_id).await;
                Ok(None)
            }
            Err(IdpError::BadRequest) => {
                // Some other transient error, continue with the token.
                Ok(token)
            }
        }
    }

    async fn get_usertoken(&self, account_id: Id) -> Result<Option<UserToken>, ()> {
        debug!("get_usertoken");
        // get the item from the cache
        let (expired, item) = self.get_cached_usertoken(&account_id).await.map_err(|e| {
            debug!("get_usertoken error -> {:?}", e);
        })?;

        let state = self.get_cachestate().await;

        match (expired, state) {
            (_, CacheState::Offline) => {
                debug!("offline, returning cached item");
                Ok(item)
            }
            (false, CacheState::OfflineNextCheck(time)) => {
                debug!(
                    "offline valid, next check {:?}, returning cached item",
                    time
                );
                // Still valid within lifetime, return.
                Ok(item)
            }
            (false, CacheState::Online) => {
                debug!("online valid, returning cached item");
                // Still valid within lifetime, return.
                Ok(item)
            }
            (true, CacheState::OfflineNextCheck(time)) => {
                debug!("offline expired, next check {:?}, refresh cache", time);
                // Attempt to refresh the item
                // Return it.
                if SystemTime::now() >= time && self.test_connection().await {
                    // We brought ourselves online, lets go
                    self.refresh_usertoken(&account_id, item).await
                } else {
                    // Unable to bring up connection, return cache.
                    Ok(item)
                }
            }
            (true, CacheState::Online) => {
                debug!("online expired, refresh cache");
                // Attempt to refresh the item
                // Return it.
                self.refresh_usertoken(&account_id, item).await
            }
        }
        .map(|t| {
            debug!("token -> {:?}", t);
            t
        })
    }

    async fn get_grouptoken(&self, grp_id: Id) -> Result<Option<GroupToken>, ()> {
        debug!("get_grouptoken");
        let (expired, item) = self.get_cached_grouptoken(&grp_id).await.map_err(|e| {
            debug!("get_grouptoken error -> {:?}", e);
        })?;

        let state = self.get_cachestate().await;

        match (expired, state) {
            (_, CacheState::Offline) => {
                debug!("offline, returning cached item");
                Ok(item)
            }
            (false, CacheState::OfflineNextCheck(time)) => {
                debug!(
                    "offline valid, next check {:?}, returning cached item",
                    time
                );
                // Still valid within lifetime, return.
                Ok(item)
            }
            (false, CacheState::Online) => {
                debug!("online valid, returning cached item");
                // Still valid within lifetime, return.
                Ok(item)
            }
            (true, CacheState::OfflineNextCheck(time)) => {
                debug!("offline expired, next check {:?}, refresh cache", time);
                // Attempt to refresh the item
                // Return it.
                if SystemTime::now() >= time && self.test_connection().await {
                    // We brought ourselves online, lets go
                    self.refresh_grouptoken(&grp_id, item).await
                } else {
                    // Unable to bring up connection, return cache.
                    Ok(item)
                }
            }
            (true, CacheState::Online) => {
                debug!("online expired, refresh cache");
                // Attempt to refresh the item
                // Return it.
                self.refresh_grouptoken(&grp_id, item).await
            }
        }
    }

    async fn get_groupmembers(&self, g_uuid: Uuid) -> Vec<String> {
        let dbtxn = self.db.write().await;

        dbtxn
            .get_group_members(g_uuid)
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .map(|ut| self.token_uidattr(&ut))
            .collect()
    }

    // Get ssh keys for an account id
    pub async fn get_sshkeys(&self, account_id: &str) -> Result<Vec<String>, ()> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;
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

    #[inline(always)]
    fn token_homedirectory_alias(&self, token: &UserToken) -> Option<String> {
        self.home_alias.map(|t| match t {
            // If we have an alias. use it.
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn => token.spn.as_str().to_string(),
            HomeAttr::Name => token.name.as_str().to_string(),
        })
    }

    #[inline(always)]
    fn token_homedirectory_attr(&self, token: &UserToken) -> String {
        match self.home_attr {
            HomeAttr::Uuid => token.uuid.hyphenated().to_string(),
            HomeAttr::Spn => token.spn.as_str().to_string(),
            HomeAttr::Name => token.name.as_str().to_string(),
        }
    }

    #[inline(always)]
    fn token_homedirectory(&self, token: &UserToken) -> String {
        self.token_homedirectory_alias(token)
            .unwrap_or_else(|| self.token_homedirectory_attr(token))
    }

    #[inline(always)]
    fn token_abs_homedirectory(&self, token: &UserToken) -> String {
        format!("{}{}", self.home_prefix, self.token_homedirectory(token))
    }

    #[inline(always)]
    fn token_uidattr(&self, token: &UserToken) -> String {
        match self.uid_attr_map {
            UidAttr::Spn => token.spn.as_str(),
            UidAttr::Name => token.name.as_str(),
        }
        .to_string()
    }

    pub async fn get_nssaccounts(&self) -> Result<Vec<NssUser>, ()> {
        self.get_cached_usertokens().await.map(|l| {
            l.into_iter()
                .map(|tok| NssUser {
                    homedir: self.token_abs_homedirectory(&tok),
                    name: self.token_uidattr(&tok),
                    gid: tok.gidnumber,
                    gecos: tok.displayname,
                    shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
                })
                .collect()
        })
    }

    async fn get_nssaccount(&self, account_id: Id) -> Result<Option<NssUser>, ()> {
        let token = self.get_usertoken(account_id).await?;
        Ok(token.map(|tok| NssUser {
            homedir: self.token_abs_homedirectory(&tok),
            name: self.token_uidattr(&tok),
            gid: tok.gidnumber,
            gecos: tok.displayname,
            shell: tok.shell.unwrap_or_else(|| self.default_shell.clone()),
        }))
    }

    pub async fn get_nssaccount_name(&self, account_id: &str) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Name(account_id.to_string())).await
    }

    pub async fn get_nssaccount_gid(&self, gid: u32) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Gid(gid)).await
    }

    #[inline(always)]
    fn token_gidattr(&self, token: &GroupToken) -> String {
        match self.gid_attr_map {
            UidAttr::Spn => token.spn.as_str(),
            UidAttr::Name => token.name.as_str(),
        }
        .to_string()
    }

    pub async fn get_nssgroups(&self) -> Result<Vec<NssGroup>, ()> {
        let l = self.get_cached_grouptokens().await?;
        let mut r: Vec<_> = Vec::with_capacity(l.len());
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

    pub async fn get_nssgroup_name(&self, grp_id: &str) -> Result<Option<NssGroup>, ()> {
        self.get_nssgroup(Id::Name(grp_id.to_string())).await
    }

    pub async fn get_nssgroup_gid(&self, gid: u32) -> Result<Option<NssGroup>, ()> {
        self.get_nssgroup(Id::Gid(gid)).await
    }

    /*
    async fn online_account_authenticate(
        &self,
        token: &Option<UserToken>,
        account_id: &Id,
        cred: Option<PamCred>,
        data: Option<PamData>,
    ) -> Result<ClientResponse, ()> {
        debug!("Attempt online password check");
        // Unwrap the cred for passing to the step function
        let ucred = match &cred {
            Some(PamCred::Password(v)) => Some(v.clone()),
            Some(PamCred::MFACode(v)) => Some(v.clone()),
            None => None,
        };
        // We are online, attempt the pw to the server.
        match self
            .client
            .unix_user_authenticate_step(account_id, ucred.as_deref(), data)
            .await
        {
            Ok(ProviderResult::UserToken(Some(mut n_tok))) => {
                if self.check_nxset(&n_tok.name, n_tok.gidnumber).await {
                    // Refuse to release the token, it's in the denied set.
                    self.delete_cache_usertoken(n_tok.uuid).await?;
                    Ok(ClientResponse::PamStatus(None))
                } else {
                    debug!("online password check success.");
                    self.set_cache_usertoken(&mut n_tok).await?;
                    match cred {
                        Some(PamCred::Password(cred)) => {
                            // Only cache an actual password (not an MFA token)
                            self.set_cache_userpassword(n_tok.uuid, &cred).await?;
                        }
                        Some(_) => {}
                        None => {}
                    }
                    Ok(ClientResponse::PamStatus(Some(true)))
                }
            }
            Ok(ProviderResult::UserToken(None)) => {
                error!("incorrect password");
                // PW failed the check.
                Ok(ClientResponse::PamStatus(Some(false)))
            }
            Ok(ProviderResult::PamPrompt(prompt)) => {
                debug!("Requesting pam prompt {:?}", prompt);
                Ok(ClientResponse::PamPrompt(prompt))
            }
            Err(IdpError::Transport) => {
                error!("transport error, moving to offline");
                // Something went wrong, mark offline.
                let time = SystemTime::now().add(Duration::from_secs(15));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                match token.as_ref() {
                    Some(t) => match ucred {
                        Some(cred) => match self.check_cache_userpassword(t.uuid, &cred).await {
                            Ok(res) => Ok(ClientResponse::PamStatus(Some(res))),
                            Err(e) => Err(e),
                        },
                        None => Ok(ClientResponse::PamPrompt(PamPrompt::passwd_prompt())),
                    },
                    None => Ok(ClientResponse::PamStatus(None)),
                }
            }
            Err(IdpError::ProviderUnauthorised) => {
                // Something went wrong, mark offline to force a re-auth ASAP.
                let time = SystemTime::now().sub(Duration::from_secs(1));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                match token.as_ref() {
                    Some(t) => match ucred {
                        Some(cred) => match self.check_cache_userpassword(t.uuid, &cred).await {
                            Ok(res) => Ok(ClientResponse::PamStatus(Some(res))),
                            Err(e) => Err(e),
                        },
                        None => Ok(ClientResponse::PamPrompt(PamPrompt::passwd_prompt())),
                    },
                    None => Ok(ClientResponse::PamStatus(None)),
                }
            }
            Err(IdpError::NotFound) => Ok(ClientResponse::PamStatus(None)),
            Err(IdpError::BadRequest) => {
                // Some other unknown processing error?
                Err(())
            }
        }
    }

    async fn offline_account_authenticate(
        &self,
        token: &Option<UserToken>,
        cred: Option<PamCred>,
    ) -> Result<ClientResponse, ()> {
        let cred = match cred {
            Some(cred) => match cred {
                PamCred::Password(v) => v.clone(),
                // We can only authenticate using a password
                _ => return Ok(ClientResponse::PamStatus(Some(false))),
            },
            None => return Ok(ClientResponse::PamPrompt(PamPrompt::passwd_prompt())),
        };
        debug!("Attempt offline password check");
        match token.as_ref() {
            Some(t) => {
                if t.valid {
                    match self.check_cache_userpassword(t.uuid, &cred).await {
                        Ok(res) => Ok(ClientResponse::PamStatus(Some(res))),
                        Err(e) => Err(e),
                    }
                } else {
                    Ok(ClientResponse::PamStatus(Some(false)))
                }
            }
            None => Ok(ClientResponse::PamStatus(None)),
        }
        /*
        token
            .as_ref()
            .map(async |t| self.check_cache_userpassword(&t.uuid, cred).await)
            .transpose()
        */
    }
    */

    pub async fn pam_account_allowed(&self, account_id: &str) -> Result<Option<bool>, ()> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;

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
                debug!("User has valid token: {}", tok.valid);

                intersection_count > 0 && tok.valid
            }))
        }
    }

    pub async fn pam_account_authenticate_init(
        &self,
        account_id: &str,
    ) -> Result<(AuthSession, PamAuthResponse), ()> {
        // Setup an auth session. If possible bring the resolver online.
        // Further steps won't attempt to bring the cache online to prevent
        // weird interactions - they should assume online/offline only for
        // the duration of their operation. A failure of connectivity during
        // an online operation will take the cache offline however.

        let id = Id::Name(account_id.to_string());
        let (_expired, token) = self.get_cached_usertoken(&id).await?;
        let state = self.get_cachestate().await;

        let online_at_init = if !matches!(state, CacheState::Online) {
            // Attempt a cache online.
            self.test_connection().await
        } else {
            true
        };

        let maybe_err = if online_at_init {
            self.client
                .unix_user_online_auth_init(account_id, token.as_ref())
                .await
        } else {
            // Can the auth proceed offline?
            self.client
                .unix_user_offline_auth_init(account_id, token.as_ref())
                .await
        };

        match maybe_err {
            Ok((next_req, cred_handler)) => {
                let auth_session = AuthSession::InProgress {
                    account_id: account_id.to_string(),
                    id,
                    token: token.map(Box::new),
                    online_at_init,
                    cred_handler,
                };

                // Now identify what credentials are needed next. The auth session tells
                // us this.

                Ok((auth_session, next_req.into()))
            }
            Err(IdpError::NotFound) => Ok((AuthSession::Denied, PamAuthResponse::Unknown)),
            Err(IdpError::ProviderUnauthorised) | Err(IdpError::Transport) => {
                error!("transport error, moving to offline");
                // Something went wrong, mark offline.
                let time = SystemTime::now().add(Duration::from_secs(15));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                Err(())
            }
            Err(IdpError::BadRequest) => Err(()),
        }
    }

    pub async fn pam_account_authenticate_step(
        &self,
        auth_session: &mut AuthSession,
        pam_next_req: PamAuthRequest,
    ) -> Result<PamAuthResponse, ()> {
        let state = self.get_cachestate().await;

        let maybe_err = match (&mut *auth_session, state) {
            (
                &mut AuthSession::InProgress {
                    ref account_id,
                    id: _,
                    token: _,
                    online_at_init: true,
                    ref mut cred_handler,
                },
                CacheState::Online,
            ) => {
                let maybe_cache_action = self
                    .client
                    .unix_user_online_auth_step(account_id, cred_handler, pam_next_req)
                    .await;

                match maybe_cache_action {
                    Ok((res, AuthCacheAction::None)) => Ok(res),
                    Ok((
                        AuthResult::Success { token },
                        AuthCacheAction::PasswordHashUpdate { cred },
                    )) => {
                        // Might need a rework with the tpm code.
                        self.set_cache_userpassword(token.uuid, &cred).await?;
                        Ok(AuthResult::Success { token })
                    }
                    // I think this state is actually invalid?
                    Ok((_, AuthCacheAction::PasswordHashUpdate { .. })) => {
                        // Ok(res)
                        error!("provider gave back illogical password hash update with a nonsuccess condition");
                        Err(IdpError::BadRequest)
                    }
                    Err(e) => Err(e),
                }
            }
            /*
            (
                &mut AuthSession::InProgress {
                    account_id: _,
                    id: _,
                    token: _,
                    online_at_init: true,
                    cred_handler: _,
                },
                _,
            ) => {
                // Fail, we went offline.
                error!("Unable to proceed with authentication, resolver has gone offline");
                Err(IdpError::Transport)
            }
            */
            (
                &mut AuthSession::InProgress {
                    account_id: _,
                    id: _,
                    token: Some(ref token),
                    online_at_init: _,
                    ref mut cred_handler,
                },
                _,
            ) => {
                // We are offline, continue. Remember, authsession should have
                // *everything you need* to proceed here!
                //
                // Rather than calling client, should this actually be self
                // contained to the resolver so that it has generic offline-paths
                // that are possible?
                match (cred_handler, pam_next_req) {
                    (AuthCredHandler::Password, PamAuthRequest::Password { cred }) => {
                        match self.check_cache_userpassword(token.uuid, &cred).await {
                            Ok(true) => Ok(AuthResult::Success {
                                token: *token.clone(),
                            }),
                            Ok(false) => Ok(AuthResult::Denied),
                            Err(()) => {
                                // We had a genuine backend error of some description.
                                return Err(());
                            }
                        }
                    }
                    (AuthCredHandler::Password, _) => {
                        // AuthCredHandler::Password is only valid with a cred provided
                        return Err(());
                    }
                    (AuthCredHandler::DeviceAuthorizationGrant, _) => {
                        // AuthCredHandler::DeviceAuthorizationGrant is invalid for offline auth
                        return Err(());
                    }
                }

                /*
                self.client
                    .unix_user_offline_auth_step(
                        &account_id,
                        cred_handler,
                        pam_next_req,
                        online_at_init,
                    )
                    .await
                */
            }
            (&mut AuthSession::InProgress { token: None, .. }, _) => {
                // Can't do much with offline auth when there is no token ...
                warn!("Unable to proceed with offline auth, no token available");
                Err(IdpError::NotFound)
            }
            (&mut AuthSession::Success, _) | (&mut AuthSession::Denied, _) => {
                Err(IdpError::BadRequest)
            }
        };

        match maybe_err {
            // What did the provider direct us to do next?
            Ok(AuthResult::Success { mut token }) => {
                if self.check_nxset(&token.name, token.gidnumber).await {
                    // Refuse to release the token, it's in the denied set.
                    self.delete_cache_usertoken(token.uuid).await?;
                    *auth_session = AuthSession::Denied;

                    Ok(PamAuthResponse::Unknown)
                } else {
                    debug!("provider authentication success.");
                    self.set_cache_usertoken(&mut token).await?;
                    *auth_session = AuthSession::Success;

                    Ok(PamAuthResponse::Success)
                }
            }
            Ok(AuthResult::Denied) => {
                *auth_session = AuthSession::Denied;
                Ok(PamAuthResponse::Denied)
            }
            Ok(AuthResult::Next(req)) => Ok(req.into()),
            Err(IdpError::NotFound) => Ok(PamAuthResponse::Unknown),
            Err(IdpError::ProviderUnauthorised) | Err(IdpError::Transport) => {
                error!("transport error, moving to offline");
                // Something went wrong, mark offline.
                let time = SystemTime::now().add(Duration::from_secs(15));
                self.set_cachestate(CacheState::OfflineNextCheck(time))
                    .await;
                Err(())
            }
            Err(IdpError::BadRequest) => Err(()),
        }
    }

    // Can this be cfg debug/test?
    pub async fn pam_account_authenticate(
        &self,
        account_id: &str,
        password: &str,
    ) -> Result<Option<bool>, ()> {
        let mut auth_session = match self.pam_account_authenticate_init(account_id).await? {
            (auth_session, PamAuthResponse::Password) => {
                // Can continue!
                auth_session
            }
            (auth_session, PamAuthResponse::DeviceAuthorizationGrant { .. }) => {
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

    pub async fn pam_account_beginsession(
        &self,
        account_id: &str,
    ) -> Result<Option<HomeDirectoryInfo>, ()> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;
        Ok(token.as_ref().map(|tok| HomeDirectoryInfo {
            gid: tok.gidnumber,
            name: self.token_homedirectory_attr(tok),
            aliases: self
                .token_homedirectory_alias(tok)
                .map(|s| vec![s])
                .unwrap_or_else(Vec::new),
        }))
    }

    pub async fn test_connection(&self) -> bool {
        let state = self.get_cachestate().await;
        match state {
            CacheState::Offline => {
                debug!("Offline -> no change");
                false
            }
            CacheState::OfflineNextCheck(_time) => {
                match self.client.provider_authenticate().await {
                    Ok(()) => {
                        debug!("OfflineNextCheck -> authenticated");
                        self.set_cachestate(CacheState::Online).await;
                        true
                    }
                    Err(e) => {
                        debug!("OfflineNextCheck -> disconnected, staying offline. {:?}", e);
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        false
                    }
                }
            }
            CacheState::Online => {
                debug!("Online, no change");
                true
            }
        }
    }
}

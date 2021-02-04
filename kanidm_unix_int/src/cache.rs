use crate::db::Db;
use crate::unix_config::{HomeAttr, UidAttr};
use crate::unix_proto::{HomeDirectoryInfo, NssGroup, NssUser};
use kanidm_client::asynchronous::KanidmAsyncClient;
use kanidm_client::ClientError;
use kanidm_proto::v1::{OperationError, UnixGroupToken, UnixUserToken};
use lru::LruCache;
use reqwest::StatusCode;
use std::collections::BTreeSet;
use std::ops::Add;
use std::string::ToString;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};

const NXCACHE_SIZE: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Id {
    Name(String),
    Gid(u32),
}

#[derive(Debug, Clone)]
enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

#[derive(Debug)]
pub struct CacheLayer {
    db: Db,
    client: RwLock<KanidmAsyncClient>,
    state: Mutex<CacheState>,
    pam_allow_groups: BTreeSet<String>,
    timeout_seconds: u64,
    default_shell: String,
    home_prefix: String,
    home_attr: HomeAttr,
    home_alias: Option<HomeAttr>,
    uid_attr_map: UidAttr,
    gid_attr_map: UidAttr,
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

impl CacheLayer {
    // TODO: Could consider refactoring this to be better ...
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        // need db path
        path: &str,
        // cache timeout
        timeout_seconds: u64,
        //
        client: KanidmAsyncClient,
        pam_allow_groups: Vec<String>,
        default_shell: String,
        home_prefix: String,
        home_attr: HomeAttr,
        home_alias: Option<HomeAttr>,
        uid_attr_map: UidAttr,
        gid_attr_map: UidAttr,
    ) -> Result<Self, ()> {
        let db = Db::new(path)?;

        // setup and do a migrate.
        {
            let dbtxn = db.write().await;
            dbtxn.migrate()?;
            dbtxn.commit()?;
        }

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(CacheLayer {
            db,
            client: RwLock::new(client),
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            timeout_seconds,
            pam_allow_groups: pam_allow_groups.into_iter().collect(),
            default_shell,
            home_prefix,
            home_attr,
            home_alias,
            uid_attr_map,
            gid_attr_map,
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
        dbtxn.clear_cache().and_then(|_| dbtxn.commit())
    }

    pub async fn invalidate(&self) -> Result<(), ()> {
        let mut nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.clear();
        let dbtxn = self.db.write().await;
        dbtxn.invalidate().and_then(|_| dbtxn.commit())
    }

    async fn get_cached_usertokens(&self) -> Result<Vec<UnixUserToken>, ()> {
        let dbtxn = self.db.write().await;
        dbtxn.get_accounts()
    }

    async fn get_cached_grouptokens(&self) -> Result<Vec<UnixGroupToken>, ()> {
        let dbtxn = self.db.write().await;
        dbtxn.get_groups()
    }

    async fn set_nxcache(&self, id: &Id) {
        let mut nxcache_txn = self.nxcache.lock().await;
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        nxcache_txn.put(id.clone(), ex_time);
    }

    pub async fn check_nxcache(&self, id: &Id) -> bool {
        let nxcache_txn = self.nxcache.lock().await;
        nxcache_txn.contains(id)
    }

    async fn get_cached_usertoken(
        &self,
        account_id: &Id,
    ) -> Result<(bool, Option<UnixUserToken>), ()> {
        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let dbtxn = self.db.write().await;
        let r = dbtxn.get_account(&account_id)?;

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
                let mut nxcache_txn = self.nxcache.lock().await;
                match nxcache_txn.get(account_id) {
                    Some(ex_time) => {
                        let now = SystemTime::now();
                        if &now >= ex_time {
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

    async fn get_cached_grouptoken(
        &self,
        grp_id: &Id,
    ) -> Result<(bool, Option<UnixGroupToken>), ()> {
        // grp_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let dbtxn = self.db.write().await;
        let r = dbtxn.get_group(&grp_id)?;

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
                let mut nxcache_txn = self.nxcache.lock().await;
                match nxcache_txn.get(grp_id) {
                    Some(ex_time) => {
                        let now = SystemTime::now();
                        if &now >= ex_time {
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

    async fn set_cache_usertoken(&self, token: &UnixUserToken) -> Result<(), ()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
            })?;

        let dbtxn = self.db.write().await;
        // We need to add the groups first
        token
            .groups
            .iter()
            .try_for_each(|g| dbtxn.update_group(g, offset.as_secs()))
            .and_then(|_|
                // So that when we add the account it can make the relationships.
                dbtxn
                    .update_account(token, offset.as_secs()))
            .and_then(|_| dbtxn.commit())
    }

    async fn set_cache_grouptoken(&self, token: &UnixGroupToken) -> Result<(), ()> {
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
    }

    async fn delete_cache_usertoken(&self, a_uuid: &str) -> Result<(), ()> {
        let dbtxn = self.db.write().await;
        dbtxn.delete_account(a_uuid).and_then(|_| dbtxn.commit())
    }

    async fn delete_cache_grouptoken(&self, g_uuid: &str) -> Result<(), ()> {
        let dbtxn = self.db.write().await;
        dbtxn.delete_group(g_uuid).and_then(|_| dbtxn.commit())
    }

    async fn set_cache_userpassword(&self, a_uuid: &str, cred: &str) -> Result<(), ()> {
        let dbtxn = self.db.write().await;
        dbtxn
            .update_account_password(a_uuid, cred)
            .and_then(|x| dbtxn.commit().map(|_| x))
    }

    async fn check_cache_userpassword(&self, a_uuid: &str, cred: &str) -> Result<bool, ()> {
        let dbtxn = self.db.write().await;
        dbtxn
            .check_account_password(a_uuid, cred)
            .and_then(|x| dbtxn.commit().map(|_| x))
    }

    async fn refresh_usertoken(
        &self,
        account_id: &Id,
        token: Option<UnixUserToken>,
    ) -> Result<Option<UnixUserToken>, ()> {
        match self
            .client
            .read()
            .await
            .idm_account_unix_token_get(account_id.to_string().as_str())
            .await
        {
            Ok(n_tok) => {
                // We have the token!
                self.set_cache_usertoken(&n_tok).await?;
                Ok(Some(n_tok))
            }
            Err(e) => {
                match e {
                    ClientError::Transport(er) => {
                        error!("transport error, moving to offline -> {:?}", er);
                        // Something went wrong, mark offline.
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        Ok(token)
                    }
                    ClientError::Http(
                        StatusCode::UNAUTHORIZED,
                        Some(OperationError::NotAuthenticated),
                        opid,
                    ) => {
                        error!(
                            "transport unauthenticated, moving to offline - eventid {}",
                            opid
                        );
                        // Something went wrong, mark offline.
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        Ok(token)
                    }
                    ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    )
                    | ClientError::Http(
                        StatusCode::NOT_FOUND,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    )
                    | ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::InvalidAccountState(_)),
                        opid,
                    ) => {
                        // We wele able to contact the server but the entry has been removed, or
                        // is not longer a valid posix account.
                        debug!("entry has been removed or is no longer a valid posix account, clearing from cache ... - eventid {}", opid);
                        if let Some(tok) = token {
                            self.delete_cache_usertoken(&tok.uuid).await?;
                        };
                        // Cache the NX here.
                        self.set_nxcache(account_id).await;

                        Ok(None)
                    }
                    er => {
                        error!("client error -> {:?}", er);
                        // Some other transient error, continue with the token.
                        Ok(token)
                    }
                }
            }
        }
    }

    async fn refresh_grouptoken(
        &self,
        grp_id: &Id,
        token: Option<UnixGroupToken>,
    ) -> Result<Option<UnixGroupToken>, ()> {
        match self
            .client
            .read()
            .await
            .idm_group_unix_token_get(grp_id.to_string().as_str())
            .await
        {
            Ok(n_tok) => {
                // We have the token!
                self.set_cache_grouptoken(&n_tok).await?;
                Ok(Some(n_tok))
            }
            Err(e) => {
                match e {
                    ClientError::Transport(er) => {
                        error!("transport error, moving to offline -> {:?}", er);
                        // Something went wrong, mark offline.
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        Ok(token)
                    }
                    ClientError::Http(
                        StatusCode::UNAUTHORIZED,
                        Some(OperationError::NotAuthenticated),
                        opid,
                    ) => {
                        error!(
                            "transport unauthenticated, moving to offline - eventid {}",
                            opid
                        );
                        // Something went wrong, mark offline.
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        Ok(token)
                    }
                    ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    )
                    | ClientError::Http(
                        StatusCode::NOT_FOUND,
                        Some(OperationError::NoMatchingEntries),
                        opid,
                    )
                    | ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::InvalidAccountState(_)),
                        opid,
                    ) => {
                        debug!("entry has been removed or is no longer a valid posix group, clearing from cache ... - eventid {}", opid);
                        if let Some(tok) = token {
                            self.delete_cache_grouptoken(&tok.uuid).await?;
                        };
                        // Cache the NX here.
                        self.set_nxcache(grp_id).await;

                        Ok(None)
                    }
                    er => {
                        error!("client error -> {:?}", er);
                        // Some other transient error, continue with the token.
                        Ok(token)
                    }
                }
            }
        }
    }

    async fn get_usertoken(&self, account_id: Id) -> Result<Option<UnixUserToken>, ()> {
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

    async fn get_grouptoken(&self, grp_id: Id) -> Result<Option<UnixGroupToken>, ()> {
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

    async fn get_groupmembers(&self, uuid: &str) -> Vec<String> {
        let dbtxn = self.db.write().await;

        dbtxn
            .get_group_members(uuid)
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
    fn token_homedirectory_alias(&self, token: &UnixUserToken) -> Option<String> {
        self.home_alias.map(|t| match t {
            // If we have an alias. use it.
            HomeAttr::Uuid => token.uuid.as_str().to_string(),
            HomeAttr::Spn => token.spn.as_str().to_string(),
            HomeAttr::Name => token.name.as_str().to_string(),
        })
    }

    #[inline(always)]
    fn token_homedirectory_attr(&self, token: &UnixUserToken) -> String {
        match self.home_attr {
            HomeAttr::Uuid => token.uuid.as_str().to_string(),
            HomeAttr::Spn => token.spn.as_str().to_string(),
            HomeAttr::Name => token.name.as_str().to_string(),
        }
    }

    #[inline(always)]
    fn token_homedirectory(&self, token: &UnixUserToken) -> String {
        self.token_homedirectory_alias(token)
            .unwrap_or_else(|| self.token_homedirectory_attr(token))
    }

    #[inline(always)]
    fn token_abs_homedirectory(&self, token: &UnixUserToken) -> String {
        format!("{}{}", self.home_prefix, self.token_homedirectory(token))
    }

    #[inline(always)]
    fn token_uidattr(&self, token: &UnixUserToken) -> String {
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
    fn token_gidattr(&self, token: &UnixGroupToken) -> String {
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
            let members = self.get_groupmembers(&tok.uuid).await;
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
                let members = self.get_groupmembers(&tok.uuid).await;
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

    async fn online_account_authenticate(
        &self,
        token: &Option<UnixUserToken>,
        account_id: &str,
        cred: &str,
    ) -> Result<Option<bool>, ()> {
        debug!("Attempt online password check");
        // We are online, attempt the pw to the server.
        match self
            .client
            .read()
            .await
            .idm_account_unix_cred_verify(account_id, cred)
            .await
        {
            Ok(Some(n_tok)) => {
                debug!("online password check success.");
                self.set_cache_usertoken(&n_tok).await?;
                self.set_cache_userpassword(&n_tok.uuid, cred).await?;
                Ok(Some(true))
            }
            Ok(None) => {
                error!("incorrect password");
                // PW failed the check.
                Ok(Some(false))
            }
            Err(e) => match e {
                ClientError::Transport(er) => {
                    error!("transport error, moving to offline -> {:?}", er);
                    // Something went wrong, mark offline.
                    let time = SystemTime::now().add(Duration::from_secs(15));
                    self.set_cachestate(CacheState::OfflineNextCheck(time))
                        .await;
                    match token.as_ref() {
                        Some(t) => self.check_cache_userpassword(&t.uuid, cred).await.map(Some),
                        None => Ok(None),
                    }
                }
                ClientError::Http(
                    StatusCode::UNAUTHORIZED,
                    Some(OperationError::NotAuthenticated),
                    opid,
                ) => {
                    error!(
                        "transport unauthenticated, moving to offline - eventid {}",
                        opid
                    );
                    // Something went wrong, mark offline.
                    let time = SystemTime::now().add(Duration::from_secs(15));
                    self.set_cachestate(CacheState::OfflineNextCheck(time))
                        .await;
                    match token.as_ref() {
                        Some(t) => self.check_cache_userpassword(&t.uuid, cred).await.map(Some),
                        None => Ok(None),
                    }
                }
                ClientError::Http(
                    StatusCode::BAD_REQUEST,
                    Some(OperationError::NoMatchingEntries),
                    opid,
                )
                | ClientError::Http(
                    StatusCode::NOT_FOUND,
                    Some(OperationError::NoMatchingEntries),
                    opid,
                )
                | ClientError::Http(
                    StatusCode::BAD_REQUEST,
                    Some(OperationError::InvalidAccountState(_)),
                    opid,
                ) => {
                    error!(
                        "unknown account or is not a valid posix account - eventid {}",
                        opid
                    );
                    Ok(None)
                }
                er => {
                    error!("client error -> {:?}", er);
                    // Some other unknown processing error?
                    Err(())
                }
            },
        }
    }

    async fn offline_account_authenticate(
        &self,
        token: &Option<UnixUserToken>,
        cred: &str,
    ) -> Result<Option<bool>, ()> {
        debug!("Attempt offline password check");
        match token.as_ref() {
            Some(t) => {
                if t.valid {
                    self.check_cache_userpassword(&t.uuid, cred).await.map(Some)
                } else {
                    Ok(Some(false))
                }
            }
            None => Ok(None),
        }
        /*
        token
            .as_ref()
            .map(async |t| self.check_cache_userpassword(&t.uuid, cred).await)
            .transpose()
        */
    }

    pub async fn pam_account_allowed(&self, account_id: &str) -> Result<Option<bool>, ()> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;

        Ok(token.map(|tok| {
            let user_set: BTreeSet<_> = tok
                .groups
                .iter()
                .map(|g| vec![g.name.clone(), g.spn.clone(), g.uuid.clone()])
                .flatten()
                .collect();

            debug!(
                "Checking if -> {:?} & {:?}",
                user_set, self.pam_allow_groups
            );

            user_set.intersection(&self.pam_allow_groups).count() > 0 && tok.valid
        }))
    }

    pub async fn pam_account_authenticate(
        &self,
        account_id: &str,
        cred: &str,
    ) -> Result<Option<bool>, ()> {
        let state = self.get_cachestate().await;
        let (_expired, token) = self
            .get_cached_usertoken(&Id::Name(account_id.to_string()))
            .await?;

        match state {
            CacheState::Online => {
                self.online_account_authenticate(&token, account_id, cred)
                    .await
            }
            CacheState::OfflineNextCheck(_time) => {
                // Always attempt to go online to attempt the authentication.
                if self.test_connection().await {
                    // Brought ourselves online, lets check.
                    self.online_account_authenticate(&token, account_id, cred)
                        .await
                } else {
                    // We are offline, check from the cache if possible.
                    self.offline_account_authenticate(&token, cred).await
                }
            }
            _ => {
                // We are offline, check from the cache if possible.
                self.offline_account_authenticate(&token, cred).await
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
            path: self.home_prefix.clone(),
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
                match self.client.write().await.auth_anonymous().await {
                    Ok(_uat) => {
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

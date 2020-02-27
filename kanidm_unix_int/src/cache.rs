use crate::db::Db;
use crate::unix_proto::{NssGroup, NssUser};
use kanidm_client::asynchronous::KanidmAsyncClient;
use kanidm_client::ClientError;
use kanidm_proto::v1::{OperationError, UnixGroupToken, UnixUserToken};
use reqwest::StatusCode;
use std::collections::BTreeSet;
use std::ops::Add;
use std::string::ToString;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

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
    client: KanidmAsyncClient,
    state: Mutex<CacheState>,
    pam_allow_groups: BTreeSet<String>,
    timeout_seconds: u64,
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
    pub fn new(
        // need db path
        path: &str,
        // cache timeout
        timeout_seconds: u64,
        //
        client: KanidmAsyncClient,
        pam_allow_groups: Vec<String>,
    ) -> Result<Self, ()> {
        let db = Db::new(path)?;

        // setup and do a migrate.
        {
            let dbtxn = db.write();
            dbtxn.migrate()?;
            dbtxn.commit()?;
        }

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(CacheLayer {
            db: db,
            client: client,
            state: Mutex::new(CacheState::OfflineNextCheck(SystemTime::now())),
            timeout_seconds: timeout_seconds,
            pam_allow_groups: pam_allow_groups.into_iter().collect(),
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

    pub fn clear_cache(&self) -> Result<(), ()> {
        let dbtxn = self.db.write();
        dbtxn.clear_cache().and_then(|_| dbtxn.commit())
    }

    pub fn invalidate(&self) -> Result<(), ()> {
        let dbtxn = self.db.write();
        dbtxn.invalidate().and_then(|_| dbtxn.commit())
    }

    fn get_cached_usertokens(&self) -> Result<Vec<UnixUserToken>, ()> {
        let dbtxn = self.db.write();
        dbtxn.get_accounts()
    }

    fn get_cached_grouptokens(&self) -> Result<Vec<UnixGroupToken>, ()> {
        let dbtxn = self.db.write();
        dbtxn.get_groups()
    }

    fn get_cached_usertoken(&self, account_id: &Id) -> Result<(bool, Option<UnixUserToken>), ()> {
        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let dbtxn = self.db.write();
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
            None => Ok((true, None)),
        }
    }

    fn get_cached_grouptoken(&self, grp_id: &Id) -> Result<(bool, Option<UnixGroupToken>), ()> {
        // grp_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let dbtxn = self.db.write();
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
            None => Ok((true, None)),
        }
    }

    fn set_cache_usertoken(&self, token: &UnixUserToken) -> Result<(), ()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
                ()
            })?;

        let dbtxn = self.db.write();
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

    fn set_cache_grouptoken(&self, token: &UnixGroupToken) -> Result<(), ()> {
        // Set an expiry
        let ex_time = SystemTime::now() + Duration::from_secs(self.timeout_seconds);
        let offset = ex_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                error!("time conversion error - ex_time less than epoch? {:?}", e);
                ()
            })?;

        let dbtxn = self.db.write();
        dbtxn
            .update_group(token, offset.as_secs())
            .and_then(|_| dbtxn.commit())
    }

    fn delete_cache_usertoken(&self, a_uuid: &str) -> Result<(), ()> {
        let dbtxn = self.db.write();
        dbtxn.delete_account(a_uuid).and_then(|_| dbtxn.commit())
    }

    fn delete_cache_grouptoken(&self, g_uuid: &str) -> Result<(), ()> {
        let dbtxn = self.db.write();
        dbtxn.delete_group(g_uuid).and_then(|_| dbtxn.commit())
    }

    fn set_cache_userpassword(&self, a_uuid: &str, cred: &str) -> Result<(), ()> {
        let dbtxn = self.db.write();
        dbtxn
            .update_account_password(a_uuid, cred)
            .and_then(|x| dbtxn.commit().map(|_| x))
    }

    fn check_cache_userpassword(&self, a_uuid: &str, cred: &str) -> Result<bool, ()> {
        let dbtxn = self.db.write();
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
            .idm_account_unix_token_get(account_id.to_string().as_str())
            .await
        {
            Ok(n_tok) => {
                // We have the token!
                self.set_cache_usertoken(&n_tok)?;
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
                    ) => {
                        error!("transport unauthenticated, moving to offline");
                        // Something went wrong, mark offline.
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        Ok(token)
                    }
                    ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::NoMatchingEntries),
                    ) => {
                        // We wele able to contact the server but the entry has been removed.
                        debug!("entry has been removed, clearing from cache ...");
                        token
                            .map(|tok| self.delete_cache_usertoken(&tok.uuid))
                            // Now an option<result<t, _>>
                            .transpose()
                            // now result<option<t>, _>
                            .map(|_| None)
                    }
                    er => {
                        error!("client error -> {:?}", er);
                        // Some other transient error, continue with the token.
                        Err(())
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
            .idm_group_unix_token_get(grp_id.to_string().as_str())
            .await
        {
            Ok(n_tok) => {
                // We have the token!
                self.set_cache_grouptoken(&n_tok)?;
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
                    ) => {
                        error!("transport unauthenticated, moving to offline");
                        // Something went wrong, mark offline.
                        let time = SystemTime::now().add(Duration::from_secs(15));
                        self.set_cachestate(CacheState::OfflineNextCheck(time))
                            .await;
                        Ok(token)
                    }
                    ClientError::Http(
                        StatusCode::BAD_REQUEST,
                        Some(OperationError::NoMatchingEntries),
                    ) => {
                        debug!("entry has been removed, clearing from cache ...");
                        token
                            .map(|tok| self.delete_cache_grouptoken(&tok.uuid))
                            // Now an option<result<t, _>>
                            .transpose()
                            // now result<option<t>, _>
                            .map(|_| None)
                    }
                    er => {
                        error!("client error -> {:?}", er);
                        // Some other transient error, continue with the token.
                        Err(())
                    }
                }
            }
        }
    }

    async fn get_usertoken(&self, account_id: Id) -> Result<Option<UnixUserToken>, ()> {
        debug!("get_usertoken");
        // get the item from the cache
        let (expired, item) = self.get_cached_usertoken(&account_id).map_err(|e| {
            debug!("get_usertoken error -> {:?}", e);
            ()
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
    }

    async fn get_grouptoken(&self, grp_id: Id) -> Result<Option<UnixGroupToken>, ()> {
        debug!("get_grouptoken");
        let (expired, item) = self.get_cached_grouptoken(&grp_id).map_err(|e| {
            debug!("get_grouptoken error -> {:?}", e);
            ()
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

    fn get_groupmembers(&self, uuid: &str) -> Vec<String> {
        let dbtxn = self.db.write();

        dbtxn
            .get_group_members(uuid)
            .unwrap_or_else(|_| Vec::new())
            .into_iter()
            .map(|ut| {
                // TODO: We'll have a switch to convert this to spn in some configs
                // in the future.
                ut.name
            })
            .collect()
    }

    // Get ssh keys for an account id
    pub async fn get_sshkeys(&self, account_id: &str) -> Result<Vec<String>, ()> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;
        Ok(token.map(|t| t.sshkeys).unwrap_or_else(|| Vec::new()))
    }

    pub fn get_nssaccounts(&self) -> Result<Vec<NssUser>, ()> {
        self.get_cached_usertokens().map(|l| {
            l.into_iter()
                .map(|tok| {
                    NssUser {
                        homedir: format!("/home/{}", tok.name),
                        name: tok.name,
                        gid: tok.gidnumber,
                        gecos: tok.displayname,
                        // TODO: default shell override.
                        shell: tok.shell.unwrap_or_else(|| "/bin/bash".to_string()),
                    }
                })
                .collect()
        })
    }

    async fn get_nssaccount(&self, account_id: Id) -> Result<Option<NssUser>, ()> {
        let token = self.get_usertoken(account_id).await?;
        Ok(token.map(|tok| {
            NssUser {
                homedir: format!("/home/{}", tok.name),
                name: tok.name,
                gid: tok.gidnumber,
                gecos: tok.displayname,
                // TODO: default shell override.
                shell: tok.shell.unwrap_or_else(|| "/bin/bash".to_string()),
            }
        }))
    }

    pub async fn get_nssaccount_name(&self, account_id: &str) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Name(account_id.to_string())).await
    }

    pub async fn get_nssaccount_gid(&self, gid: u32) -> Result<Option<NssUser>, ()> {
        self.get_nssaccount(Id::Gid(gid)).await
    }

    pub fn get_nssgroups(&self) -> Result<Vec<NssGroup>, ()> {
        self.get_cached_grouptokens().map(|l| {
            l.into_iter()
                .map(|tok| {
                    let members = self.get_groupmembers(&tok.uuid);
                    NssGroup {
                        name: tok.name,
                        gid: tok.gidnumber,
                        members: members,
                    }
                })
                .collect()
        })
    }

    async fn get_nssgroup(&self, grp_id: Id) -> Result<Option<NssGroup>, ()> {
        let token = self.get_grouptoken(grp_id).await?;
        // Get members set.
        Ok(token.map(|tok| {
            let members = self.get_groupmembers(&tok.uuid);
            NssGroup {
                name: tok.name,
                gid: tok.gidnumber,
                members: members,
            }
        }))
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
            .idm_account_unix_cred_verify(account_id, cred)
            .await
        {
            Ok(Some(n_tok)) => {
                debug!("online password check success.");
                self.set_cache_usertoken(&n_tok)?;
                self.set_cache_userpassword(&n_tok.uuid, cred)?;
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
                    token
                        .as_ref()
                        .map(|t| self.check_cache_userpassword(&t.uuid, cred))
                        .transpose()
                }
                ClientError::Http(
                    StatusCode::UNAUTHORIZED,
                    Some(OperationError::NotAuthenticated),
                ) => {
                    error!("transport unauthenticated, moving to offline");
                    // Something went wrong, mark offline.
                    let time = SystemTime::now().add(Duration::from_secs(15));
                    self.set_cachestate(CacheState::OfflineNextCheck(time))
                        .await;
                    token
                        .as_ref()
                        .map(|t| self.check_cache_userpassword(&t.uuid, cred))
                        .transpose()
                }
                ClientError::Http(
                    StatusCode::BAD_REQUEST,
                    Some(OperationError::NoMatchingEntries),
                ) => {
                    error!("unknown account");
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

    fn offline_account_authenticate(
        &self,
        token: &Option<UnixUserToken>,
        cred: &str,
    ) -> Result<Option<bool>, ()> {
        debug!("Attempt offline password check");
        token
            .as_ref()
            .map(|t| self.check_cache_userpassword(&t.uuid, cred))
            .transpose()
    }

    pub async fn pam_account_allowed(&self, account_id: &str) -> Result<Option<bool>, ()> {
        let token = self.get_usertoken(Id::Name(account_id.to_string())).await?;

        Ok(token.map(|tok| {
            let user_set: BTreeSet<_> = tok.groups.iter().map(|g| g.name.clone()).collect();

            debug!(
                "Checking if -> {:?} & {:?}",
                user_set, self.pam_allow_groups
            );

            let b = user_set.intersection(&self.pam_allow_groups).count() > 0;
            b
        }))
    }

    pub async fn pam_account_authenticate(
        &self,
        account_id: &str,
        cred: &str,
    ) -> Result<Option<bool>, ()> {
        let state = self.get_cachestate().await;
        let (_expired, token) = self.get_cached_usertoken(&Id::Name(account_id.to_string()))?;

        match state {
            CacheState::Online => {
                self.online_account_authenticate(&token, account_id, cred)
                    .await
            }
            CacheState::OfflineNextCheck(time) => {
                // Should this always attempt to go online?
                if SystemTime::now() >= time && self.test_connection().await {
                    // Brought ourselves online, lets check.
                    self.online_account_authenticate(&token, account_id, cred)
                        .await
                } else {
                    // We are offline, check from the cache if possible.
                    self.offline_account_authenticate(&token, cred)
                }
            }
            _ => {
                // We are offline, check from the cache if possible.
                self.offline_account_authenticate(&token, cred)
            }
        }
    }

    pub async fn test_connection(&self) -> bool {
        let state = self.get_cachestate().await;
        match state {
            CacheState::Offline => {
                debug!("Offline -> no change");
                false
            }
            CacheState::OfflineNextCheck(_time) => match self.client.auth_anonymous().await {
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
            },
            CacheState::Online => {
                debug!("Online, no change");
                true
            }
        }
    }
}

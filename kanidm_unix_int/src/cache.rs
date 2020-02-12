use kanidm_client::asynchronous::KanidmAsyncClient;
use kanidm_proto::v1::{UnixUserToken, UnixGroupToken};
use crate::db::Db;
use std::ops::Add;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

#[derive(Debug)]
pub struct CacheLayer {
    db: Db,
    client: KanidmAsyncClient,
    state: CacheState,
}

impl CacheLayer {
    pub fn new(
        // need db path
        path: &str,
        // cache timeout
        timeout_seconds: usize,
        //
        client: KanidmAsyncClient,
    ) -> Result<Self, ()> {
        let db = Db::new(path)?;

        // setup and do a migrate.
        {
            let mut dbtxn = db.write();
            dbtxn.migrate()?;
            dbtxn.commit();
        }

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(CacheLayer {
            db: db,
            client: client,
            state: CacheState::OfflineNextCheck(SystemTime::now()),
        })
    }

    // Need a way to mark online/offline.
    pub fn attempt_online(&mut self) {
        self.state = CacheState::OfflineNextCheck(SystemTime::now());
    }

    pub fn mark_offline(&mut self) {
        self.state = CacheState::Offline;
    }

    // Invalidate the whole cache. We do this by just deleting the content
    // of the sqlite db.
    pub fn invalidate(&self) {
        unimplemented!();
    }

    fn get_cached_usertoken(&self, account_id: &str) -> Result<(bool, Option<UnixUserToken>), ()> {
        // Account_id could be:
        //  * gidnumber
        //  * name
        //  * spn
        //  * uuid
        //  Attempt to search these in the db.
        let dbtxn = self.db.write();
        let r = dbtxn.get_account(account_id)?;

        match r {
            Some((ut, ex)) => {
                // Are we expired?
                let offset = Duration::from_secs(ex);
                let ex_time = SystemTime::UNIX_EPOCH + offset;
                let now = SystemTime::now();

                if now >= ex_time  {
                    Ok((true, Some(ut)))
                } else {
                    Ok((false, Some(ut)))
                }
            }
            None => {
                Ok((true, None))
            }
        }
    }

    fn set_cache_usertoken(&mut self, token: ()) -> Result<(), ()> {
        unimplemented!();
    }

    async fn get_usertoken(&mut self, account_id: &str) -> Result<Option<UnixUserToken>, ()> {
        debug!("get_usertoken");
        // get the item from the cache
        let (expired, item) = self.get_cached_usertoken(account_id).map_err(|e| {
            debug!("get_usertoken error -> {:?}", e);
            ()
        })?;

        match (expired, &self.state) {
            (_, CacheState::Offline) => Ok(item),
            (false, CacheState::OfflineNextCheck(_time)) => {
                // Still valid within lifetime, return.
                Ok(item)
            }
            (false, CacheState::Online) => {
                // Still valid within lifetime, return.
                Ok(item)
            }
            (true, CacheState::OfflineNextCheck(time)) => {
                // Attempt to refresh the item
                // Return it.
                unimplemented!();
            }
            (true, CacheState::Online) => {
                // Attempt to refresh the item
                // Return it.
                unimplemented!();
            }
        }
    }

    // Get ssh keys for an account id
    pub async fn get_sshkeys(&mut self, account_id: &str) -> Result<Vec<String>, ()> {
        let token = self.get_usertoken(account_id).await?;
        Ok(token
            .map(|t| t.sshkeys)
            .unwrap_or_else(|| Vec::new()))
    }

    pub async fn test_connection(&mut self) -> bool {
        match &self.state {
            CacheState::Offline => {
                debug!("Offline -> no change");
                false
            }
            CacheState::OfflineNextCheck(_time) => match self.client.auth_anonymous().await {
                Ok(uat) => {
                    debug!("OfflineNextCheck -> authenticated");
                    self.state = CacheState::Online;
                    true
                }
                Err(e) => {
                    debug!("OfflineNextCheck -> disconnected, staying offline.");
                    let time = SystemTime::now().add(Duration::from_secs(15));
                    self.state = CacheState::OfflineNextCheck(time);
                    false
                }
            },
            CacheState::Online => {
                unimplemented!();
            }
        }
    }
}

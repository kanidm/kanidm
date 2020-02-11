use kanidm_client::asynchronous::KanidmAsyncClient;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
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
    pool: Pool<SqliteConnectionManager>,
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
        let manager = SqliteConnectionManager::file(path);
        // We only build a single thread. If we need more than one, we'll
        // need to re-do this to account for path = "" for debug.
        let builder1 = Pool::builder().max_size(1);
        let pool = builder1.build(manager).map_err(|e| {
            error!("r2d2 error {:?}", e);
            ()
        })?;

        // We assume we are offline at start up, and we mark the next "online check" as
        // being valid from "now".
        Ok(CacheLayer {
            pool: pool,
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

    fn get_cached_usertoken(&self) -> Result<Option<()>, ()> {
        unimplemented!();
    }

    fn set_cache_usertoken(&mut self, token: ()) -> Result<(), ()> {
        unimplemented!();
    }

    async fn get_usertoken(&mut self) -> Result<(), ()> {
        debug!("get_usertoken");
        // get the item from the cache
        let mut item = self.get_cached_usertoken().map_err(|e| {
            debug!("get_usertoken error -> {:?}", e);
            ()
        })?;
        // does it need refresh?

        // what state are we in?
        match self.state {
            CacheState::Offline => {
                unimplemented!();
            }
            CacheState::OfflineNextCheck(time) => {
                //
                unimplemented!();
            }
            CacheState::Online => {
                unimplemented!();
            }
        }
    }

    // Get ssh keys for an account id
    pub async fn get_sshkeys(&mut self, account_id: &str) -> Result<Vec<String>, ()> {
        let token = self.get_usertoken().await?;
        unimplemented!();
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

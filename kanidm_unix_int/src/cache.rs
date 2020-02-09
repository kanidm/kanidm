use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
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
    state: CacheState,
}

impl CacheLayer {
    pub fn new(
        // need db path
        path: &str,
        // need url
        addr: &str,
        // ca
        // username/pass
        // timeout
        // cache timeout
    ) -> Result<Self, ()> {
        let manager = SqliteConnectionManager::file(path);
        // We only build a single thread. If we need more than one, we'll
        // need to re-do this to account for path = "" for debug.
        let builder1 = Pool::builder().max_size(1);
        let pool = builder1.build(manager).map_err(|e| {
            error!("r2d2 error {:?}", e);
            ()
        })?;

        // We assume we are online at start up, which may change as we
        // proceed.
        Ok(CacheLayer {
            pool: pool,
            state: CacheState::Online,
        })
    }

    // Need a way to mark online/offline.
    pub fn mark_online(&mut self) {
        self.state = CacheState::Online;
    }

    pub fn mark_offline(&mut self) {
        self.state = CacheState::Offline;
    }

    // Invalidate the whole cache. We do this by just deleting the content
    // of the sqlite db.
    pub fn invalidate(&self) {
        unimplemented!();
    }

    // Get ssh keys for an account id
    pub async fn get_sshkeys(&mut self, account_id: &str) -> Result<Vec<String>, ()> {
        unimplemented!();
    }

    pub async fn test_async(&self) -> bool {
        true
    }
}

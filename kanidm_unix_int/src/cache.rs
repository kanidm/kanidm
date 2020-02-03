use std::time::{Duration, SystemTime};

#[derive(Debug)]
enum CacheState {
    Online,
    Offline,
    OfflineNextCheck(SystemTime),
}

#[derive(Debug)]
pub struct CacheLayer {
    state: CacheState
}

impl CacheLayer {
    pub fn new(
        // need db path
        // need url
        // ca
        // username/pass
        // timeout
        // cache timeout
    ) -> Self {
        // We assume we are online at start up, which may change as we
        // proceed.
        CacheLayer {
            state: CacheState::Online
        }
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



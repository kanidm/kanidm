//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;

use crate::constants::PURGE_FREQUENCY;
use crate::event::{LiveBackupEvent, PurgeRecycledEvent, PurgeTombstoneEvent};

use tokio::time::{interval, Duration};

pub struct IntervalActor;

impl IntervalActor {
    pub fn start(server: &'static QueryServerWriteV1) {
        tokio::spawn(async move {
            let mut inter = interval(Duration::from_secs(PURGE_FREQUENCY));
            loop {
                inter.tick().await;
                server
                    .handle_purgetombstoneevent(PurgeTombstoneEvent::new())
                    .await;
                server
                    .handle_purgerecycledevent(PurgeRecycledEvent::new())
                    .await;
            }
        });
    }

    pub fn start_live_backup(server: &'static QueryServerReadV1) {
        tokio::spawn(async move {
            let mut inter = interval(Duration::from_secs(5));
            loop {
                inter.tick().await;
                server.handle_live_backup(LiveBackupEvent::new()).await;
            }
        });
    }
}

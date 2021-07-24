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

    pub fn start_online_backup(server: &'static QueryServerReadV1, outpath: &String, itime: u64) {
        let outpath = outpath.to_owned();

        tokio::spawn(async move {
            let mut inter = interval(Duration::from_secs(itime));
            loop {
                inter.tick().await;
                server
                    .handle_online_backup(LiveBackupEvent::new(), outpath.clone().as_str())
                    .await;
            }
        });
    }
}

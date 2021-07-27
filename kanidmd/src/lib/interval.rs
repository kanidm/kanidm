//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;

use crate::config::OnlineBackup;
use crate::constants::PURGE_FREQUENCY;
use crate::event::{OnlineBackupEvent, PurgeRecycledEvent, PurgeTombstoneEvent};
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

    pub fn start_online_backup(server: &'static QueryServerReadV1, cfg: &OnlineBackup) {
        let outpath = cfg.path.to_owned();
        let schedule = cfg.schedule.to_owned();
        let versions = cfg.versions;

        tokio::spawn(async move {
            // TODO parse the schedule string using saffron and get the next time to run the backup.
            let _x = schedule.clone();
            let mut inter = interval(Duration::from_secs(10));
            loop {
                inter.tick().await;
                server
                    .handle_online_backup(
                        OnlineBackupEvent::new(),
                        outpath.clone().as_str(),
                        versions,
                    )
                    .await;
            }
        });
    }
}

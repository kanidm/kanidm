//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;

use crate::config::OnlineBackup;
use crate::constants::PURGE_FREQUENCY;
use crate::event::{OnlineBackupEvent, PurgeRecycledEvent, PurgeTombstoneEvent};
use chrono::Utc;
use saffron::parse::{CronExpr, English};
use saffron::Cron;
use tokio::time::{interval, sleep, Duration};

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

        // TODO: add some checks arount the provided cron pattern .any() etc.
        let cron_expr = match schedule.as_str().parse::<CronExpr>() {
            Ok(ce) => {
                // TODO maybe we remove this info output?
                info!(
                    "Online backup schedule parsed as: {}",
                    ce.describe(English::default())
                );

                if !Cron::new(ce.clone()).any() {
                    error!(
                        "Online backup error: Schedule '{}' will not match any date.",
                        schedule
                    );
                    // do not continue!
                    return;
                }
                ce
            }
            Err(err) => {
                error!(
                    "Online backup error: Schedule '{}' failed to parse. Error: {}.",
                    schedule, err
                );
                // do not continue!
                return;
            }
        };

        tokio::spawn(async move {
            let ct = Utc::now();
            let cron = Cron::new(cron_expr.clone());

            let cron_iter = cron.clone().iter_after(ct);
            for next_time in cron_iter {
                // +1 to have even times, but we might anyway cut away the seconds from the timestamp.
                let wait_seconds = 1 + (next_time - Utc::now()).num_seconds() as u64;
                info!(
                    "Online backup next run on {}, wait_time = {}s",
                    next_time, wait_seconds
                );

                sleep(Duration::from_secs(wait_seconds)).await;
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

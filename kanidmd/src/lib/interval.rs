//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;

use crate::config::OnlineBackup;
use crate::constants::PURGE_FREQUENCY;
use crate::event::{OnlineBackupEvent, PurgeRecycledEvent, PurgeTombstoneEvent};
use crate::utils::file_permissions_readonly;

use chrono::Utc;
use saffron::parse::{CronExpr, English};
use saffron::Cron;
use std::fs;
use std::path::Path;
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

    pub fn start_online_backup(
        server: &'static QueryServerReadV1,
        cfg: &OnlineBackup,
    ) -> Result<(), ()> {
        let outpath = cfg.path.to_owned();
        let schedule = cfg.schedule.to_owned();
        let versions = cfg.versions;

        // Cron expression handling
        let cron_expr = schedule.as_str().parse::<CronExpr>().map_err(|e| {
            error!("Online backup schedule parse error: {}", e);
        })?;

        info!(
            "Online backup schedule parsed as: {}",
            cron_expr.describe(English::default())
        );

        if !Cron::new(cron_expr.clone()).any() {
            error!(
                "Online backup schedule error: '{}' will not match any date.",
                schedule
            );
            return Err(());
        }

        // Output path handling
        let op = Path::new(&outpath);

        // does the path exist and is a directory?
        if !op.exists() {
            info!(
                "Online backup output folder '{}' does not exist, trying to create it.",
                outpath
            );
            fs::create_dir_all(&outpath).map_err(|e| {
                error!(
                    "Online backup failed to create output directory '{}': {}",
                    outpath.clone(),
                    e
                )
            })?;
        }

        if !op.is_dir() {
            error!("Online backup output '{}' is not a directory or we are missing permissions to access it.", outpath);
            return Err(());
        }

        // checking permissions (not sure about this)
        // TODO: we still might have a folder that we can read but not write in it.
        let meta = op.metadata().unwrap();
        if !file_permissions_readonly(&meta) {
            eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", outpath);
        }

        tokio::spawn(async move {
            let ct = Utc::now();
            let cron = Cron::new(cron_expr.clone());

            let cron_iter = cron.clone().iter_after(ct);
            for next_time in cron_iter {
                // We add 1 second to the `wait_time` in order to get "even" timestampes
                // for example: 1 + 17:05:59Z --> 17:06:00Z
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

        Ok(())
    }
}

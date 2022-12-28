//! This contains scheduled tasks/interval tasks that are run inside of the server on a schedule
//! as background operations.

use std::fs;
use std::path::Path;
use std::str::FromStr;

use chrono::Utc;
use cron::Schedule;

use tokio::sync::broadcast;
use tokio::time::{interval, sleep, Duration};

use crate::config::OnlineBackup;
use crate::CoreAction;

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use kanidmd_lib::constants::PURGE_FREQUENCY;
use kanidmd_lib::event::{OnlineBackupEvent, PurgeRecycledEvent, PurgeTombstoneEvent};

pub struct IntervalActor;

impl IntervalActor {
    pub fn start(
        server: &'static QueryServerWriteV1,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut inter = interval(Duration::from_secs(PURGE_FREQUENCY));

            loop {
                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                        }
                    }
                    _ = inter.tick() => {
                        server
                            .handle_purgetombstoneevent(PurgeTombstoneEvent::new())
                            .await;
                        server
                            .handle_purgerecycledevent(PurgeRecycledEvent::new())
                            .await;
                    }
                }
            }

            info!("Stopped IntervalActor");
        })
    }

    // Allow this because result is the only way to map and ? to bubble up, but we aren't
    // returning an op-error here because this is in early start up.
    #[allow(clippy::result_unit_err)]
    pub fn start_online_backup(
        server: &'static QueryServerReadV1,
        cfg: &OnlineBackup,
        mut rx: broadcast::Receiver<CoreAction>,
    ) -> Result<tokio::task::JoinHandle<()>, ()> {
        let outpath = cfg.path.to_owned();
        let versions = cfg.versions;

        // Cron expression handling
        let cron_expr = Schedule::from_str(cfg.schedule.as_str()).map_err(|e| {
            error!("Online backup schedule parse error: {}", e);
            error!("valid formats are:");
            error!("sec  min   hour   day of month   month   day of week   year");
            error!("@hourly | @daily | @weekly");
        })?;

        info!("Online backup schedule parsed as: {}", cron_expr);

        if cron_expr.upcoming(Utc).next().is_none() {
            error!(
                "Online backup schedule error: '{}' will not match any date.",
                cron_expr
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

        let handle = tokio::spawn(async move {
            for next_time in cron_expr.upcoming(Utc) {
                // We add 1 second to the `wait_time` in order to get "even" timestampes
                // for example: 1 + 17:05:59Z --> 17:06:00Z
                let wait_seconds = 1 + (next_time - Utc::now()).num_seconds() as u64;
                info!(
                    "Online backup next run on {}, wait_time = {}s",
                    next_time, wait_seconds
                );

                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                        }
                    }
                    _ = sleep(Duration::from_secs(wait_seconds)) => {
                        if let Err(e) = server
                            .handle_online_backup(
                                OnlineBackupEvent::new(),
                                outpath.clone().as_str(),
                                versions,
                            )
                            .await
                        {
                            error!(?e, "An online backup error occured.");
                        }
                    }
                }
            }
            info!("Stopped OnlineBackupActor");
        });

        Ok(handle)
    }
}

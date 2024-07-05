//! ⚠️  Operations in this set of actor handlers are INTERNAL and MAY bypass
//! access controls. Access is *IMPLIED* by the use of these via the internal
//! admin unixd socket.

use crate::{QueryServerReadV1, QueryServerWriteV1};
use tracing::{Instrument, Level};

use kanidmd_lib::prelude::*;

use kanidmd_lib::{
    event::{PurgeRecycledEvent, PurgeTombstoneEvent},
    idm::delayed::DelayedAction,
};

use kanidm_proto::internal::{
    DomainInfo as ProtoDomainInfo, DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport,
};

impl QueryServerReadV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn handle_domain_show(
        &self,
        eventid: Uuid,
    ) -> Result<ProtoDomainInfo, OperationError> {
        let mut idms_prox_read = self.idms.proxy_read().await;

        idms_prox_read.qs_read.domain_info()
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn handle_domain_upgrade_check(
        &self,
        eventid: Uuid,
    ) -> Result<ProtoDomainUpgradeCheckReport, OperationError> {
        let mut idms_prox_read = self.idms.proxy_read().await;

        idms_prox_read.qs_read.domain_upgrade_check()
    }
}

impl QueryServerWriteV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?msg.eventid)
    )]
    pub async fn handle_purgetombstoneevent(&self, msg: PurgeTombstoneEvent) {
        let mut idms_prox_write = self.idms.proxy_write(duration_from_epoch_now()).await;

        let res = idms_prox_write
            .qs_write
            .purge_tombstones()
            .and_then(|_changed| idms_prox_write.commit());

        match res {
            Ok(()) => {
                debug!("Purge tombstone success");
            }
            Err(err) => {
                error!(?err, "Unable to purge tombstones");
            }
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?msg.eventid)
    )]
    pub async fn handle_purgerecycledevent(&self, msg: PurgeRecycledEvent) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await;
        let res = idms_prox_write
            .qs_write
            .purge_recycled()
            .and_then(|touched| {
                // don't need to commit a txn with no changes
                if touched > 0 {
                    idms_prox_write.commit()
                } else {
                    Ok(())
                }
            });

        match res {
            Ok(()) => {
                debug!("Purge recyclebin success");
            }
            Err(err) => {
                error!(?err, "Unable to purge recyclebin");
            }
        }
    }

    pub(crate) async fn handle_delayedaction(&self, da_batch: &mut Vec<DelayedAction>) {
        let eventid = Uuid::new_v4();
        let span = span!(Level::INFO, "process_delayed_action", uuid = ?eventid);

        let mut retry = false;

        async {
            let ct = duration_from_epoch_now();
            let mut idms_prox_write = self.idms.proxy_write(ct).await;

            for da in da_batch.iter() {
                retry = idms_prox_write.process_delayedaction(da, ct).is_err();
                if retry {
                    // exit the loop
                    warn!("delayed action failed, will be retried individually.");
                    break;
                }
            }

            if let Err(res) = idms_prox_write.commit() {
                retry = true;
                error!(?res, "delayed action batch commit error");
            }
        }
        .instrument(span)
        .await;

        if retry {
            // An error occured, retry each operation one at a time.
            for da in da_batch.iter() {
                let eventid = Uuid::new_v4();
                let span = span!(Level::INFO, "process_delayed_action_retried", uuid = ?eventid);

                async {
                    let ct = duration_from_epoch_now();
                    let mut idms_prox_write = self.idms.proxy_write(ct).await;
                    if let Err(res) = idms_prox_write
                        .process_delayedaction(da, ct)
                        .and_then(|_| idms_prox_write.commit())
                    {
                        error!(?res, "delayed action commit error");
                    }
                }
                .instrument(span)
                .await
            }
        }

        // We're done, clear out the buffer.
        da_batch.clear();
    }

    #[instrument(
        level = "info",
        skip(self, eventid),
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn handle_admin_recover_account(
        &self,
        name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await;
        let pw = idms_prox_write.recover_account(name.as_str(), None)?;

        idms_prox_write.commit().map(|()| pw)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn handle_domain_raise(&self, eventid: Uuid) -> Result<u32, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await;

        idms_prox_write.qs_write.domain_raise(DOMAIN_MAX_LEVEL)?;

        idms_prox_write.commit().map(|()| DOMAIN_MAX_LEVEL)
    }

    #[instrument(
        level = "info",
        skip(self, eventid),
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn handle_domain_remigrate(
        &self,
        level: Option<u32>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let level = level.unwrap_or(DOMAIN_MIN_REMIGRATION_LEVEL);
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await;

        idms_prox_write.qs_write.domain_remigrate(level)?;

        idms_prox_write.commit()
    }
}

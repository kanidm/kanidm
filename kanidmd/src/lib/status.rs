use crate::audit::AuditScope;
use actix::prelude::*;
use crossbeam::channel::Sender;
use uuid::Uuid;

pub struct StatusActor {
    log_tx: Sender<Option<AuditScope>>,
    log_level: Option<u32>,
}

impl StatusActor {
    pub fn start(
        log_tx: Sender<Option<AuditScope>>,
        log_level: Option<u32>,
    ) -> actix::Addr<StatusActor> {
        SyncArbiter::start(1, move || StatusActor {
            log_tx: log_tx.clone(),
            log_level,
        })
    }
}

impl Actor for StatusActor {
    type Context = SyncContext<Self>;
}

pub struct StatusRequestEvent {
    pub eventid: Uuid,
}

impl Message for StatusRequestEvent {
    type Result = bool;
}

impl Handler<StatusRequestEvent> for StatusActor {
    type Result = bool;

    fn handle(&mut self, event: StatusRequestEvent, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let mut audit = AuditScope::new(
            "status_handler",
            event.eventid.clone(),
            self.log_level.clone(),
        );
        ladmin_info!(&mut audit, "status handler");
        self.log_tx.send(Some(audit)).unwrap_or_else(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
        });
        true
    }
}

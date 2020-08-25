use crate::audit::AuditScope;
use actix::prelude::*;
use tokio::sync::mpsc::UnboundedSender as Sender;
use uuid::Uuid;

pub struct StatusRequestEvent {
    pub eventid: Uuid,
}

pub struct StatusActor {
    log_tx: Sender<AuditScope>,
    log_level: Option<u32>,
}

impl StatusActor {
    pub fn start(
        log_tx: Sender<AuditScope>,
        log_level: Option<u32>,
    ) -> &'static Self {

        let x = Box::new(StatusActor {
            log_tx: log_tx.clone(),
            log_level,
        });

        let x_ptr = Box::into_raw(x);
        unsafe {
            &(*x_ptr)
        }
    }

    pub async fn handle_request(&self,
        event: StatusRequestEvent
    ) -> bool {
        let mut audit = AuditScope::new("status_handler", event.eventid, self.log_level);
        ladmin_info!(&mut audit, "status handler complete");
        self.log_tx.send(audit).unwrap_or_else(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
        });
        true
    }
}

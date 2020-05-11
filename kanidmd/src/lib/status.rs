use crate::async_log::{EventLog, LogEvent};
use actix::prelude::*;

pub struct StatusActor {
    log_addr: actix::Addr<EventLog>,
}

impl StatusActor {
    pub fn start(log_addr: actix::Addr<EventLog>) -> actix::Addr<StatusActor> {
        SyncArbiter::start(1, move || StatusActor {
            log_addr: log_addr.clone(),
        })
    }
}

impl Actor for StatusActor {
    type Context = SyncContext<Self>;
}

pub struct StatusRequestEvent {}

impl Message for StatusRequestEvent {
    type Result = bool;
}

impl Handler<StatusRequestEvent> for StatusActor {
    type Result = bool;

    fn handle(&mut self, _event: StatusRequestEvent, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.log_addr.do_send(LogEvent {
            msg: "status request event: ok".to_string(),
        });
        true
    }
}

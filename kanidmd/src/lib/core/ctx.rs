use crate::audit::AuditScope;
use actix::prelude::*;
use crossbeam::channel::Sender;
use std::thread;

pub struct ServerCtx {
    system: System,
    log_tx: Sender<Option<AuditScope>>,
    log_thread: thread::JoinHandle<()>,
}

impl ServerCtx {
    pub fn new(
        system: System,
        log_tx: Sender<Option<AuditScope>>,
        log_thread: thread::JoinHandle<()>,
    ) -> Self {
        ServerCtx {
            system,
            log_tx,
            log_thread,
        }
    }

    pub fn current(&self) -> System {
        self.system.clone()
    }

    pub fn stop(self) {
        // stop the actix system
        self.system.stop();
        // drain the log thread
        self.log_tx
            .send(None)
            .expect("unable to shutdown log thread!");
        self.log_thread.join().expect("failed to stop log thread");
    }
}

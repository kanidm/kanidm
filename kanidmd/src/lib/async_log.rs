use crate::audit::AuditScope;
use crossbeam::channel::Receiver;

pub fn run(rx: &Receiver<Option<AuditScope>>) {
    info!("Log thread started ...");
    loop {
        match rx.recv() {
            Ok(Some(al)) => {
                al.write_log();
            }
            Ok(None) => {
                // Prep to shutdown, finish draining.
                break;
            }
            Err(_) => {
                // we're cooked.
                error!("CRITICAL: log thread is cooked.");
            }
        }
    }

    loop {
        match rx.try_recv() {
            Ok(Some(al)) => {
                al.write_log();
            }
            Ok(None) => {
                // Skip this, it's a shutdown msg.
            }
            Err(_) => {
                // we've drained.
                break;
            }
        }
    }
    info!("Log thread shutdown complete.");
}

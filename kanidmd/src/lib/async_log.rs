use crate::audit::AuditScope;
use tokio::sync::mpsc::UnboundedReceiver as Receiver;

pub(crate) async fn run(mut rx: Receiver<AuditScope>) {
    info!("Log task started ...");
    loop {
        match rx.recv().await {
            Some(al) => {
                al.write_log();
            }
            None => {
                // Prep to shutdown, finish draining.
                break;
            }
        }
    }

    info!("Log thread shutdown complete.");
}

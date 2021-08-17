use crate::audit::AuditScope;
use tokio::sync::mpsc::UnboundedReceiver as Receiver;

pub(crate) async fn run(mut rx: Receiver<AuditScope>) {
    info!("Log task started ...");
    while let Some(al) = rx.recv().await {
        al.write_log();
    }
    info!("Log task shutdown complete.");
}

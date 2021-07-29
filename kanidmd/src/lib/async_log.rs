use crate::audit::AuditScope;
use tokio::sync::mpsc::UnboundedReceiver as Receiver;

use crate::tracing_tree::{KanidmEventTag, TreeProcessor};
use tracing::info;

pub(crate) async fn run(mut rx: Receiver<AuditScope>) {
    info!("Log task started ...");
    while let Some(al) = rx.recv().await {
        al.write_log();
    }
    info!("Log task shutdown complete.");
}

pub(crate) async fn run_tracing_tree(mut rx: Receiver<TreeProcessor<KanidmEventTag>>) {
    // We can't log here because it will just get sent here and we have recursion oops
    while let Some(processor) = rx.recv().await {
        processor.process().expect("Failed writing");
    }
}

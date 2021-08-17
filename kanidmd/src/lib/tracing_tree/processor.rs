use super::TreePreProcessed;
use tokio::sync::mpsc::UnboundedSender;

pub trait Processor: 'static {
    fn process(&self, preprocessed: TreePreProcessed);
}

pub struct ExportProcessor {
    sender: UnboundedSender<TreePreProcessed>,
}

pub struct TestProcessor {}

impl ExportProcessor {
    pub fn with_sender(sender: UnboundedSender<TreePreProcessed>) -> Self {
        ExportProcessor { sender }
    }
}

impl Processor for ExportProcessor {
    fn process(&self, preprocessed: TreePreProcessed) {
        self.sender
            .send(preprocessed)
            .expect("Processing channel has been closed, cannot log events.");
    }
}

impl Processor for TestProcessor {
    fn process(&self, preprocessed: TreePreProcessed) {
        preprocessed.process().expect("Failed to write logs");
    }
}

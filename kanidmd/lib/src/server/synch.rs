use crate::prelude::*;
use super::QueryServerWriteTransaction;

pub struct SynchEvent {
}


impl<'a> QueryServerWriteTransaction<'a> {
    #[instrument(level = "debug", skip_all)]
    pub fn synch(&mut self, _se: &SynchEvent) -> Result<(), OperationError> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[qs_test]
    async fn test_synch_basic(_server: &QueryServer) {
        todo!()
    }
}

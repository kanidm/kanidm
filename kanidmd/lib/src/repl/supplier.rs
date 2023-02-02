use super::proto::ReplRefreshContext;
use crate::prelude::*;

impl<'a> QueryServerReadTransaction<'a> {
    // Given a consumers state, calculate the differential of changes they
    // need to be sent to bring them to the equivalent state.

    // We use the RUV or Cookie to determine if:
    // * The consumer requires a full-reinit.
    // * Which entry attr-states need to be sent, if any

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_provide_changes(&mut self) -> Result<(), OperationError> {
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_provide_refresh(&mut self) -> Result<ReplRefreshContext, OperationError> {
        // A refresh must provide
        //
        // * the current domain version
        let domain_version = self.d_info.d_vers;
        let domain_uuid = self.d_info.d_uuid;

        // * the domain uuid
        // * the set of schema entries
        // * the set of non-schema entries
        // - We must exclude certain entries and attributes!
        //   * schema defines what we exclude!

        let schema_entries = Vec::default();
        let meta_entries = Vec::default();
        let entries = Vec::default();

        Ok(ReplRefreshContext {
            domain_version,
            domain_uuid,
            schema_entries,
            meta_entries,
            entries,
        })
    }
}

use super::proto::{ReplEntryV1, ReplIncrementalContext, ReplRefreshContext, ReplRuvRange};
use super::ruv::{
    ReplicationUpdateVector,
    ReplicationUpdateVectorTransaction,

};
use crate::be::BackendTransaction;
use crate::prelude::*;

impl<'a> QueryServerReadTransaction<'a> {
    // Given a consumers state, calculate the differential of changes they
    // need to be sent to bring them to the equivalent state.

    // We use the RUV or Cookie to determine if:
    // * The consumer requires a full-reinit.
    // * Which entry attr-states need to be sent, if any

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_provide_changes(
        &mut self,
        ctx_ruv: ReplRuvRange,
    ) -> Result<ReplIncrementalContext, OperationError> {
        // Convert types if needed. This way we can compare ruv's correctly.
        let ctx_ranges = match ctx_ruv {
            ReplRuvRange::V1 { ranges } => ranges,
        };

        let our_ranges = self
            .get_be_txn()
            .get_ruv()
            .current_ruv_range()
            .map_err(|e| {
                error!(err = ?e, "Unable to access supplier RUV range");
                e
            })?;

        // Compare this to our internal ranges - work out the list of entry
        // id's that are now different.

        let supply_ranges = ReplicationUpdateVector::range_diff(&ctx_ranges, &our_ranges);

        // If empty, return an empty set of changes!

        match supply_ranges {
            Ok(ranges) => {
            }
            Err(ranges) => {
                
            }
        }

        // From the set of change id's, fetch those entries.

        // Seperate the entries into schema, meta and remaining.

        // For each entry, determine the changes that exist on the entry that fall
        // into the ruv range - reduce to a incremental set of changes.

        // Build the incremental context.

        todo!();
    }

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_provide_refresh(&mut self) -> Result<ReplRefreshContext, OperationError> {
        // Get the current schema. We use this for attribute and entry filtering.
        let schema = self.get_schema();

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

        let schema_filter = filter!(f_or!([
            f_eq("class", PVCLASS_ATTRIBUTETYPE.clone()),
            f_eq("class", PVCLASS_CLASSTYPE.clone()),
        ]));

        let meta_filter = filter!(f_or!([
            f_eq("uuid", PVUUID_DOMAIN_INFO.clone()),
            f_eq("uuid", PVUUID_SYSTEM_INFO.clone()),
            f_eq("uuid", PVUUID_SYSTEM_CONFIG.clone()),
        ]));

        let entry_filter = filter!(f_and!([
            f_pres("class"),
            f_andnot(f_or(vec![
                // These are from above!
                f_eq("class", PVCLASS_ATTRIBUTETYPE.clone()),
                f_eq("class", PVCLASS_CLASSTYPE.clone()),
                f_eq("uuid", PVUUID_DOMAIN_INFO.clone()),
                f_eq("uuid", PVUUID_SYSTEM_INFO.clone()),
                f_eq("uuid", PVUUID_SYSTEM_CONFIG.clone()),
            ])),
        ]));

        let schema_entries = self
            .internal_search(schema_filter)
            .map(|ent| {
                ent.into_iter()
                    .map(|e| ReplEntryV1::new(e.as_ref(), schema))
                    .collect()
            })
            .map_err(|e| {
                error!("Failed to access schema entries");
                e
            })?;

        let meta_entries = self
            .internal_search(meta_filter)
            .map(|ent| {
                ent.into_iter()
                    .map(|e| ReplEntryV1::new(e.as_ref(), schema))
                    .collect()
            })
            .map_err(|e| {
                error!("Failed to access meta entries");
                e
            })?;

        let entries = self
            .internal_search(entry_filter)
            .map(|ent| {
                ent.into_iter()
                    .map(|e| ReplEntryV1::new(e.as_ref(), schema))
                    .collect()
            })
            .map_err(|e| {
                error!("Failed to access entries");
                e
            })?;

        Ok(ReplRefreshContext::V1 {
            domain_version,
            domain_uuid,
            schema_entries,
            meta_entries,
            entries,
        })
    }
}

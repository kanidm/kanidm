use super::proto::{
    ReplEntryV1, ReplIncrementalContext, ReplIncrementalEntryV1, ReplRefreshContext, ReplRuvRange,
};
use super::ruv::{RangeDiffStatus, ReplicationUpdateVector, ReplicationUpdateVectorTransaction};
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

        let ranges = match supply_ranges {
            RangeDiffStatus::Ok(ranges) => ranges,
            RangeDiffStatus::Refresh { lag_range } => {
                error!("Replication - Consumer is lagging and must be refreshed.");
                debug!(?lag_range);
                return Ok(ReplIncrementalContext::RefreshRequired);
            }
            RangeDiffStatus::Unwilling { adv_range } => {
                error!("Replication - Supplier is lagging and must be investigated.");
                debug!(?adv_range);
                return Ok(ReplIncrementalContext::UnwillingToSupply);
            }
            RangeDiffStatus::Critical {
                lag_range,
                adv_range,
            } => {
                error!("Replication Critical - Servers are advanced of us, and also lagging! This must be immediately investigated!");
                debug!(?lag_range);
                debug!(?adv_range);
                return Ok(ReplIncrementalContext::UnwillingToSupply);
            }
        };

        debug!(?ranges, "these ranges will be supplied");

        if ranges.is_empty() {
            return Ok(ReplIncrementalContext::NoChangesAvailable);
        }

        // From the set of change id's, fetch those entries.
        // This is done by supplying the ranges to the be which extracts
        // the entries affected by the idls in question.
        let entries = self.get_be_txn().retrieve_range(&ranges).map_err(|e| {
            admin_error!(?e, "backend failure");
            OperationError::Backend
        })?;

        // Separate the entries into schema, meta and remaining.
        let (schema_entries, rem_entries): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| {
            e.get_ava_set(Attribute::Class)
                .map(|cls| {
                    cls.contains(&EntryClass::AttributeType.into() as &PartialValue)
                        || cls.contains(&EntryClass::ClassType.into() as &PartialValue)
                })
                .unwrap_or(false)
        });

        let (meta_entries, entries): (Vec<_>, Vec<_>) = rem_entries.into_iter().partition(|e| {
            e.get_ava_set(Attribute::Uuid)
                .map(|uset| {
                    uset.contains(&PVUUID_DOMAIN_INFO as &PartialValue)
                        || uset.contains(&PVUUID_SYSTEM_INFO as &PartialValue)
                        || uset.contains(&PVUUID_SYSTEM_CONFIG as &PartialValue)
                })
                .unwrap_or(false)
        });

        trace!(?schema_entries);
        trace!(?meta_entries);
        trace!(?entries);

        // For each entry, determine the changes that exist on the entry that fall
        // into the ruv range - reduce to a incremental set of changes.

        let schema = self.get_schema();
        let domain_version = self.d_info.d_vers;
        let domain_uuid = self.d_info.d_uuid;

        let schema_entries: Vec<_> = schema_entries
            .into_iter()
            .map(|e| ReplIncrementalEntryV1::new(e.as_ref(), schema, &ranges))
            .collect();

        let meta_entries: Vec<_> = meta_entries
            .into_iter()
            .map(|e| ReplIncrementalEntryV1::new(e.as_ref(), schema, &ranges))
            .collect();

        let entries: Vec<_> = entries
            .into_iter()
            .map(|e| ReplIncrementalEntryV1::new(e.as_ref(), schema, &ranges))
            .collect();

        // Build the incremental context.

        Ok(ReplIncrementalContext::V1 {
            domain_version,
            domain_uuid,
            ranges,
            schema_entries,
            meta_entries,
            entries,
        })
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

        // What is the set of data we are providing?
        let ranges = self
            .get_be_txn()
            .get_ruv()
            .current_ruv_range()
            .map_err(|e| {
                error!(err = ?e, "Unable to access supplier RUV range");
                e
            })?;

        // * the domain uuid
        // * the set of schema entries
        // * the set of non-schema entries
        // - We must exclude certain entries and attributes!
        //   * schema defines what we exclude!

        let schema_filter = filter!(f_or!([
            f_eq(Attribute::Class, EntryClass::AttributeType.into()),
            f_eq(Attribute::Class, EntryClass::ClassType.into()),
        ]));

        let meta_filter = filter!(f_or!([
            f_eq(Attribute::Uuid, PVUUID_DOMAIN_INFO.clone()),
            f_eq(Attribute::Uuid, PVUUID_SYSTEM_INFO.clone()),
            f_eq(Attribute::Uuid, PVUUID_SYSTEM_CONFIG.clone()),
        ]));

        let entry_filter = filter_all!(f_or!([
            f_and!([
                f_pres(Attribute::Class),
                f_andnot(f_or(vec![
                    // These are from above!
                    f_eq(Attribute::Class, EntryClass::AttributeType.into()),
                    f_eq(Attribute::Class, EntryClass::ClassType.into()),
                    f_eq(Attribute::Uuid, PVUUID_DOMAIN_INFO.clone()),
                    f_eq(Attribute::Uuid, PVUUID_SYSTEM_INFO.clone()),
                    f_eq(Attribute::Uuid, PVUUID_SYSTEM_CONFIG.clone()),
                ])),
            ]),
            f_eq(Attribute::Class, EntryClass::Tombstone.into()),
            f_eq(Attribute::Class, EntryClass::Recycled.into()),
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
            ranges,
            schema_entries,
            meta_entries,
            entries,
        })
    }
}

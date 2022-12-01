use super::QueryServerWriteTransaction;
use crate::idm::scim::ScimSyncUpdateEvent;
use crate::prelude::*;
use kanidm_proto::scim_v1::ScimEntry;
use std::collections::BTreeMap;

impl<'a> QueryServerWriteTransaction<'a> {
    /// The purpose of this phase of the synchronisation is to ensure that all entries
    /// that we are going to manipulate exist and have current and up to date external id
    /// references attached, if any.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn scim_sync_apply_phase_2(
        &mut self,
        _sse: &ScimSyncUpdateEvent,
        change_entries: &BTreeMap<Uuid, &ScimEntry>,
        sync_uuid: Uuid,
    ) -> Result<(), OperationError> {
        // First, search for all uuids present in the change set.

        let filter_or = change_entries
            .keys()
            .copied()
            .map(|u| f_eq("uuid", PartialValue::new_uuid(u)))
            .collect();

        // NOTE: We bypass recycled/ts here because we WANT to know if we are in that
        // state so we can AVOID updates to these entries!
        let existing_entries = self
            .internal_search(filter_all!(f_or(filter_or)))
            .map_err(|e| {
                error!("Failed to determine existing entries set");
                e
            })?;

        // Refuse to proceed if any entries are in the recycled or tombstone state, since subsequent
        // operations WOULD fail.
        //
        // I'm still a bit not sure what to do here though, because if we have uuid re-use from the
        // external system, that would be a pain, but I think we have to do this. This would be an
        // exceedingly rare situation though since 389-ds doesn't allow external uuid to be set, nor
        // does openldap. It would break both of their replication models for it to occur.
        //
        // Still we cover the possibility
        let mut fail = false;
        existing_entries.iter().for_each(|e| {
            if e.mask_recycled_ts().is_none() {
                error!("Unable to proceed: entry uuid {} is masked. You must re-map this entries uuid in the sync connector to proceed.", e.get_uuid());
                fail = true;
            }
        });
        if fail {
            return Err(OperationError::InvalidEntryState);
        }
        // From that set of entries, parition to entries that exist and are
        // present, and entries that do not yet exist.
        //
        // We can't easily parititon here because we need to iterate over the
        // existing entry set to work out what we need, so what we do is copy
        // the change_entries set, then remove what we already have.
        let mut missing_scim = change_entries.clone();
        existing_entries.iter().for_each(|entry| {
            missing_scim.remove(&entry.get_uuid());
        });

        // For entries that do not exist, create stub entries. We don't create the external ID here
        // yet, because we need to ensure that it's unique.
        let create_stubs: Vec<EntryInitNew> = missing_scim
            .keys()
            .copied()
            .map(|u| {
                entry_init!(
                    ("class", Value::new_class("object")),
                    ("class", Value::new_class("sync_object")),
                    ("sync_parent_uuid", Value::new_refer(sync_uuid)),
                    ("uuid", Value::new_uuid(u))
                )
            })
            .collect();

        // We use internal create here to ensure that the values of these entries are all setup correctly.
        // We know that uuid won't conflict because it didn't exist in the previous search, so if we error
        // it has to be something bad.
        self.internal_create(create_stubs).map_err(|e| {
            error!("Unable to create stub entries");
            e
        })?;

        // We have to search again now, this way we can do the internal mod process for
        // updating the external_id.
        //
        // For entries that do exist, mod their external_id
        //
        // Basicly we just set this up as a batch modify and submit it.
        self.internal_batch_modify(change_entries.iter().filter_map(|(u, scim_ent)| {
            // If the entry has an external id
            scim_ent.external_id.as_ref().map(|ext_id| {
                // Add it to the mod request.
                (
                    *u,
                    ModifyList::new_purge_and_set("sync_external_id", Value::new_iutf8(ext_id)),
                )
            })
        }))
        .map_err(|e| {
            error!("Unable to setup external ids from sync entries");
            e
        })?;

        // Ready to go.

        Ok(())
    }
}

// Note, tests are in scim.

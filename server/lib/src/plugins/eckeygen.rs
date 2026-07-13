use super::Plugin;
use crate::prelude::*;
use crate::valueset::ValueSetSecret;
use std::sync::Arc;

pub struct EcdhKeyGen {}

impl EcdhKeyGen {
    // we optionally provide a target_cand to update only the entry with the given uuid
    fn generate_key<STATE: Clone>(
        qs: &mut QueryServerWriteTransaction,
        cands: &mut [Entry<EntryInvalid, STATE>],
    ) -> Result<(), OperationError> {
        let domain_level = qs.get_domain_version();
        if domain_level >= DOMAIN_LEVEL_12 {
            trace!("Skipping id key generation");
            return Ok(());
        }

        for cand in cands.iter_mut() {
            if cand.attribute_equality(Attribute::Class, &EntryClass::Person.to_partialvalue())
                && !cand.attribute_pres(Attribute::IdVerificationEcKey)
            {
                debug!(
                    "Generating {} for {}",
                    Attribute::IdVerificationEcKey,
                    cand.get_display_id()
                );

                cand.set_ava_set(
                    &Attribute::IdVerificationEcKey,
                    ValueSetSecret::new("no-longer-used".into()),
                )
            }
        }
        Ok(())
    }
}

impl Plugin for EcdhKeyGen {
    fn id() -> &'static str {
        "plugin_ecdhkey_gen"
    }

    #[instrument(level = "debug", name = "ecdhkeygen::pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::generate_key(qs, cand)
    }

    #[instrument(level = "debug", name = "ecdhkeygen::pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::generate_key(qs, cand)
    }

    #[instrument(level = "debug", name = "ecdhkeygen::pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::generate_key(qs, cand)
    }
}

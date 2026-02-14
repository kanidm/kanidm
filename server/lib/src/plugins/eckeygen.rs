use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;

use crate::prelude::*;
use std::sync::Arc;

use super::Plugin;

// it contains all the partialvalues used to match against an Entry's class,
// we need ALL partialvalues to match in order to target the entry
static DEFAULT_KEY_GROUP: LazyLock<EcGroup> = LazyLock::new(|| {
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    #[allow(clippy::unwrap_used)]
    EcGroup::from_curve_name(nid).unwrap()
});

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

                let new_private_key = EcKey::generate(&DEFAULT_KEY_GROUP).map_err(|e| {
                    error!(err = ?e, "Unable to generate id verification ECDH private key");
                    OperationError::CryptographyError
                })?;
                cand.add_ava_if_not_exist(
                    Attribute::IdVerificationEcKey,
                    crate::value::Value::EcKeyPrivate(new_private_key),
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

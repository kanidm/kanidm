use crate::plugins::Plugin;
use crate::prelude::*;
use std::sync::Arc;

pub struct KeyObjectManagement {}

impl Plugin for KeyObjectManagement {
    fn id() -> &'static str {
        "plugin_keyobject_management"
    }

    #[instrument(
        level = "debug",
        name = "keyobject_management::pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::apply_keyobject_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "keyobject_management::pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::apply_keyobject_inner(qs, cand)
    }

    #[instrument(
        level = "debug",
        name = "keyobject_management::pre_batch_modify",
        skip_all
    )]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::apply_keyobject_inner(qs, cand)
    }

    /*
    #[instrument(level = "debug", name = "keyobject_management::pre_delete", skip_all)]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntrySealed
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }
    */

    #[instrument(level = "debug", name = "keyobject_management::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Every key object must have at least one concrete provided key type.
        Vec::default()
    }
}

impl KeyObjectManagement {
    fn apply_keyobject_inner<T: Clone>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        // Valid from right meow!
        let valid_from = qs.get_curtime();

        let key_providers = qs.get_key_providers_mut();

        cand.iter_mut()
            .filter(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
            })
            .try_for_each(|entry| {
                // The entry should not have set any type of KeyObject at this point.
                // Should we force delete those attrs here just incase?
                entry.remove_ava(Attribute::Class, &EntryClass::KeyObjectInternal.into());

                // Must be set by now.
                let key_object_uuid = entry
                    .get_uuid()
                    .ok_or(OperationError::KP0008KeyObjectMissingUuid)?;

                trace!(?key_object_uuid, "Setting up key object");

                // Get the default provider, and create a new ephemeral key object
                // inside it. If the object existed already, we clone it so that we can stage
                // our changes.
                let mut key_object = key_providers.get_or_create_in_default(key_object_uuid)?;

                // If revoke. This weird looking let dance is to ensure that the inner hexstring set
                // lives long enough.
                let maybe_revoked = entry.pop_ava(Attribute::KeyActionRevoke);
                if let Some(revoke_keys) =
                    maybe_revoked.as_ref().and_then(|vs| vs.as_hexstring_set())
                {
                    key_object.revoke_keys(revoke_keys)?;
                }

                // Rotation is after revocation, but before assertion. This way if the user
                // asked for rotation and revocation, we don't double rotate when we get to
                // the assert phase. We also only get a rotation time if the time is in the
                // future, to avoid rotating keys in the past.
                if let Some(rotation_time) = entry
                    .pop_ava(Attribute::KeyActionRotate)
                    .and_then(|vs| vs.to_datetime_single())
                    .and_then(|odt| {
                        let secs = odt.unix_timestamp() as u64;
                        if secs > valid_from.as_secs() {
                            Some(Duration::from_secs(secs))
                        } else {
                            None
                        }
                    })
                {
                    key_object.rotate_keys(rotation_time)?;
                }

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtEs256.into())
                {
                    // Assert that this object has a valid es256 key present. Post revoke, it may NOT
                    // be present. This differs to rotate, in that the assert verifes we have at least
                    // *one* key that is valid from right now.
                    trace!(?key_object_uuid, "Adding es256 to key object");
                    key_object.jws_es256_assert(valid_from)?;
                }

                // Turn that object into it's entry template to create. I think we need to make this
                // some kind of merge_vs?
                key_object.into_valuesets()?.into_iter().try_for_each(
                    |(attribute, valueset)| entry.merge_ava_set(attribute, valueset),
                )?;

                Ok(())
            })
    }
}

// Unlike other plugins, tests for this plugin will be located in server/lib/src/server/keys.
//
// The reason is because we can preconfigure different providers to test these paths in future.

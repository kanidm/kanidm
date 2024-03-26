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
                // inside it. If the object existed already, we clone it.
                let mut key_object = key_providers.get_or_create_in_default(key_object_uuid)?;

                // If rotate.
                //    if key type ...

                // If revoke.
                //    locate the key and revoke it.

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtEs256.into())
                {
                    // If has valid es 256
                    trace!(?key_object_uuid, "Adding es256 to key object");
                    key_object.jws_es256_generate(valid_from)?;
                }

                // Turn that object into it's entry template to create. I think we need to make this
                // some kind of merge_vs?
                key_object.into_valuesets().try_for_each(|maybe_valueset| {
                    // If an error occured during the conversion into a valueset,
                    // it will be bubbled up here.
                    maybe_valueset
                        .and_then(|(attribute, valueset)| entry.merge_ava_set(attribute, valueset))
                })?;

                Ok(())
            })
    }
}

// Unlike other plugins, tests for this plugin will be located in server/lib/src/server/keys.
//
// The reason is because we can preconfigure different providers to test these paths in future.

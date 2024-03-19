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
        let key_providers = qs.get_key_providers();
        // Valid from right meow!
        let valid_from = qs.get_curtime();

        let key_objects_to_create = cand
            .iter_mut()
            .filter(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
            })
            .map(|entry| {
                // The entry should not have set any type of KeyObject at this point.
                // Should we force delete those attrs here just incase?
                entry.remove_ava(Attribute::Class, &EntryClass::KeyObjectInternal.into());

                // Must be set by now.
                let key_object_uuid = entry
                    .get_uuid()
                    .ok_or(OperationError::KP0008KeyObjectMissingUuid)?;

                // Get the default provider, and create a new ephemeral key object
                // inside it.
                let mut key_object = key_providers
                    .get_default()?
                    .create_new_key_object(key_object_uuid)?;

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtEs256.into())
                {
                    key_object.jwt_es256_generate(valid_from)?;
                }

                // Turn that object into it's entry template to create
                key_object.into_entry_new()
            })
            .collect::<Result<Vec<_>, _>>()?;

        if !key_objects_to_create.is_empty() {
            qs.internal_create(key_objects_to_create)?;
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "keyobject_management::pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    #[instrument(
        level = "debug",
        name = "keyobject_management::pre_batch_modify",
        skip_all
    )]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(())
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

// Unlike other plugins, tests for this plugin will be located in server/lib/src/server/keys.
//
// The reason is because we can preconfigure different providers to test these paths in future.

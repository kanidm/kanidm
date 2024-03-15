use super::KeyId;
use crate::prelude::*;

use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;

use compact_jwt::{JwsEs256Signer, JwsEs256Verifier};

pub struct KeyProviderInternal {
    uuid: Uuid,
    name: String,
}

impl KeyProviderInternal {
    pub(super) fn try_from(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Classes already checked.
        let name = value
            .get_ava_single_iname(Attribute::Name)
            .ok_or_else(|| {
                error!("Missing {}", Attribute::Name);
                OperationError::KP0004KeyProviderMissingAttributeName
            })?
            .to_string();

        let uuid = value.get_uuid();

        Ok(KeyProviderInternal { uuid, name })
    }

    pub(crate) fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) fn test(&self) -> Result<(), OperationError> {
        // Are there crypto operations we should test?

        Ok(())
    }
}

#[cfg(test)]
impl KeyProviderInternal {
    fn create_test_provider() -> Self {
        KeyProviderInternal {
            uuid: UUID_KEY_PROVIDER_INTERNAL,
            name: "key_provider_internal".to_string(),
        }
    }
}

pub enum KeyObjectInternalStatus {
    Valid {
        private_der: Vec<u8>,
        from: OffsetDateTime,
    },
    // A special form of valid, where only the public key is retained for verification
    // Retained {
    //     from: OffsetDateTime
    // },
    Revoked {
        at: OffsetDateTime,
    },
}

pub enum VSKeyObjectInternal {
    JwtES256 {
        status: KeyObjectInternalStatus,
        public_der: Vec<u8>,
        key_id: KeyId,
    },
}

// To move elsewhere, probably valueSet
pub struct ValueSetKeyObjectInternal {
    objects: BTreeMap<KeyId, VSKeyObjectInternal>,
}

pub struct KeyObjectInternal {
    provider: Arc<KeyProviderInternal>,
    uuid: Uuid,
}

pub struct KeyObjectInternalJwtEs256 {
    object: KeyObjectInternal,

    // The active signing key
    jwt_es256: JwsEs256Signer,
    // All current trust keys that can validate a signature.
    //
    // NOTE: The active signing key is reflected in this set!
    jwt_es256_valid: BTreeMap<KeyId, JwsEs256Verifier>,
}

impl KeyObjectInternalJwtEs256 {
    pub fn new(provider: Arc<KeyProviderInternal>, uuid: Uuid) -> Result<Self, OperationError> {
        // Generate a new key.
        let jwt_es256 = JwsEs256Signer::generate_es256().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to generate new jwt es256 signing key");
            OperationError::KP0006KeyObjectJwtEs256Generation
        })?;

        Ok(KeyObjectInternalJwtEs256 {
            object: KeyObjectInternal { provider, uuid },
            jwt_es256,
            jwt_es256_valid: BTreeMap::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[qs_test]
    async fn test_key_object_internal_es256(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await;

        // Assert the default provider is the internal one.
        let default_key_provider = write_txn
            .get_key_providers()
            .get_default()
            .expect("Unable to access default key provider object.");

        assert_eq!(default_key_provider.uuid(), UUID_KEY_PROVIDER_INTERNAL);

        // Create a new key object
        let key_object_uuid = Uuid::new_v4();

        write_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::KeyObject.to_value()),
                // Signal we want a jwt es256
                (Attribute::Class, EntryClass::KeyObjectJwtEs256.to_value()),
                (Attribute::Uuid, Value::Uuid(key_object_uuid))
            )])
            .expect("Unable to create new key object");

        // Reload to trigger the key object to reload.
        write_txn.reload().expect("Unable to reload transaction");

        // Get the key object entry.

        let key_object_entry = write_txn
            .internal_search_uuid(key_object_uuid)
            .expect("Unable to retrieve key object by uuid");

        // Check that the es256 is now present.
        assert!(key_object_entry.attribute_pres(Attribute::KeyInternalJwtEs256));

        // Now check the object was loaded.

        let key_object_loaded = write_txn
            .get_key_providers()
            .get_key_object(key_object_uuid)
            .expect("Unable to retrieve key object by uuid");

        // Check the key works, and has es256.

        write_txn.commit().expect("Failed to commit");
    }
}

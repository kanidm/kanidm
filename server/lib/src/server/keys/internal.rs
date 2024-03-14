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

    #[test]
    fn test_key_object_internal_basic() {
        /*
         * Here we have to test a bit of a fun chicken and egg scenario. Imagine we have our domain
         * entry. It has no associated key object. So we need to create the key object *and* it's
         * keys in a single transaction.
         *
         * However to create cryptographic material we need the key object in place with valid ID's
         * else in the future how will pkcs11 work? (in addition, we need to handle roll-backs
         * in those cases too). We need to create the keys in the provider/object and then have
         * a way to export them back to database form.
         *
         * (Later we need to also find orphan pkcs11 objects and prune them too ...)
         *
         * But we also have to be able to take the database form into the object during a reload.
         * But we can't create the database form without the object being loaded.
         *
         * This creates this wonderful problem where we have to have the object existing so we
         * can make keys for the database, but we need the database entries to make the object.
         *
         * To solve this, we have to think about the user interface. The user can:
         * - Revoke a key by it's KeyId
         * - Retire a key by it's KeyId
         * - Inspect the DB content without revealing the keys.
         *
         * Since none of these directly allow the user to create, import or view keys, we can use
         * this to our advantage. Create/Delete of all objects ends up being an internal only
         * operation, and the database is just a reflection of the state that the user can inspect
         * and request a limited set of deletes via.
         *
         * Because of this, this means that internal to the DB, the domain entries/objects can
         * directly interact with the key provider and object level operations, and then these
         * are reflected into the database.
         *
         */

        // Get the internal provider.
        let provider = Arc::new(KeyProviderInternal::create_test_provider());

        // Create a jwt es256 key object
        let key_uuid = Uuid::new_v4();
        let key_object = KeyObjectInternalJwtEs256::new(provider.clone(), key_uuid)
            .expect("Unable to create new jwt es256 object");
        // Turn the key_object to an entry.

        // Now load it back from an entry.

        // Compare they are the same.

        // I think in the domain plugin or oauth2 etc, we check for the key object in the provider,
        // if it's there we can do operations, else we have to create it with our default params.

        todo!();
    }
}

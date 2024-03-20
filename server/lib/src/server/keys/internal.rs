use super::object::KeyObject;
use super::KeyId;
use crate::prelude::*;

use std::collections::BTreeMap;
use std::sync::Arc;

use compact_jwt::{JwsEs256Signer, JwsEs256Verifier, JwsSigner, JwsSignerToVerifier};

use crate::value::{KeyInternalStatus, KeyUsage};
use crate::valueset::{KeyInternalData, ValueSetKeyInternal};

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

    pub(crate) fn create_new_key_object(
        &self,
        uuid: Uuid,
        provider: Arc<Self>,
    ) -> Result<Box<dyn KeyObject>, OperationError> {
        Ok(Box::new(KeyObjectInternal {
            provider,
            uuid,
            jwt_es256: None,
        }))
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

enum InternalJwtEs256Status {
    Valid {
        signer: JwsEs256Signer,
        verifier: JwsEs256Verifier,
    },
    Retained {
        verifier: JwsEs256Verifier,
    },
    Revoked {
        untrusted_verifier: JwsEs256Verifier,
    },
}

struct InternalJwtEs256 {
    valid_from: u64,
    der: Vec<u8>,
    status: InternalJwtEs256Status,
}

#[derive(Default)]
struct KeyObjectInternalJwtEs256 {
    // active signing keys are in a BTreeMap indexed by their valid_from
    // time so that we can retrieve the active key.
    //
    // We don't need to worry about manipulating this at runtime, since any expiry
    // event will cause the keyObject to reload, which will reflect to this map.

    // QUESTION: If we're worried about memory this could be an Rc or a
    // KeyId
    active: BTreeMap<u64, JwsEs256Signer>,

    // All keys are stored by their KeyId for fast lookup. Keys internally have a
    // current status which is checked for signature validation.
    all: BTreeMap<KeyId, InternalJwtEs256>,
}

impl KeyObjectInternalJwtEs256 {
    fn new_active(&mut self, valid_from: Duration) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        let signer = JwsEs256Signer::generate_es256().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to generate new jwt es256 signing key");
            OperationError::KP0006KeyObjectJwtEs256Generation
        })?;

        let verifier = signer.get_verifier().map_err(|jwt_error| {
            error!(
                ?jwt_error,
                "Unable to produce jwt es256 verifier from signer"
            );
            OperationError::KP0010KeyObjectSignerToVerifier
        })?;

        let der = signer.private_key_to_der().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to convert signing key to DER");
            OperationError::KP0009KeyObjectPrivateToDer
        })?;

        self.active.insert(valid_from, signer.clone());

        let kid = signer.get_kid().as_bytes().to_vec();

        self.all.insert(
            kid,
            InternalJwtEs256 {
                valid_from,
                der,
                status: InternalJwtEs256Status::Valid { signer, verifier },
            },
        );

        Ok(())
    }

    fn to_key_iter(&self) -> impl Iterator<Item = (KeyId, KeyInternalData)> + '_ {
        self.all.iter().map(|(key_id, internal_jwt)| {
            let usage = KeyUsage::JwtEs256;

            let valid_from = internal_jwt.valid_from;

            let der = internal_jwt.der.clone();

            let status = match &internal_jwt.status {
                InternalJwtEs256Status::Valid { .. } => KeyInternalStatus::Valid,
                InternalJwtEs256Status::Retained { .. } => KeyInternalStatus::Retained,
                InternalJwtEs256Status::Revoked { .. } => KeyInternalStatus::Revoked,
            };

            (
                key_id.clone(),
                KeyInternalData {
                    usage,
                    valid_from,
                    der,
                    status,
                },
            )
        })
    }
}

pub struct KeyObjectInternal {
    provider: Arc<KeyProviderInternal>,
    uuid: Uuid,
    jwt_es256: Option<KeyObjectInternalJwtEs256>,
}

impl KeyObject for KeyObjectInternal {
    fn uuid(&self) -> Uuid {
        self.uuid
    }

    fn jwt_es256_generate(&mut self, valid_from: Duration) -> Result<(), OperationError> {
        let mut koi = self
            .jwt_es256
            .get_or_insert_with(|| KeyObjectInternalJwtEs256::default());
        koi.new_active(valid_from)
    }

    fn update_entry_invalid_new(&self, entry: &mut EntryInvalidNew) -> Result<(), OperationError> {
        entry.add_ava(Attribute::Class, EntryClass::KeyObjectInternal.to_value());
        entry.add_ava(Attribute::KeyProvider, Value::Refer(self.provider.uuid()));

        let key_iter = self
            .jwt_es256
            .iter()
            .flat_map(|jwt_es256| jwt_es256.to_key_iter());

        let key_vs = ValueSetKeyInternal::from_key_iter(key_iter)?;

        // Replace any content with this.
        entry.set_ava_set(Attribute::KeyInternalData, key_vs);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::keys::*;

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
        assert!(key_object_entry.attribute_pres(Attribute::KeyInternalData));

        // Now check the object was loaded.

        let key_object_loaded = write_txn
            .get_key_providers()
            .get_key_object(key_object_uuid)
            .expect("Unable to retrieve key object by uuid");

        // Check the key works, and has es256.

        write_txn.commit().expect("Failed to commit");
    }
}

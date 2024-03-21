use super::object::KeyObject;
use super::KeyId;
use crate::prelude::*;

use std::collections::BTreeMap;
use std::sync::Arc;

use compact_jwt::traits::*;
use compact_jwt::{
    JwaAlg, Jws, JwsCompact, JwsEs256Signer, JwsEs256Verifier, JwsSigner, JwsSignerToVerifier,
};

use std::ops::Bound::{Included, Unbounded};

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
            jws_es256: None,
        }))
    }

    pub(super) fn load_key_object(
        &self,
        entry: &EntrySealedCommitted,
        provider: Arc<Self>,
    ) -> Result<Arc<Box<dyn KeyObject>>, OperationError> {
        let uuid = entry.get_uuid();
        trace!(?uuid, "Loading key object ...");

        let mut jws_es256: Option<KeyObjectInternalJwtEs256> = None;

        if let Some(key_internal_map) = entry
            .get_ava_set(Attribute::KeyInternalData)
            .and_then(|vs| vs.as_key_internal_map())
        {
            for (
                key_id,
                KeyInternalData {
                    usage,
                    status,
                    der,
                    valid_from,
                },
            ) in key_internal_map.iter()
            {
                match usage {
                    KeyUsage::JwtEs256 => {
                        let jws_es256_ref =
                            jws_es256.get_or_insert_with(|| KeyObjectInternalJwtEs256::default());

                        jws_es256_ref.load(key_id, *status, der, *valid_from)?;
                    }
                }
            }
        }

        Ok(Arc::new(Box::new(KeyObjectInternal {
            provider,
            uuid,
            jws_es256,
        })))
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

        let kid = signer.get_kid().to_string();

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

    fn load(
        &mut self,
        id: &str,
        status: KeyInternalStatus,
        der: &[u8],
        valid_from: u64,
    ) -> Result<(), OperationError> {
        let id: KeyId = id.to_string();

        let status = match status {
            KeyInternalStatus::Valid => {
                let signer = JwsEs256Signer::from_es256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load es256 DER signer");
                    OperationError::KP0013KeyObjectJwsEs256DerInvalid
                })?;

                let verifier = signer.get_verifier().map_err(|err| {
                    error!(?err, "Unable to retrieve verifier from signer");
                    OperationError::KP0014KeyObjectSignerToVerifier
                })?;

                self.active.insert(valid_from, signer.clone());

                InternalJwtEs256Status::Valid { signer, verifier }
            }
            KeyInternalStatus::Retained => {
                let verifier = JwsEs256Verifier::from_es256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load es256 DER verifier");
                    OperationError::KP0015KeyObjectJwsEs256DerInvalid
                })?;

                InternalJwtEs256Status::Retained { verifier }
            }
            KeyInternalStatus::Revoked => {
                let untrusted_verifier = JwsEs256Verifier::from_es256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load es256 DER revoked verifier");
                    OperationError::KP0016KeyObjectJwsEs256DerInvalid
                })?;

                InternalJwtEs256Status::Revoked { untrusted_verifier }
            }
        };

        let der = der.to_vec();

        let internal_jwt = InternalJwtEs256 {
            valid_from,
            der,
            status,
        };

        self.all.insert(id, internal_jwt);

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

    fn sign<V: JwsSignable>(
        &self,
        jws: &V,
        current_time: Duration,
    ) -> Result<V::Signed, OperationError> {
        let ct_secs = current_time.as_secs();

        let Some((_key_id, signing_key)) = self
            .active
            .range((Unbounded, Included(ct_secs)))
            .next_back()
        else {
            error!("No signing keys available");
            return Err(OperationError::KP0020KeyObjectNoActiveSigningKeys);
        };

        signing_key.sign(jws).map_err(|jwt_err| {
            error!(?jwt_err, "Unable to sign jws");
            OperationError::KP0021KeyObjectJwsEs256Signature
        })
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, OperationError> {
        let internal_jws = jwsc
            .kid()
            .and_then(|kid| self.all.get(kid))
            .ok_or_else(|| {
                error!("JWS is signed by a key that is not present in this KeyObject");
                OperationError::KP0022KeyObjectJwsNotAssociated
            })?;

        match &internal_jws.status {
            InternalJwtEs256Status::Valid { verifier, .. }
            | InternalJwtEs256Status::Retained { verifier } => {
                verifier.verify(jwsc).map_err(|jwt_err| {
                    error!(?jwt_err, "Failed to verify jws");
                    OperationError::KP0024KeyObjectJwsInvalid
                })
            }
            InternalJwtEs256Status::Revoked { .. } => {
                error!("The key used to sign this JWS has been revoked.");
                Err(OperationError::KP0023KeyObjectJwsKeyRevoked)
            }
        }
    }
}

pub struct KeyObjectInternal {
    provider: Arc<KeyProviderInternal>,
    uuid: Uuid,
    jws_es256: Option<KeyObjectInternalJwtEs256>,
}

impl KeyObject for KeyObjectInternal {
    fn uuid(&self) -> Uuid {
        self.uuid
    }

    fn jws_es256_generate(&mut self, valid_from: Duration) -> Result<(), OperationError> {
        let mut koi = self
            .jws_es256
            .get_or_insert_with(|| KeyObjectInternalJwtEs256::default());
        koi.new_active(valid_from)
    }

    fn jws_es256_sign(
        &self,
        jws: &Jws,
        current_time: Duration,
    ) -> Result<JwsCompact, OperationError> {
        if let Some(jws_es256_object) = &self.jws_es256 {
            jws_es256_object.sign(jws, current_time)
        } else {
            error!(provider_uuid = ?self.uuid, "jwt es256 not available on this provider");
            Err(OperationError::KP0017KeyProviderNoSuchKey)
        }
    }

    fn jws_verify(&self, jwsc: &JwsCompact) -> Result<Jws, OperationError> {
        // Seems weird, but we can match on alg to select the provider.
        let alg = jwsc.alg();

        match alg {
            JwaAlg::ES256 => {
                if let Some(jws_es256_object) = &self.jws_es256 {
                    jws_es256_object.verify(jwsc)
                } else {
                    error!(provider_uuid = ?self.uuid, "jwt es256 not available on this provider");
                    Err(OperationError::KP0018KeyProviderNoSuchKey)
                }
            }
            unsupported_alg => {
                // unsupported rn.
                error!(provider_uuid = ?self.uuid, ?unsupported_alg, "algorithm not available on this provider");
                Err(OperationError::KP0019KeyProviderUnsupportedAlgorithm)
            }
        }
    }

    fn update_entry_invalid_new(&self, entry: &mut EntryInvalidNew) -> Result<(), OperationError> {
        entry.add_ava(Attribute::Class, EntryClass::KeyObjectInternal.to_value());
        entry.add_ava(Attribute::KeyProvider, Value::Refer(self.provider.uuid()));

        let key_iter = self
            .jws_es256
            .iter()
            .flat_map(|jws_es256| jws_es256.to_key_iter());

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
    use compact_jwt::jws::JwsBuilder;

    #[qs_test]
    async fn test_key_object_internal_es256(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await;

        // Assert the default provider is the internal one.
        let default_key_provider = write_txn
            .get_key_providers()
            .get_default()
            .expect("Unable to access default key provider object.");

        assert_eq!(default_key_provider.uuid(), UUID_KEY_PROVIDER_INTERNAL);

        // Create a new key object
        let key_object_uuid = Uuid::new_v4();

        trace!("AAAAAAAAAAAAAAA");

        write_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::KeyObject.to_value()),
                // Signal we want a jwt es256
                (Attribute::Class, EntryClass::KeyObjectJwtEs256.to_value()),
                (Attribute::Uuid, Value::Uuid(key_object_uuid))
            )])
            .expect("Unable to create new key object");

        trace!("BBBBBBBBBBBBBBbb");

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
        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4]).build();

        let jwsc = key_object_loaded
            .jws_es256_sign(&jws, ct)
            .expect("Unable to sign jws");

        assert!(jwsc.get_jwk_pubkey_url().is_none());

        let released = key_object_loaded
            .jws_verify(&jwsc)
            .expect("Unable to validate jws");

        assert_eq!(released.payload(), &[0, 1, 2, 3, 4]);

        // Test rotation of the key

        // Test Key revocation.
        todo!();

        write_txn.commit().expect("Failed to commit");
    }
}

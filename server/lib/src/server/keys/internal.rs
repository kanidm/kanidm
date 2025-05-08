use super::object::{KeyObject, KeyObjectT};
use super::KeyId;
use crate::prelude::*;
use crate::value::{KeyStatus, KeyUsage};
use crate::valueset::{KeyInternalData, ValueSetKeyInternal};
use compact_jwt::compact::{JweAlg, JweCompact, JweEnc};
use compact_jwt::crypto::{
    JweA128GCMEncipher, JweA128KWEncipher, JwsRs256Signer, JwsRs256Verifier,
};
use compact_jwt::jwe::Jwe;
use compact_jwt::traits::*;
use compact_jwt::{
    JwaAlg, Jwk, JwkKeySet, Jws, JwsCompact, JwsEs256Signer, JwsEs256Verifier, JwsSigner,
    JwsSignerToVerifier,
};
use smolset::SmolSet;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Included, Unbounded};
use std::sync::Arc;

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
        &self.name
    }

    pub(crate) fn create_new_key_object(
        &self,
        uuid: Uuid,
        provider: Arc<Self>,
    ) -> Result<KeyObject, OperationError> {
        Ok(Box::new(KeyObjectInternal {
            provider,
            uuid,
            jws_es256: None,
            jwe_a128gcm: None,
            jws_rs256: None,
        }))
    }

    pub(super) fn load_key_object(
        &self,
        entry: &EntrySealedCommitted,
        provider: Arc<Self>,
    ) -> Result<Arc<KeyObject>, OperationError> {
        let uuid = entry.get_uuid();
        debug!(?uuid, "Loading key object ...");

        let mut jws_es256: Option<KeyObjectInternalJwtEs256> = None;
        let mut jws_rs256: Option<KeyObjectInternalJwtRs256> = None;
        let mut jwe_a128gcm: Option<KeyObjectInternalJweA128GCM> = None;

        if let Some(key_internal_map) = entry
            .get_ava_set(Attribute::KeyInternalData)
            .and_then(|vs| vs.as_key_internal_map())
        {
            for (
                key_id,
                KeyInternalData {
                    usage,
                    status,
                    status_cid,
                    der,
                    valid_from,
                },
            ) in key_internal_map.iter()
            {
                trace!(?uuid, ?usage, ?status, ?key_id);
                match usage {
                    KeyUsage::JwsEs256 => {
                        let jws_es256_ref =
                            jws_es256.get_or_insert_with(KeyObjectInternalJwtEs256::default);

                        jws_es256_ref.load(
                            key_id,
                            *status,
                            status_cid.clone(),
                            der,
                            *valid_from,
                        )?;
                    }
                    KeyUsage::JwsRs256 => {
                        let jws_rs256_ref =
                            jws_rs256.get_or_insert_with(KeyObjectInternalJwtRs256::default);

                        jws_rs256_ref.load(
                            key_id,
                            *status,
                            status_cid.clone(),
                            der,
                            *valid_from,
                        )?;
                    }
                    KeyUsage::JweA128GCM => {
                        let jwe_a128gcm_ref =
                            jwe_a128gcm.get_or_insert_with(KeyObjectInternalJweA128GCM::default);

                        jwe_a128gcm_ref.load(
                            key_id,
                            *status,
                            status_cid.clone(),
                            der,
                            *valid_from,
                        )?;
                    }
                }
            }
        }

        Ok(Arc::new(Box::new(KeyObjectInternal {
            provider,
            uuid,
            jws_es256,
            jwe_a128gcm,
            jws_rs256,
        })))
    }

    pub(crate) fn test(&self) -> Result<(), OperationError> {
        // Are there crypto operations we should test or feature requirements
        // we have?
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

#[derive(Clone)]
enum InternalJweA128GCMStatus {
    Valid {
        cipher: JweA128KWEncipher,
        key: Vec<u8>,
    },
    Retained {
        cipher: JweA128KWEncipher,
        key: Vec<u8>,
    },
    Revoked,
}

#[derive(Clone)]
struct InternalJweA128GCM {
    valid_from: u64,
    status: InternalJweA128GCMStatus,
    status_cid: Cid,
}

#[derive(Default, Clone)]
struct KeyObjectInternalJweA128GCM {
    // active signing keys are in a BTreeMap indexed by their valid_from
    // time so that we can retrieve the active key.
    //
    // We don't need to worry about manipulating this at runtime, since any expiry
    // event will cause the keyObject to reload, which will reflect to this map.
    active: BTreeMap<u64, JweA128KWEncipher>,

    // All keys are stored by their KeyId for fast lookup. Only valid or retained
    // keys can be used to decrypt
    all: BTreeMap<KeyId, InternalJweA128GCM>,
}

impl KeyObjectInternalJweA128GCM {
    fn get_valid_cipher(&self, time: Duration) -> Option<&JweA128KWEncipher> {
        let ct_secs = time.as_secs();

        self.active
            .range((Unbounded, Included(ct_secs)))
            .next_back()
            .map(|(_time, cipher)| cipher)
    }

    fn assert_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        if self.get_valid_cipher(valid_from).is_none() {
            // This means there is no active signing key, so we need to create one.
            debug!("no active jwe a128gcm found, creating a new one ...");
            self.new_active(valid_from, cid)
        } else {
            Ok(())
        }
    }

    #[instrument(level = "debug", name = "keyobject::jwe_a128_gcm::new", skip_all)]
    fn new_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        let cipher = JweA128KWEncipher::new().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to generate new jwe a128 encryption key");
            OperationError::KP0035KeyObjectJweA128GCMGeneration
        })?;

        let key = cipher.key_bytes().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to access new jwe a128 encryption key");
            OperationError::KP0036KeyObjectPrivateToBytes
        })?;

        let key = Vec::from(key);

        let kid = cipher.kid().to_string();

        self.active.insert(valid_from, cipher.clone());

        self.all.insert(
            kid,
            InternalJweA128GCM {
                valid_from,
                status: InternalJweA128GCMStatus::Valid { cipher, key },
                status_cid: cid.clone(),
            },
        );

        Ok(())
    }

    fn to_key_iter(&self) -> impl Iterator<Item = (KeyId, KeyInternalData)> + '_ {
        self.all.iter().map(|(key_id, internal_jwe)| {
            let usage = KeyUsage::JweA128GCM;

            let valid_from = internal_jwe.valid_from;
            let status_cid = internal_jwe.status_cid.clone();

            let (status, der) = match &internal_jwe.status {
                InternalJweA128GCMStatus::Valid { cipher: _, key } => {
                    (KeyStatus::Valid, key.clone())
                }
                InternalJweA128GCMStatus::Retained { cipher: _, key } => {
                    (KeyStatus::Retained, key.clone())
                }
                InternalJweA128GCMStatus::Revoked => (KeyStatus::Revoked, Vec::with_capacity(0)),
            };

            (
                key_id.clone(),
                KeyInternalData {
                    usage,
                    valid_from,
                    der,
                    status,
                    status_cid,
                },
            )
        })
    }

    fn revoke(&mut self, revoke_key_id: &KeyId, cid: &Cid) -> Result<bool, OperationError> {
        if let Some(key_to_revoke) = self.all.get_mut(revoke_key_id) {
            key_to_revoke.status = InternalJweA128GCMStatus::Revoked;
            key_to_revoke.status_cid = cid.clone();

            let valid_from = key_to_revoke.valid_from;

            // Remove it from the active set.
            self.active.remove(&valid_from);

            Ok(true)
        } else {
            // We didn't revoke anything
            Ok(false)
        }
    }

    fn load(
        &mut self,
        id: &str,
        status: KeyStatus,
        status_cid: Cid,
        der: &[u8],
        valid_from: u64,
    ) -> Result<(), OperationError> {
        let id: KeyId = id.to_string();

        let status = match status {
            KeyStatus::Valid => {
                let cipher = JweA128KWEncipher::try_from(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load A128GCM retained cipher");
                    OperationError::KP0037KeyObjectImportJweA128GCMInvalid
                })?;

                self.active.insert(valid_from, cipher.clone());

                InternalJweA128GCMStatus::Valid {
                    cipher,
                    key: der.to_vec(),
                }
            }
            KeyStatus::Retained => {
                let cipher = JweA128KWEncipher::try_from(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load A128GCM retained cipher");
                    OperationError::KP0038KeyObjectImportJweA128GCMInvalid
                })?;

                InternalJweA128GCMStatus::Retained {
                    cipher,
                    key: der.to_vec(),
                }
            }
            KeyStatus::Revoked => InternalJweA128GCMStatus::Revoked,
        };

        let internal_jwe = InternalJweA128GCM {
            valid_from,
            status,
            status_cid,
        };

        self.all.insert(id, internal_jwe);

        Ok(())
    }

    fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, OperationError> {
        let internal_jwe = jwec
            .kid()
            .and_then(|kid| {
                debug!(?kid);
                self.all.get(kid)
            })
            .ok_or_else(|| {
                error!("JWE is encrypted by a key that is not present in this KeyObject");
                for pres_kid in self.all.keys() {
                    debug!(?pres_kid);
                }
                OperationError::KP0039KeyObjectJweNotAssociated
            })?;

        match &internal_jwe.status {
            InternalJweA128GCMStatus::Valid { cipher, .. }
            | InternalJweA128GCMStatus::Retained { cipher, .. } => {
                cipher.decipher(jwec).map_err(|jwt_err| {
                    error!(?jwt_err, "Failed to decrypt jwe");
                    OperationError::KP0040KeyObjectJweInvalid
                })
            }
            InternalJweA128GCMStatus::Revoked => {
                error!("The key used to encrypt this JWE has been revoked.");
                Err(OperationError::KP0041KeyObjectJweRevoked)
            }
        }
    }

    fn encipher(&self, jwe: &Jwe, current_time: Duration) -> Result<JweCompact, OperationError> {
        let Some(cipher) = self.get_valid_cipher(current_time) else {
            error!("No encryption keys available. This may indicate that no keys are valid yet!");
            return Err(OperationError::KP0042KeyObjectNoActiveEncryptionKeys);
        };

        cipher.encipher::<JweA128GCMEncipher>(jwe).map_err(|err| {
            error!(?err, "Unable to sign jwe");
            OperationError::KP0043KeyObjectJweA128GCMEncryption
        })
    }
}

#[derive(Clone)]
enum InternalJwtEs256Status {
    Valid {
        // signer: JwsEs256Signer,
        verifier: JwsEs256Verifier,
        private_der: Vec<u8>,
    },
    Retained {
        verifier: JwsEs256Verifier,
        public_der: Vec<u8>,
    },
    Revoked {
        untrusted_verifier: JwsEs256Verifier,
        public_der: Vec<u8>,
    },
}

#[derive(Clone)]
struct InternalJwtEs256 {
    valid_from: u64,
    status: InternalJwtEs256Status,
    status_cid: Cid,
}

#[derive(Default, Clone)]
struct KeyObjectInternalJwtEs256 {
    // active signing keys are in a BTreeMap indexed by their valid_from
    // time so that we can retrieve the active key.
    //
    // We don't need to worry about manipulating this at runtime, since any expiry
    // event will cause the keyObject to reload, which will reflect to this map.
    active: BTreeMap<u64, JwsEs256Signer>,

    // All keys are stored by their KeyId for fast lookup. Keys internally have a
    // current status which is checked for signature validation.
    all: BTreeMap<KeyId, InternalJwtEs256>,
}

impl KeyObjectInternalJwtEs256 {
    fn get_valid_signer(&self, time: Duration) -> Option<&JwsEs256Signer> {
        let ct_secs = time.as_secs();

        self.active
            .range((Unbounded, Included(ct_secs)))
            .next_back()
            .map(|(_time, signer)| signer)
    }

    fn assert_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        if self.get_valid_signer(valid_from).is_none() {
            // This means there is no active signing key, so we need to create one.
            debug!("no active jwt es256 found, creating a new one ...");
            self.new_active(valid_from, cid)
        } else {
            Ok(())
        }
    }

    fn import(
        &mut self,
        import_keys: &SmolSet<[Vec<u8>; 1]>,
        valid_from: Duration,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        for private_der in import_keys {
            let mut signer = JwsEs256Signer::from_es256_der(private_der).map_err(|err| {
                error!(?err, "Unable to load imported es256 DER signer");
                OperationError::KP0028KeyObjectImportJwsEs256DerInvalid
            })?;

            let verifier = signer.get_verifier().map_err(|jwt_error| {
                error!(
                    ?jwt_error,
                    "Unable to produce jwt es256 verifier from signer"
                );
                OperationError::KP0029KeyObjectSignerToVerifier
            })?;

            // We need to use the legacy KID for imported objects
            let kid = signer.get_legacy_kid().to_string();
            debug!(?kid, "imported key");

            // Indicate to the signer we wish to use the legacy kid for this signer.
            signer.set_kid(kid.as_str());

            self.active.insert(valid_from, signer.clone());

            self.all.insert(
                kid,
                InternalJwtEs256 {
                    valid_from,
                    status: InternalJwtEs256Status::Valid {
                        verifier,
                        private_der: private_der.clone(),
                    },
                    status_cid: cid.clone(),
                },
            );
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "keyobject::jws_es256::new", skip_all)]
    fn new_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
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

        let private_der = signer.private_key_to_der().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to convert signing key to DER");
            OperationError::KP0009KeyObjectPrivateToDer
        })?;

        self.active.insert(valid_from, signer.clone());

        let kid = signer.get_kid().to_string();

        self.all.insert(
            kid,
            InternalJwtEs256 {
                valid_from,
                status: InternalJwtEs256Status::Valid {
                    // signer,
                    verifier,
                    private_der,
                },
                status_cid: cid.clone(),
            },
        );

        Ok(())
    }

    fn revoke(&mut self, revoke_key_id: &KeyId, cid: &Cid) -> Result<bool, OperationError> {
        if let Some(key_to_revoke) = self.all.get_mut(revoke_key_id) {
            let untrusted_verifier = match &key_to_revoke.status {
                InternalJwtEs256Status::Valid { verifier, .. }
                | InternalJwtEs256Status::Retained { verifier, .. } => verifier,
                InternalJwtEs256Status::Revoked {
                    untrusted_verifier, ..
                } => untrusted_verifier,
            }
            .clone();

            let public_der = untrusted_verifier
                .public_key_to_der()
                .map_err(|jwt_error| {
                    error!(?jwt_error, "Unable to convert public key to DER");
                    OperationError::KP0027KeyObjectPublicToDer
                })?;

            key_to_revoke.status = InternalJwtEs256Status::Revoked {
                untrusted_verifier,
                public_der,
            };
            key_to_revoke.status_cid = cid.clone();

            let valid_from = key_to_revoke.valid_from;

            // Remove it from the active set.
            self.active.remove(&valid_from);

            Ok(true)
        } else {
            // We didn't revoke anything
            Ok(false)
        }
    }

    fn load(
        &mut self,
        id: &str,
        status: KeyStatus,
        status_cid: Cid,
        der: &[u8],
        valid_from: u64,
    ) -> Result<(), OperationError> {
        let id: KeyId = id.to_string();

        let status = match status {
            KeyStatus::Valid => {
                let mut signer = JwsEs256Signer::from_es256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load es256 DER signer");
                    OperationError::KP0013KeyObjectJwsEs256DerInvalid
                })?;

                // Ensure that the signer has a coherent kid
                signer.set_kid(id.as_str());

                let verifier = signer.get_verifier().map_err(|err| {
                    error!(?err, "Unable to retrieve verifier from signer");
                    OperationError::KP0014KeyObjectSignerToVerifier
                })?;

                self.active.insert(valid_from, signer);

                InternalJwtEs256Status::Valid {
                    // signer,
                    verifier,
                    private_der: der.to_vec(),
                }
            }
            KeyStatus::Retained => {
                let verifier = JwsEs256Verifier::from_es256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load es256 DER verifier");
                    OperationError::KP0015KeyObjectJwsEs256DerInvalid
                })?;

                InternalJwtEs256Status::Retained {
                    verifier,
                    public_der: der.to_vec(),
                }
            }
            KeyStatus::Revoked => {
                let untrusted_verifier = JwsEs256Verifier::from_es256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load es256 DER revoked verifier");
                    OperationError::KP0016KeyObjectJwsEs256DerInvalid
                })?;

                InternalJwtEs256Status::Revoked {
                    untrusted_verifier,
                    public_der: der.to_vec(),
                }
            }
        };

        let internal_jwt = InternalJwtEs256 {
            valid_from,
            status,
            status_cid,
        };

        self.all.insert(id, internal_jwt);

        Ok(())
    }

    fn to_key_iter(&self) -> impl Iterator<Item = (KeyId, KeyInternalData)> + '_ {
        self.all.iter().map(|(key_id, internal_jwt)| {
            let usage = KeyUsage::JwsEs256;

            let valid_from = internal_jwt.valid_from;
            let status_cid = internal_jwt.status_cid.clone();

            let (status, der) = match &internal_jwt.status {
                InternalJwtEs256Status::Valid { private_der, .. } => {
                    (KeyStatus::Valid, private_der.clone())
                }
                InternalJwtEs256Status::Retained { public_der, .. } => {
                    (KeyStatus::Retained, public_der.clone())
                }
                InternalJwtEs256Status::Revoked { public_der, .. } => {
                    (KeyStatus::Revoked, public_der.clone())
                }
            };

            (
                key_id.clone(),
                KeyInternalData {
                    usage,
                    valid_from,
                    der,
                    status,
                    status_cid,
                },
            )
        })
    }

    fn sign<V: JwsSignable>(
        &self,
        jws: &V,
        current_time: Duration,
    ) -> Result<V::Signed, OperationError> {
        let Some(signing_key) = self.get_valid_signer(current_time) else {
            error!("No signing keys available. This may indicate that no keys are valid yet!");
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
            .and_then(|kid| {
                debug!(?kid);
                self.all.get(kid)
            })
            .ok_or_else(|| {
                error!("JWS is signed by a key that is not present in this KeyObject");
                for pres_kid in self.all.keys() {
                    debug!(?pres_kid);
                }
                OperationError::KP0022KeyObjectJwsNotAssociated
            })?;

        match &internal_jws.status {
            InternalJwtEs256Status::Valid { verifier, .. }
            | InternalJwtEs256Status::Retained { verifier, .. } => {
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

    fn public_jwks(&self) -> JwkKeySet {
        // A lot of applications assume the first item in the set is the latest
        // key, so we need to return that first.
        let mut signing_keys: Vec<_> = self.all.iter().collect();

        // Sort by the time they are valid from.
        signing_keys.sort_unstable_by_key(|(_, k)| Reverse(k.valid_from));

        let keys = signing_keys
            .into_iter()
            .filter_map(|(_, es256)| match &es256.status {
                InternalJwtEs256Status::Valid { verifier, .. }
                | InternalJwtEs256Status::Retained { verifier, .. } => verifier
                    .public_key_as_jwk()
                    .map_err(|err| {
                        error!(?err);
                    })
                    .ok(),
                InternalJwtEs256Status::Revoked { .. } => None,
            })
            .collect::<Vec<_>>();

        JwkKeySet { keys }
    }

    fn public_jwk(&self, key_id: &str) -> Result<Option<Jwk>, OperationError> {
        if let Some(key_to_check) = self.all.get(key_id) {
            match &key_to_check.status {
                InternalJwtEs256Status::Valid { verifier, .. }
                | InternalJwtEs256Status::Retained { verifier, .. } => {
                    verifier.public_key_as_jwk().map(Some).map_err(|err| {
                        error!(?err, "Unable to construct public JWK.");
                        OperationError::KP0044KeyObjectJwsPublicJwk
                    })
                }
                InternalJwtEs256Status::Revoked { .. } => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    fn kid_status(&self, key_id: &KeyId) -> Result<Option<KeyStatus>, OperationError> {
        if let Some(key_to_check) = self.all.get(key_id) {
            let status = match &key_to_check.status {
                InternalJwtEs256Status::Valid { .. } => KeyStatus::Valid,
                InternalJwtEs256Status::Retained { .. } => KeyStatus::Retained,
                InternalJwtEs256Status::Revoked { .. } => KeyStatus::Revoked,
            };
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone)]
enum InternalJwtRs256Status {
    Valid {
        verifier: JwsRs256Verifier,
        private_der: Vec<u8>,
    },
    Retained {
        verifier: JwsRs256Verifier,
        public_der: Vec<u8>,
    },
    Revoked {
        untrusted_verifier: JwsRs256Verifier,
        public_der: Vec<u8>,
    },
}

#[derive(Clone)]
struct InternalJwtRs256 {
    valid_from: u64,
    status: InternalJwtRs256Status,
    status_cid: Cid,
}

#[derive(Default, Clone)]
struct KeyObjectInternalJwtRs256 {
    // active signing keys are in a BTreeMap indexed by their valid_from
    // time so that we can retrieve the active key.
    //
    // We don't need to worry about manipulating this at runtime, since any expiry
    // event will cause the keyObject to reload, which will reflect to this map.
    active: BTreeMap<u64, JwsRs256Signer>,

    // All keys are stored by their KeyId for fast lookup. Keys internally have a
    // current status which is checked for signature validation.
    all: BTreeMap<KeyId, InternalJwtRs256>,
}

impl KeyObjectInternalJwtRs256 {
    fn get_valid_signer(&self, time: Duration) -> Option<&JwsRs256Signer> {
        let ct_secs = time.as_secs();

        self.active
            .range((Unbounded, Included(ct_secs)))
            .next_back()
            .map(|(_time, signer)| signer)
    }

    fn assert_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        if self.get_valid_signer(valid_from).is_none() {
            // This means there is no active signing key, so we need to create one.
            debug!("no active jwt rs256 found, creating a new one ...");
            self.new_active(valid_from, cid)
        } else {
            Ok(())
        }
    }

    fn import(
        &mut self,
        import_keys: &SmolSet<[Vec<u8>; 1]>,
        valid_from: Duration,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        for private_der in import_keys {
            let mut signer = JwsRs256Signer::from_rs256_der(private_der).map_err(|err| {
                error!(?err, "Unable to load imported rs256 DER signer");
                OperationError::KP0045KeyObjectImportJwsRs256DerInvalid
            })?;

            let verifier = signer.get_verifier().map_err(|jwt_error| {
                error!(
                    ?jwt_error,
                    "Unable to produce jwt rs256 verifier from signer"
                );
                OperationError::KP0046KeyObjectSignerToVerifier
            })?;

            // We need to use the legacy KID for imported objects
            let kid = signer.get_legacy_kid().to_string();
            debug!(?kid, "imported key");

            // Indicate to the signer we wish to use the legacy kid for this signer.
            signer.set_kid(kid.as_str());

            self.active.insert(valid_from, signer.clone());

            self.all.insert(
                kid,
                InternalJwtRs256 {
                    valid_from,
                    status: InternalJwtRs256Status::Valid {
                        verifier,
                        private_der: private_der.clone(),
                    },
                    status_cid: cid.clone(),
                },
            );
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "keyobject::jws_rs256::new", skip_all)]
    fn new_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        let signer = JwsRs256Signer::generate_legacy_rs256().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to generate new jwt rs256 signing key");
            OperationError::KP0048KeyObjectJwtRs256Generation
        })?;

        let verifier = signer.get_verifier().map_err(|jwt_error| {
            error!(
                ?jwt_error,
                "Unable to produce jwt rs256 verifier from signer"
            );
            OperationError::KP0049KeyObjectSignerToVerifier
        })?;

        let private_der = signer.private_key_to_der().map_err(|jwt_error| {
            error!(?jwt_error, "Unable to convert signing key to DER");
            OperationError::KP0050KeyObjectPrivateToDer
        })?;

        self.active.insert(valid_from, signer.clone());

        let kid = signer.get_kid().to_string();

        self.all.insert(
            kid,
            InternalJwtRs256 {
                valid_from,
                status: InternalJwtRs256Status::Valid {
                    // signer,
                    verifier,
                    private_der,
                },
                status_cid: cid.clone(),
            },
        );

        Ok(())
    }

    fn revoke(&mut self, revoke_key_id: &KeyId, cid: &Cid) -> Result<bool, OperationError> {
        if let Some(key_to_revoke) = self.all.get_mut(revoke_key_id) {
            let untrusted_verifier = match &key_to_revoke.status {
                InternalJwtRs256Status::Valid { verifier, .. }
                | InternalJwtRs256Status::Retained { verifier, .. } => verifier,
                InternalJwtRs256Status::Revoked {
                    untrusted_verifier, ..
                } => untrusted_verifier,
            }
            .clone();

            let public_der = untrusted_verifier
                .public_key_to_der()
                .map_err(|jwt_error| {
                    error!(?jwt_error, "Unable to convert public key to DER");
                    OperationError::KP0051KeyObjectPublicToDer
                })?;

            key_to_revoke.status = InternalJwtRs256Status::Revoked {
                untrusted_verifier,
                public_der,
            };
            key_to_revoke.status_cid = cid.clone();

            let valid_from = key_to_revoke.valid_from;

            // Remove it from the active set.
            self.active.remove(&valid_from);

            Ok(true)
        } else {
            // We didn't revoke anything
            Ok(false)
        }
    }

    fn load(
        &mut self,
        id: &str,
        status: KeyStatus,
        status_cid: Cid,
        der: &[u8],
        valid_from: u64,
    ) -> Result<(), OperationError> {
        let id: KeyId = id.to_string();

        let status = match status {
            KeyStatus::Valid => {
                let mut signer = JwsRs256Signer::from_rs256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load rs256 DER signer");
                    OperationError::KP0052KeyObjectJwsRs256DerInvalid
                })?;

                // Ensure that the signer has a coherent kid
                signer.set_kid(id.as_str());

                let verifier = signer.get_verifier().map_err(|err| {
                    error!(?err, "Unable to retrieve verifier from signer");
                    OperationError::KP0053KeyObjectSignerToVerifier
                })?;

                self.active.insert(valid_from, signer);

                InternalJwtRs256Status::Valid {
                    // signer,
                    verifier,
                    private_der: der.to_vec(),
                }
            }
            KeyStatus::Retained => {
                let verifier = JwsRs256Verifier::from_rs256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load rs256 DER verifier");
                    OperationError::KP0054KeyObjectJwsRs256DerInvalid
                })?;

                InternalJwtRs256Status::Retained {
                    verifier,
                    public_der: der.to_vec(),
                }
            }
            KeyStatus::Revoked => {
                let untrusted_verifier = JwsRs256Verifier::from_rs256_der(der).map_err(|err| {
                    error!(?err, ?id, "Unable to load rs256 DER revoked verifier");
                    OperationError::KP0055KeyObjectJwsRs256DerInvalid
                })?;

                InternalJwtRs256Status::Revoked {
                    untrusted_verifier,
                    public_der: der.to_vec(),
                }
            }
        };

        let internal_jwt = InternalJwtRs256 {
            valid_from,
            status,
            status_cid,
        };

        self.all.insert(id, internal_jwt);

        Ok(())
    }

    fn to_key_iter(&self) -> impl Iterator<Item = (KeyId, KeyInternalData)> + '_ {
        self.all.iter().map(|(key_id, internal_jwt)| {
            let usage = KeyUsage::JwsRs256;

            let valid_from = internal_jwt.valid_from;
            let status_cid = internal_jwt.status_cid.clone();

            let (status, der) = match &internal_jwt.status {
                InternalJwtRs256Status::Valid { private_der, .. } => {
                    (KeyStatus::Valid, private_der.clone())
                }
                InternalJwtRs256Status::Retained { public_der, .. } => {
                    (KeyStatus::Retained, public_der.clone())
                }
                InternalJwtRs256Status::Revoked { public_der, .. } => {
                    (KeyStatus::Revoked, public_der.clone())
                }
            };

            (
                key_id.clone(),
                KeyInternalData {
                    usage,
                    valid_from,
                    der,
                    status,
                    status_cid,
                },
            )
        })
    }

    fn sign<V: JwsSignable>(
        &self,
        jws: &V,
        current_time: Duration,
    ) -> Result<V::Signed, OperationError> {
        let Some(signing_key) = self.get_valid_signer(current_time) else {
            error!("No signing keys available. This may indicate that no keys are valid yet!");
            return Err(OperationError::KP0061KeyObjectNoActiveSigningKeys);
        };

        signing_key.sign(jws).map_err(|jwt_err| {
            error!(?jwt_err, "Unable to sign jws");
            OperationError::KP0056KeyObjectJwsRs256Signature
        })
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, OperationError> {
        let internal_jws = jwsc
            .kid()
            .and_then(|kid| {
                debug!(?kid);
                self.all.get(kid)
            })
            .ok_or_else(|| {
                error!("JWS is signed by a key that is not present in this KeyObject");
                for pres_kid in self.all.keys() {
                    debug!(?pres_kid);
                }
                OperationError::KP0057KeyObjectJwsNotAssociated
            })?;

        match &internal_jws.status {
            InternalJwtRs256Status::Valid { verifier, .. }
            | InternalJwtRs256Status::Retained { verifier, .. } => {
                verifier.verify(jwsc).map_err(|jwt_err| {
                    error!(?jwt_err, "Failed to verify jws");
                    OperationError::KP0058KeyObjectJwsInvalid
                })
            }
            InternalJwtRs256Status::Revoked { .. } => {
                error!("The key used to sign this JWS has been revoked.");
                Err(OperationError::KP0059KeyObjectJwsKeyRevoked)
            }
        }
    }

    fn public_jwks(&self) -> JwkKeySet {
        // A lot of applications assume the first item in the set is the latest
        // key, so we need to return that first.
        let mut signing_keys: Vec<_> = self.all.iter().collect();

        // Sort by the time they are valid from.
        signing_keys.sort_unstable_by_key(|(_, k)| Reverse(k.valid_from));

        let keys = signing_keys
            .iter()
            .filter_map(|(key_id, rs256)| {
                error!(?key_id);
                match &rs256.status {
                    InternalJwtRs256Status::Valid { verifier, .. }
                    | InternalJwtRs256Status::Retained { verifier, .. } => verifier
                        .public_key_as_jwk()
                        .map_err(|err| {
                            error!(?err);
                        })
                        .ok(),
                    InternalJwtRs256Status::Revoked { .. } => None,
                }
            })
            .collect::<Vec<_>>();

        JwkKeySet { keys }
    }

    fn public_jwk(&self, key_id: &str) -> Result<Option<Jwk>, OperationError> {
        if let Some(key_to_check) = self.all.get(key_id) {
            match &key_to_check.status {
                InternalJwtRs256Status::Valid { verifier, .. }
                | InternalJwtRs256Status::Retained { verifier, .. } => {
                    verifier.public_key_as_jwk().map(Some).map_err(|err| {
                        error!(?err, "Unable to construct public JWK.");
                        OperationError::KP0060KeyObjectJwsPublicJwk
                    })
                }
                InternalJwtRs256Status::Revoked { .. } => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    fn kid_status(&self, key_id: &KeyId) -> Result<Option<KeyStatus>, OperationError> {
        if let Some(key_to_check) = self.all.get(key_id) {
            let status = match &key_to_check.status {
                InternalJwtRs256Status::Valid { .. } => KeyStatus::Valid,
                InternalJwtRs256Status::Retained { .. } => KeyStatus::Retained,
                InternalJwtRs256Status::Revoked { .. } => KeyStatus::Revoked,
            };
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone)]
pub struct KeyObjectInternal {
    provider: Arc<KeyProviderInternal>,
    uuid: Uuid,
    jws_es256: Option<KeyObjectInternalJwtEs256>,
    jws_rs256: Option<KeyObjectInternalJwtRs256>,
    jwe_a128gcm: Option<KeyObjectInternalJweA128GCM>,
    // If you add more types here you need to add these to rotate
    // and revoke.
}

#[cfg(test)]
impl KeyObjectInternal {
    pub fn new_test() -> Arc<KeyObject> {
        let provider = Arc::new(KeyProviderInternal::create_test_provider());

        let mut key_object = provider
            .create_new_key_object(Uuid::new_v4(), provider.clone())
            .expect("Unable to build new key object");

        key_object
            .jws_es256_assert(Duration::from_secs(0), &Cid::new_zero())
            .expect("Unable to add jws_es256 to key object");

        Arc::new(key_object)
    }
}

impl KeyObjectT for KeyObjectInternal {
    fn uuid(&self) -> Uuid {
        self.uuid
    }

    fn duplicate(&self) -> KeyObject {
        Box::new(self.clone())
    }

    fn rotate_keys(&mut self, rotation_time: Duration, cid: &Cid) -> Result<(), OperationError> {
        if let Some(jws_es256_object) = &mut self.jws_es256 {
            jws_es256_object.new_active(rotation_time, cid)?;
        }

        if let Some(jws_rs256_object) = &mut self.jws_rs256 {
            jws_rs256_object.new_active(rotation_time, cid)?;
        }

        if let Some(jwe_a128_gcm) = &mut self.jwe_a128gcm {
            jwe_a128_gcm.new_active(rotation_time, cid)?;
        }

        Ok(())
    }

    fn revoke_keys(
        &mut self,
        revoke_set: &BTreeSet<String>,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        for revoke_key_id in revoke_set.iter() {
            let mut has_revoked = false;

            if let Some(jws_es256_object) = &mut self.jws_es256 {
                if jws_es256_object.revoke(revoke_key_id, cid)? {
                    has_revoked = true;
                }
            };

            if let Some(jws_rs256_object) = &mut self.jws_rs256 {
                if jws_rs256_object.revoke(revoke_key_id, cid)? {
                    has_revoked = true;
                }
            };

            if let Some(jwe_a128_gcm) = &mut self.jwe_a128gcm {
                if jwe_a128_gcm.revoke(revoke_key_id, cid)? {
                    has_revoked = true;
                }
            };

            if !has_revoked {
                error!(?revoke_key_id, "Unable to revoked key, id not found");
                return Err(OperationError::KP0026KeyObjectNoSuchKey);
            }
        }

        Ok(())
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
            JwaAlg::RS256 => {
                if let Some(jws_rs256_object) = &self.jws_rs256 {
                    jws_rs256_object.verify(jwsc)
                } else {
                    error!(provider_uuid = ?self.uuid, "jwt rs256 not available on this provider");
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

    fn jws_es256_jwks(&self) -> Option<JwkKeySet> {
        self.jws_es256
            .as_ref()
            .map(|jws_es256_object| jws_es256_object.public_jwks())
    }

    fn jws_public_jwk(&self, key_id: &str) -> Result<Option<Jwk>, OperationError> {
        if let Some(jws_es256_object) = &self.jws_es256 {
            if let Some(status) = jws_es256_object.public_jwk(key_id)? {
                return Ok(Some(status));
            }
        }

        if let Some(jws_rs256_object) = &self.jws_rs256 {
            if let Some(status) = jws_rs256_object.public_jwk(key_id)? {
                return Ok(Some(status));
            }
        }

        Ok(None)
    }

    #[instrument(level = "debug", name = "keyobject::jws_es256_import", skip_all)]
    fn jws_es256_import(
        &mut self,
        import_keys: &SmolSet<[Vec<u8>; 1]>,
        valid_from: Duration,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        let koi = self
            .jws_es256
            .get_or_insert_with(KeyObjectInternalJwtEs256::default);

        koi.import(import_keys, valid_from, cid)
    }

    fn jws_es256_assert(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        let koi = self
            .jws_es256
            .get_or_insert_with(KeyObjectInternalJwtEs256::default);

        koi.assert_active(valid_from, cid)
    }

    fn jwe_decrypt(&self, jwec: &JweCompact) -> Result<Jwe, OperationError> {
        let (alg, enc) = jwec.get_alg_enc();

        match (alg, enc) {
            (JweAlg::A128KW, JweEnc::A128GCM) => {
                if let Some(jwe_a128_gcm) = &self.jwe_a128gcm {
                    jwe_a128_gcm.decipher(jwec)
                } else {
                    error!(provider_uuid = ?self.uuid, "jwe a128gcm not available on this provider");
                    Err(OperationError::KP0033KeyProviderNoSuchKey)
                }
            }
            (unsupported_alg, unsupported_enc) => {
                // unsupported rn.
                error!(provider_uuid = ?self.uuid, ?unsupported_alg, ?unsupported_enc, "algorithm+encryption not available on this provider");
                Err(OperationError::KP0019KeyProviderUnsupportedAlgorithm)
            }
        }
    }

    fn jwe_a128gcm_assert(
        &mut self,
        valid_from: Duration,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        let koi = self
            .jwe_a128gcm
            .get_or_insert_with(KeyObjectInternalJweA128GCM::default);

        koi.assert_active(valid_from, cid)
    }

    fn jwe_a128gcm_encrypt(
        &self,
        jwe: &Jwe,
        current_time: Duration,
    ) -> Result<JweCompact, OperationError> {
        if let Some(jwe_a128_gcm) = &self.jwe_a128gcm {
            jwe_a128_gcm.encipher(jwe, current_time)
        } else {
            error!(provider_uuid = ?self.uuid, "jwe a128gcm not available on this provider");
            Err(OperationError::KP0032KeyProviderNoSuchKey)
        }
    }

    #[cfg(test)]
    fn kid_status(&self, key_id: &KeyId) -> Result<Option<KeyStatus>, OperationError> {
        if let Some(jws_es256_object) = &self.jws_es256 {
            if let Some(status) = jws_es256_object.kid_status(key_id)? {
                return Ok(Some(status));
            }
        }

        if let Some(jws_rs256_object) = &self.jws_rs256 {
            if let Some(status) = jws_rs256_object.kid_status(key_id)? {
                return Ok(Some(status));
            }
        }

        Ok(None)
    }

    fn as_valuesets(&self) -> Result<Vec<(Attribute, ValueSet)>, OperationError> {
        let key_iter = self
            .jws_es256
            .iter()
            .flat_map(|jws_es256| jws_es256.to_key_iter())
            .chain(
                self.jwe_a128gcm
                    .iter()
                    .flat_map(|jwe_a128gcm| jwe_a128gcm.to_key_iter()),
            )
            .chain(
                self.jws_rs256
                    .iter()
                    .flat_map(|jws_rs256| jws_rs256.to_key_iter()),
            );
        let key_vs = ValueSetKeyInternal::from_key_iter(key_iter)? as ValueSet;

        Ok(vec![
            (
                Attribute::Class,
                ValueSetIutf8::new(EntryClass::KeyObjectInternal.into()) as ValueSet,
            ),
            (
                Attribute::KeyProvider,
                ValueSetRefer::new(self.provider.uuid()) as ValueSet,
            ),
            (Attribute::KeyInternalData, key_vs),
        ])
    }

    #[instrument(level = "debug", name = "keyobject::jws_rs256_import", skip_all)]
    fn jws_rs256_import(
        &mut self,
        import_keys: &SmolSet<[Vec<u8>; 1]>,
        valid_from: Duration,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        let koi = self
            .jws_rs256
            .get_or_insert_with(KeyObjectInternalJwtRs256::default);

        koi.import(import_keys, valid_from, cid)
    }

    fn jws_rs256_assert(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        let koi = self
            .jws_rs256
            .get_or_insert_with(KeyObjectInternalJwtRs256::default);

        koi.assert_active(valid_from, cid)
    }

    fn jws_rs256_sign(
        &self,
        jws: &Jws,
        current_time: Duration,
    ) -> Result<JwsCompact, OperationError> {
        if let Some(jws_rs256_object) = &self.jws_rs256 {
            jws_rs256_object.sign(jws, current_time)
        } else {
            error!(provider_uuid = ?self.uuid, "jwt rs256 not available on this provider");
            Err(OperationError::KP0062KeyProviderNoSuchKey)
        }
    }

    fn jws_rs256_jwks(&self) -> Option<JwkKeySet> {
        self.jws_rs256
            .as_ref()
            .map(|jws_rs256_object| jws_rs256_object.public_jwks())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::keys::*;
    use compact_jwt::jws::JwsBuilder;

    #[tokio::test]
    async fn test_key_object_internal_basic() {
        let ct = duration_from_epoch_now();
        let test_provider = Arc::new(KeyProviderInternal::create_test_provider());

        test_provider.test().expect("Provider failed testing");

        let mut key_object = test_provider
            .create_new_key_object(Uuid::new_v4(), test_provider.clone())
            .expect("Unable to create new key object");

        key_object
            .jws_es256_assert(ct, &Cid::new_count(ct.as_secs()))
            .expect("Unable to create signing key");

        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4]).build();

        let sig = key_object
            .jws_es256_sign(&jws, ct)
            .expect("Unable to sign jws");

        let released = key_object.jws_verify(&sig).expect("Unable to validate jws");

        assert_eq!(released.payload(), &[0, 1, 2, 3, 4]);
    }

    #[qs_test]
    async fn test_key_object_internal_es256(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();

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

        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4]).build();

        let jwsc_sig_1 = {
            let key_object_loaded = write_txn
                .get_key_providers()
                .get_key_object(key_object_uuid)
                .expect("Unable to retrieve key object by uuid");

            // Check the key works, and has es256.
            let jwsc_sig_1 = key_object_loaded
                .jws_es256_sign(&jws, ct)
                .expect("Unable to sign jws");

            assert!(jwsc_sig_1.get_jwk_pubkey_url().is_none());

            let released = key_object_loaded
                .jws_verify(&jwsc_sig_1)
                .expect("Unable to validate jws");

            assert_eq!(released.payload(), &[0, 1, 2, 3, 4]);

            jwsc_sig_1
        };

        // Test rotation of the key. Key rotation is always in terms of when the new key should be
        // considered valid from, which allows us to nominate a time in the future for it to be used.

        let ct_future = ct + Duration::from_secs(300);

        write_txn
            .internal_modify_uuid(
                key_object_uuid,
                &ModifyList::new_append(
                    Attribute::KeyActionRotate,
                    Value::new_datetime_epoch(ct_future),
                ),
            )
            .expect("Unable to rotate key.");

        // While the rotation is stored in the DB, it's not reflected in the key object until
        // a reload occurs.
        write_txn.reload().expect("Unable to reload transaction");

        let (jwsc_sig_2, jwsc_sig_3) = {
            let key_object_loaded = write_txn
                .get_key_providers()
                .get_key_object(key_object_uuid)
                .expect("Unable to retrieve key object by uuid");

            // Will be signed with the former key.
            let jwsc_sig_2 = key_object_loaded
                .jws_es256_sign(&jws, ct)
                .expect("Unable to sign jws");

            // Signed with the new key (note that we manipulated time here).
            let jwsc_sig_3 = key_object_loaded
                .jws_es256_sign(&jws, ct_future)
                .expect("Unable to sign jws");

            (jwsc_sig_2, jwsc_sig_3)
        };

        assert_eq!(jwsc_sig_1.kid(), jwsc_sig_2.kid());
        assert_ne!(jwsc_sig_2.kid(), jwsc_sig_3.kid());

        // Test Key revocation. Revocation takes effect immediately, and is by key id.
        // The new key
        let remain_key = jwsc_sig_3.kid().unwrap().to_string();
        // The older key (since sig 1 == sig 2 kid)
        let revoke_kid = jwsc_sig_2.kid().unwrap().to_string();

        // First check that both keys are live.
        {
            let key_object = write_txn
                .internal_search_uuid(key_object_uuid)
                .expect("unable to access key object");

            let key_internal_map = key_object
                .get_ava_set(Attribute::KeyInternalData)
                .and_then(|vs| vs.as_key_internal_map())
                .expect("Unable to access key internal map.");

            let revoke_key_status = key_internal_map
                .get(&revoke_kid)
                .map(|kdata| kdata.status)
                .expect("Key ID not found");

            assert_eq!(revoke_key_status, KeyStatus::Valid);

            let remain_key_status = key_internal_map
                .get(&remain_key)
                .map(|kdata| kdata.status)
                .expect("Key ID not found");

            assert_eq!(remain_key_status, KeyStatus::Valid);
            // Scope the object
        }

        // Revoke the older key.
        write_txn
            .internal_modify_uuid(
                key_object_uuid,
                &ModifyList::new_append(
                    Attribute::KeyActionRevoke,
                    Value::HexString(revoke_kid.clone()),
                ),
            )
            .expect("Unable to revoke key.");

        // While the rotation is stored in the DB, it's not reflected in the key object until
        // a reload occurs.
        write_txn.reload().expect("Unable to reload transaction");

        {
            let key_object = write_txn
                .internal_search_uuid(key_object_uuid)
                .expect("unable to access key object");

            let key_internal_map = key_object
                .get_ava_set(Attribute::KeyInternalData)
                .and_then(|vs| vs.as_key_internal_map())
                .expect("Unable to access key internal map.");

            let revoke_key_status = key_internal_map
                .get(&revoke_kid)
                .map(|kdata| kdata.status)
                .expect("Key ID not found");

            trace!(?revoke_kid);

            assert_eq!(revoke_key_status, KeyStatus::Revoked);

            let remain_key_status = key_internal_map
                .get(&remain_key)
                .map(|kdata| kdata.status)
                .expect("Key ID not found");

            trace!(?remain_key);
            trace!(?remain_key_status);

            assert_eq!(remain_key_status, KeyStatus::Valid);
            // Scope to limit the key object
        }

        // Will fail to be signed with the former key, since it is now revoked, and the ct precedes
        // the validity of the new key
        {
            let key_object_loaded = write_txn
                .get_key_providers()
                .get_key_object(key_object_uuid)
                .expect("Unable to retrieve key object by uuid");

            let _ = key_object_loaded
                .jws_es256_sign(&jws, ct)
                .expect("Unable to sign jws");

            // Signature works since the time is now in the valid window of the newer key.
            let _jwsc_sig_4 = key_object_loaded
                .jws_es256_sign(&jws, ct_future)
                .expect("Unable to sign jws");
        }

        write_txn.commit().expect("Failed to commit");
    }
}

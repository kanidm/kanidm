use crate::prelude::*;

use concread::cowcell::*;
use uuid::Uuid;

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use super::internal::KeyProviderInternal;
use super::object::KeyObject;

#[cfg(test)]
use super::object::KeyObjectRef;

#[derive(Clone)]
pub enum KeyProvider {
    // Mostly this is a wrapper to store the loaded providers, which are then downcast into
    // their concrete type and associated with key objects.
    Internal(Arc<KeyProviderInternal>),
}

impl fmt::Display for KeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyProvider")
            .field("name", &self.name())
            .field("uuid", &self.uuid())
            .finish()
    }
}

impl KeyProvider {
    pub(crate) fn uuid(&self) -> Uuid {
        match self {
            KeyProvider::Internal(inner) => inner.uuid(),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            KeyProvider::Internal(inner) => inner.name(),
        }
    }

    pub(crate) fn test(&self) -> Result<(), OperationError> {
        match self {
            KeyProvider::Internal(inner) => inner.test(),
        }
    }

    fn create_new_key_object(&self, key_object_uuid: Uuid) -> Result<KeyObject, OperationError> {
        match self {
            KeyProvider::Internal(inner) => {
                inner.create_new_key_object(key_object_uuid, inner.clone())
            }
        }
    }

    fn load_key_object(
        &self,
        entry: &EntrySealedCommitted,
    ) -> Result<Arc<KeyObject>, OperationError> {
        match self {
            KeyProvider::Internal(inner) => inner.load_key_object(entry, inner.clone()),
        }
    }

    pub(crate) fn try_from(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Arc<Self>, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::KeyProvider.into()) {
            error!("class key_provider not present.");
            return Err(OperationError::KP0002KeyProviderInvalidClass);
        }

        if value.attribute_equality(Attribute::Class, &EntryClass::KeyProviderInternal.into()) {
            KeyProviderInternal::try_from(value)
                .map(|kpi| KeyProvider::Internal(Arc::new(kpi)))
                .map(Arc::new)
        } else {
            error!("No supported key provider type present");
            Err(OperationError::KP0003KeyProviderInvalidType)
        }
    }
}

#[derive(Clone)]
struct KeyProvidersInner {
    // Wondering if this should be Arc later to allow KeyObjects to refer to their provider directly.
    providers: BTreeMap<Uuid, Arc<KeyProvider>>,
    objects: BTreeMap<Uuid, Arc<KeyObject>>,
}

pub struct KeyProviders {
    inner: CowCell<KeyProvidersInner>,
}

impl Default for KeyProviders {
    fn default() -> Self {
        KeyProviders {
            inner: CowCell::new(KeyProvidersInner {
                providers: BTreeMap::default(),
                objects: BTreeMap::default(),
            }),
        }
    }
}

impl KeyProviders {
    pub fn read(&self) -> KeyProvidersReadTransaction {
        KeyProvidersReadTransaction {
            inner: self.inner.read(),
        }
    }

    pub fn write(&self) -> KeyProvidersWriteTransaction {
        KeyProvidersWriteTransaction {
            inner: self.inner.write(),
        }
    }
}

pub trait KeyProvidersTransaction {
    #[cfg(test)]
    fn get_uuid(&self, key_provider_uuid: Uuid) -> Option<&KeyProvider>;

    #[cfg(test)]
    fn get_key_object(&self, key_object_uuid: Uuid) -> Option<KeyObjectRef>;

    fn get_key_object_handle(&self, key_object_uuid: Uuid) -> Option<Arc<KeyObject>>;
}

pub struct KeyProvidersReadTransaction {
    inner: CowCellReadTxn<KeyProvidersInner>,
}

impl KeyProvidersTransaction for KeyProvidersReadTransaction {
    #[cfg(test)]
    fn get_uuid(&self, key_provider_uuid: Uuid) -> Option<&KeyProvider> {
        self.inner
            .deref()
            .providers
            .get(&key_provider_uuid)
            .map(|k| k.as_ref())
    }

    #[cfg(test)]
    fn get_key_object(&self, key_object_uuid: Uuid) -> Option<KeyObjectRef> {
        self.inner
            .deref()
            .objects
            .get(&key_object_uuid)
            .map(|k| k.as_ref().as_ref())
    }

    fn get_key_object_handle(&self, key_object_uuid: Uuid) -> Option<Arc<KeyObject>> {
        self.inner.deref().objects.get(&key_object_uuid).cloned()
    }
}

pub struct KeyProvidersWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, KeyProvidersInner>,
}

impl KeyProvidersTransaction for KeyProvidersWriteTransaction<'_> {
    #[cfg(test)]
    fn get_uuid(&self, key_provider_uuid: Uuid) -> Option<&KeyProvider> {
        self.inner
            .deref()
            .providers
            .get(&key_provider_uuid)
            .map(|k| k.as_ref())
    }

    #[cfg(test)]
    fn get_key_object(&self, key_object_uuid: Uuid) -> Option<KeyObjectRef> {
        self.inner
            .deref()
            .objects
            .get(&key_object_uuid)
            .map(|k| k.as_ref().as_ref())
    }

    fn get_key_object_handle(&self, key_object_uuid: Uuid) -> Option<Arc<KeyObject>> {
        self.inner.deref().objects.get(&key_object_uuid).cloned()
    }
}

impl KeyProvidersWriteTransaction<'_> {
    #[cfg(test)]
    pub(crate) fn get_default(&self) -> Result<&KeyProvider, OperationError> {
        // In future we will make this configurable, and we'll load the default into
        // the write txn during a reload.
        self.get_uuid(UUID_KEY_PROVIDER_INTERNAL)
            .ok_or(OperationError::KP0007KeyProviderDefaultNotAvailable)
    }

    pub(crate) fn get_or_create_in_default(
        &mut self,
        key_object_uuid: Uuid,
    ) -> Result<KeyObject, OperationError> {
        self.get_or_create(UUID_KEY_PROVIDER_INTERNAL, key_object_uuid)
    }

    pub(crate) fn get_or_create(
        &mut self,
        key_provider_uuid: Uuid,
        key_object_uuid: Uuid,
    ) -> Result<KeyObject, OperationError> {
        if let Some(key_object) = self.inner.deref().objects.get(&key_object_uuid) {
            Ok(key_object.as_ref().duplicate())
        } else {
            let provider = self
                .inner
                .deref()
                .providers
                .get(&key_provider_uuid)
                .map(|k| k.as_ref())
                .ok_or(OperationError::KP0025KeyProviderNotAvailable)?;

            provider.create_new_key_object(key_object_uuid)
        }
    }
}

impl KeyProvidersWriteTransaction<'_> {
    pub(crate) fn update_providers(
        &mut self,
        providers: Vec<Arc<KeyProvider>>,
    ) -> Result<(), OperationError> {
        // Clear the current set.
        self.inner.providers.clear();

        // For each provider insert.
        for provider in providers.into_iter() {
            let uuid = provider.uuid();
            if self.inner.providers.insert(uuid, provider).is_some() {
                error!(key_provider_uuid = ?uuid, "duplicate key provider detected");
                return Err(OperationError::KP0005KeyProviderDuplicate);
            }
        }

        Ok(())
    }

    pub(crate) fn load_key_object(
        &mut self,
        entry: &EntrySealedCommitted,
    ) -> Result<(), OperationError> {
        // Object UUID
        let object_uuid = entry.get_uuid();

        if !entry.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into()) {
            error!(?object_uuid, "Invalid entry, keyobject class not found.");
            return Err(OperationError::KP0011KeyObjectMissingClass);
        }

        // Get provider UUID.
        let provider_uuid = entry
            .get_ava_single_refer(Attribute::KeyProvider)
            .ok_or_else(|| {
                error!(
                    ?object_uuid,
                    "Invalid key object, key provider referenced is not found."
                );
                OperationError::KP0012KeyObjectMissingProvider
            })?;

        let provider = self.inner.providers.get(&provider_uuid).ok_or_else(|| {
            error!(
                ?object_uuid,
                ?provider_uuid,
                "Invalid reference state, key provider has not be loaded."
            );
            OperationError::KP0012KeyProviderNotLoaded
        })?;

        // Ask the provider to load this object.
        let key_object = provider.load_key_object(entry)?;

        // Can't be duplicate as uuid is enforced unique in other layers.
        self.inner.objects.insert(object_uuid, key_object);

        Ok(())
    }

    pub(crate) fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();

        Ok(())
    }
}

/*
#[cfg(test)]
mod tests {
    use super::{KeyProvider, KeyProvidersTransaction};
    use crate::prelude::*;
    use crate::value::KeyStatus;
    use compact_jwt::{JwsEs256Signer, JwsSigner};

}
*/

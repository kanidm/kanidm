use crate::prelude::*;

use concread::cowcell::*;
use uuid::Uuid;

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

use super::internal::KeyProviderInternal;

#[derive(Clone)]
pub enum KeyProvider {
    // Mostly this is a wrapper to store the loaded providers, which are then downcast into
    // their concrete type and associated with key objects.
    Internal(Arc<KeyProviderInternal>),
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

    pub(crate) fn try_from(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::KeyProvider.into()) {
            error!("class key_provider not present.");
            return Err(OperationError::KP0002KeyProviderInvalidClass);
        }

        if value.attribute_equality(Attribute::Class, &EntryClass::KeyProviderInternal.into()) {
            KeyProviderInternal::try_from(value).map(|kpi| KeyProvider::Internal(Arc::new(kpi)))
        } else {
            error!("No supported key provider type present");
            Err(OperationError::KP0003KeyProviderInvalidType)
        }
    }
}

#[derive(Clone)]
struct KeyProvidersInner {
    // Wondering if this should be Arc later to allow KeyObjects to refer to their provider directly.
    providers: BTreeMap<Uuid, KeyProvider>,
}

pub struct KeyProviders {
    inner: CowCell<KeyProvidersInner>,
}

impl Default for KeyProviders {
    fn default() -> Self {
        KeyProviders {
            inner: CowCell::new(KeyProvidersInner {
                providers: BTreeMap::default(),
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
    fn get_uuid(&self, key_provider_uuid: Uuid) -> Option<&KeyProvider>;
}

pub struct KeyProvidersReadTransaction {
    inner: CowCellReadTxn<KeyProvidersInner>,
}

impl KeyProvidersTransaction for KeyProvidersReadTransaction {
    fn get_uuid(&self, key_provider_uuid: Uuid) -> Option<&KeyProvider> {
        self.inner.deref().providers.get(&key_provider_uuid)
    }
}

pub struct KeyProvidersWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, KeyProvidersInner>,
}

impl<'a> KeyProvidersTransaction for KeyProvidersWriteTransaction<'a> {
    fn get_uuid(&self, key_provider_uuid: Uuid) -> Option<&KeyProvider> {
        self.inner.deref().providers.get(&key_provider_uuid)
    }
}

impl<'a> KeyProvidersWriteTransaction<'a> {
    pub(crate) fn update_providers(
        &mut self,
        providers: Vec<KeyProvider>,
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

    pub(crate) fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyProvider, KeyProvidersTransaction};
    use crate::prelude::*;

    #[qs_test(domain_level=DOMAIN_LEVEL_5)]
    async fn test_key_provider_creation_basic(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await;

        // No key providers.

        // Set the version to 6.
        write_txn
            .internal_modify_uuid(
                UUID_DOMAIN_INFO,
                &ModifyList::new_purge_and_set(
                    Attribute::Version,
                    Value::new_uint32(DOMAIN_LEVEL_6),
                ),
            )
            .expect("Unable to set domain level to version 6");

        // Re-load - this applies the migrations.
        write_txn.reload().expect("Unable to reload transaction");

        // The internel key provider is created from dl 5 to 6
        let key_provider_object = write_txn
            .internal_search_uuid(UUID_KEY_PROVIDER_INTERNAL)
            .expect("Unable to find key provider entry.");

        assert!(key_provider_object.attribute_equality(
            Attribute::Name,
            &PartialValue::new_iname("key_provider_internal")
        ));

        // Check that is loaded in the qs.

        let key_provider = write_txn
            .get_key_providers()
            .get_uuid(UUID_KEY_PROVIDER_INTERNAL)
            .expect("Unable to access key provider object.");

        // Because there is only one variant today ...
        #[allow(irrefutable_let_patterns)]
        let KeyProvider::Internal(key_provider_internal) = key_provider
        else {
            unreachable!()
        };

        // Run the providers internal test
        assert!(key_provider_internal.test().is_ok());
    }
}

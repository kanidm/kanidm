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
    pub fn commit(self) -> Result<(), OperationError> {
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

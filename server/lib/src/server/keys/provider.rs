pub struct KeyProviders {}

impl Default for KeyProviders {
    fn default() -> Self {
        KeyProviders {}
    }
}

#[cfg(test)]
mod tests {
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

        // Check that is loaded in the qs.

        todo!();
    }
}

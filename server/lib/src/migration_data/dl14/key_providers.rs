use crate::prelude::*;

pub(crate) fn e_key_provider_internal_dl6() -> EntryInitNew {
    entry_init_fn(
        [
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::KeyProvider.to_value()),
            (Attribute::Class, EntryClass::KeyProviderInternal.to_value()),
            (Attribute::Uuid, Value::Uuid(UUID_KEY_PROVIDER_INTERNAL)),
            (Attribute::Name, Value::new_iname("key_provider_internal")),
            (
                Attribute::Description,
                Value::new_utf8s("The default database internal cryptographic key provider."),
            ),
        ]
        .into_iter(),
    )
}

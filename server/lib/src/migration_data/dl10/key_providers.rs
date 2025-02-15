use crate::constants::entries::{Attribute, EntryClass};
use crate::constants::uuids::UUID_KEY_PROVIDER_INTERNAL;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::value::Value;

lazy_static! {
    pub static ref E_KEY_PROVIDER_INTERNAL_DL6: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::KeyProvider.to_value()),
        (Attribute::Class, EntryClass::KeyProviderInternal.to_value()),
        (Attribute::Uuid, Value::Uuid(UUID_KEY_PROVIDER_INTERNAL)),
        (Attribute::Name, Value::new_iname("key_provider_internal")),
        (
            Attribute::Description,
            Value::new_utf8s("The default database internal cryptographic key provider.")
        )
    );
}

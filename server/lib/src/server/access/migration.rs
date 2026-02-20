use crate::prelude::EntryClass;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// These entry classes may be affected by migrations. All protection rules still
/// apply.
pub static MIGRATION_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::Object,
        EntryClass::MemberOf,
        EntryClass::DomainInfo,
        EntryClass::OAuth2ResourceServer,
        EntryClass::OAuth2ResourceServerBasic,
        EntryClass::OAuth2ResourceServerPublic,
        EntryClass::Account,
        EntryClass::Person,
        EntryClass::PosixAccount,
        EntryClass::Group,
        EntryClass::DynGroup,
        EntryClass::AccountPolicy,
        EntryClass::PosixGroup,
        EntryClass::ServiceAccount,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

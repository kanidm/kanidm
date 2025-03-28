use crate::prelude::EntryClass;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// These entry classes may not be created or deleted, and may invoke some protection rules
/// if on an entry.
pub static PROTECTED_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        EntryClass::SyncObject,
        EntryClass::Tombstone,
        EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// Entries with these classes are protected from modifications - not that
/// sync object is not present here as there are separate rules for that in
/// the modification access module.
///
/// Recycled is also not protected here as it needs to be able to be removed
/// by a recycle bin admin.
pub static PROTECTED_MOD_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        // EntryClass::SyncObject,
        EntryClass::Tombstone,
        EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// These classes may NOT be added to ANY ENTRY
pub static PROTECTED_MOD_PRES_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        EntryClass::SyncObject,
        EntryClass::Tombstone,
        EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// These classes may NOT be removed from ANY ENTRY
pub static PROTECTED_MOD_REM_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        EntryClass::SyncObject,
        EntryClass::Tombstone,
        // EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// Entries with these classes may not be modified under any circumstance.
pub static LOCKED_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::Tombstone,
        // EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

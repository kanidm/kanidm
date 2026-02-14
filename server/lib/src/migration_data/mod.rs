pub(crate) mod dl10;
pub(crate) mod dl11;
pub(crate) mod dl12;
pub(crate) mod dl13;
pub(crate) mod dl14;

mod types;

#[cfg(test)]
pub(crate) use dl14::accounts::BUILTIN_ACCOUNT_ANONYMOUS_DL6 as BUILTIN_ACCOUNT_ANONYMOUS;

#[cfg(test)]
pub use self::types::BuiltinAccount;

/// Builtin System Admin account.
#[cfg(test)]
pub static BUILTIN_ACCOUNT_TEST_PERSON: BuiltinAccount = BuiltinAccount {
    account_type: kanidm_proto::v1::AccountType::Person,
    entry_managed_by: None,
    name: "test_person",
    uuid: crate::constants::uuids::UUID_TESTPERSON_1,
    description: "Test Person",
    displayname: "Test Person",
};

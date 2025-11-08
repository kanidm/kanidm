pub(crate) mod dl10;
pub(crate) mod dl11;
pub(crate) mod dl12;
pub(crate) mod dl13;

mod types;

#[cfg(test)]
pub(crate) use dl13::accounts::BUILTIN_ACCOUNT_ANONYMOUS_DL6 as BUILTIN_ACCOUNT_ANONYMOUS;

#[cfg(test)]
pub use self::types::BuiltinAccount;

#[cfg(test)]
lazy_static! {
    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_TEST_PERSON: BuiltinAccount = BuiltinAccount {
        account_type: kanidm_proto::v1::AccountType::Person,
        entry_managed_by: None,
        name: "test_person",
        uuid: crate::constants::uuids::UUID_TESTPERSON_1,
        description: "Test Person",
        displayname: "Test Person",
    };
}

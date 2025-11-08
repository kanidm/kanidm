//! Constant Entries for the IDM
use crate::constants::uuids::*;
use crate::migration_data::types::BuiltinAccount;
use kanidm_proto::v1::AccountType;

lazy_static! {
    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_IDM_ADMIN: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        entry_managed_by: None,
        name: "idm_admin",
        uuid: UUID_IDM_ADMIN,
        description: "Builtin IDM Admin account.",
        displayname: "IDM Administrator",
    };

    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_ADMIN: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        entry_managed_by: None,
        name: "admin",
        uuid: UUID_ADMIN,
        description: "Builtin System Admin account.",
        displayname: "System Administrator",
    };

    pub static ref BUILTIN_ACCOUNT_ANONYMOUS_DL6: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        name: "anonymous",
        uuid: UUID_ANONYMOUS,
        description: "Anonymous access account.",
        displayname: "Anonymous",
    };
}

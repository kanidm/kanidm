//! Constant Entries for the IDM
use crate::constants::uuids::*;
use crate::entry::EntryInitNew;
use crate::prelude::EntryClass;
use crate::value::Value;
pub use kanidm_proto::attribute::Attribute;
use kanidm_proto::v1::AccountType;

use uuid::Uuid;

#[derive(Debug, Clone)]
/// Built in accounts such as anonymous, idm_admin and admin
pub struct BuiltinAccount {
    pub account_type: kanidm_proto::v1::AccountType,
    pub entry_managed_by: Option<uuid::Uuid>,
    pub name: &'static str,
    pub uuid: Uuid,
    pub description: &'static str,
    pub displayname: &'static str,
}

#[cfg(test)]
impl Default for BuiltinAccount {
    fn default() -> Self {
        BuiltinAccount {
            account_type: AccountType::ServiceAccount,
            entry_managed_by: None,
            name: "",
            uuid: Uuid::new_v4(),
            description: "<set description>",
            displayname: "<set displayname>",
        }
    }
}

impl From<BuiltinAccount> for EntryInitNew {
    fn from(value: BuiltinAccount) -> Self {
        let mut entry = EntryInitNew::new();
        entry.add_ava(Attribute::Name, Value::new_iname(value.name));
        #[allow(clippy::panic)]
        if value.uuid >= DYNAMIC_RANGE_MINIMUM_UUID {
            panic!("Builtin ACP has invalid UUID! {value:?}");
        }
        entry.add_ava(Attribute::Uuid, Value::Uuid(value.uuid));
        entry.add_ava(Attribute::Description, Value::new_utf8s(value.description));
        entry.add_ava(Attribute::DisplayName, Value::new_utf8s(value.displayname));

        if let Some(entry_manager) = value.entry_managed_by {
            entry.add_ava(Attribute::EntryManagedBy, Value::Refer(entry_manager));
        }

        entry.set_ava(
            Attribute::Class,
            vec![
                EntryClass::Account.to_value(),
                EntryClass::MemberOf.to_value(),
                EntryClass::Object.to_value(),
            ],
        );
        match value.account_type {
            AccountType::Person => entry.add_ava(Attribute::Class, EntryClass::Person.to_value()),
            AccountType::ServiceAccount => {
                entry.add_ava(Attribute::Class, EntryClass::ServiceAccount.to_value())
            }
        }
        entry
    }
}

// Transform password import requests into proper kanidm credentials.
use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew};
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::server::QueryServerWriteTransaction;
use kanidm_proto::v1::OperationError; //  PluginError};

pub struct PasswordImport {}

/*
impl PasswordImport {
    fn import_to_credential() -> () {
    }
}
*/

impl Plugin for PasswordImport {
    fn id() -> &'static str {
        "plugin_password_import"
    }

    fn pre_create_transform(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Given and cand that contains "password_import"
        // remove that attr
        // does that cand have a cred?
        //

        // If there are multiple, fail.

        Ok(())
    }

    fn pre_modify(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // As above

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::value::{PartialValue, Value};

    static IMPORT_HASH: &'static str =
        "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";
    // static IMPORT_PASSWORD: &'static str = "eicieY7ahchaoCh0eeTa";

    #[test]
    fn test_pre_create_password_import_1() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "account"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"],
                "password_import": ["pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w="],
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(Ok(()), preload, create, None, |_, _| {});
    }

    #[test]
    fn test_modify_password_import_1() {
        // Add another uuid to a type
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["account", "person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                "password_import".to_string(),
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_, _| {}
        );
    }
}

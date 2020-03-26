// Transform password import requests into proper kanidm credentials.
use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew};
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::server::QueryServerWriteTransaction;
use crate::credential::Password;
use std::convert::TryFrom;
use kanidm_proto::v1::{OperationError, PluginError};

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
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut()
            .try_for_each(|e| {
                // is there an import_password?
                let vs = match e.get_ava("password_import") {
                    Some(vs) => vs,
                    None => return Ok(()),
                };
                // if there are multiple, fail.
                if vs.len() > 1 {
                    return Err(OperationError::Plugin(PluginError::PasswordImport("multiple password_imports specified".to_string())))
                }
                debug_assert!(vs.len() >= 1);
                let im_pw = vs.first()
                    .unwrap()
                    .to_str()
                    .ok_or(OperationError::Plugin(PluginError::PasswordImport("password_import has incorrect value type".to_string())))?;

                // convert the import_password to a cred
                let _pw = Password::try_from(im_pw);

                // does the entry have a primary cred?
                // map it in as needed.
                Ok(())
            })
    }

    fn pre_modify(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut()
            .try_for_each(|_e| {
                Ok(())
            })
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
                "password_import": ["pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w="]
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

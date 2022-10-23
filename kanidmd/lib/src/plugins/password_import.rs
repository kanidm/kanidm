// Transform password import requests into proper kanidm credentials.
use std::convert::TryFrom;
use std::iter::once;

use kanidm_proto::v1::PluginError;

use crate::credential::{Credential, Password};
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct PasswordImport {}

impl Plugin for PasswordImport {
    fn id() -> &'static str {
        "plugin_password_import"
    }

    #[instrument(
        level = "debug",
        name = "password_import_pre_create_transform",
        skip(_qs, cand, _ce)
    )]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut()
            .try_for_each(|e| {
                // is there a password we are trying to import?
                let vs = match e.pop_ava("password_import") {
                    Some(vs) => vs,
                    None => return Ok(()),
                };
                // if there are multiple, fail.
                if vs.len() > 1 {
                    return Err(OperationError::Plugin(PluginError::PasswordImport("multiple password_imports specified".to_string())))
                }

                let im_pw = vs.to_utf8_single()
                    .ok_or_else(|| OperationError::Plugin(PluginError::PasswordImport("password_import has incorrect value type".to_string())))?;

                // convert the import_password to a cred
                let pw = Password::try_from(im_pw)
                    .map_err(|_| OperationError::Plugin(PluginError::PasswordImport("password_import was unable to convert hash format".to_string())))?;

                // does the entry have a primary cred?
                match e.get_ava_single_credential("primary_credential") {
                    Some(_c) => {
                        Err(
                            OperationError::Plugin(PluginError::PasswordImport(
                                "password_import - impossible state, how did you get a credential into a create!?".to_string()))
                        )
                    }
                    None => {
                        // just set it then!
                        let c = Credential::new_from_password(pw);
                        e.set_ava("primary_credential",
                            once(Value::new_credential("primary", c)));
                        Ok(())
                    }
                }
            })
    }

    #[instrument(
        level = "debug",
        name = "password_import_pre_modify",
        skip(_qs, cand, _me)
    )]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            // is there a password we are trying to import?
            let vs = match e.pop_ava("password_import") {
                Some(vs) => vs,
                None => return Ok(()),
            };
            // if there are multiple, fail.
            if vs.len() > 1 {
                return Err(OperationError::Plugin(PluginError::PasswordImport(
                    "multiple password_imports specified".to_string(),
                )));
            }

            let im_pw = vs.to_utf8_single().ok_or_else(|| {
                OperationError::Plugin(PluginError::PasswordImport(
                    "password_import has incorrect value type".to_string(),
                ))
            })?;

            // convert the import_password to a cred
            let pw = Password::try_from(im_pw).map_err(|_| {
                OperationError::Plugin(PluginError::PasswordImport(
                    "password_import was unable to convert hash format".to_string(),
                ))
            })?;

            // does the entry have a primary cred?
            match e.get_ava_single_credential("primary_credential") {
                Some(c) => {
                    // This is the major diff to create, we can update in place!
                    let c = c.update_password(pw);
                    e.set_ava(
                        "primary_credential",
                        once(Value::new_credential("primary", c)),
                    );
                    Ok(())
                }
                None => {
                    // just set it then!
                    let c = Credential::new_from_password(pw);
                    e.set_ava(
                        "primary_credential",
                        once(Value::new_credential("primary", c)),
                    );
                    Ok(())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
    use crate::credential::{Credential, CredentialType};
    use crate::prelude::*;

    const IMPORT_HASH: &'static str =
        "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";
    // const IMPORT_PASSWORD: &'static str = "eicieY7ahchaoCh0eeTa";

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

        run_create_test!(Ok(()), preload, create, None, |_| {});
    }

    #[test]
    fn test_modify_password_import_1() {
        // Add another uuid to a type
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
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
            filter!(f_eq("name", PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("password_import"),
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_modify_password_import_2() {
        // Add another uuid to a type
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let p = CryptoPolicy::minimum();
        let c = Credential::new_password_only(&p, "password").unwrap();
        ea.add_ava("primary_credential", Value::new_credential("primary", c));

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("password_import"),
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_modify_password_import_3_totp() {
        // Add another uuid to a type
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let p = CryptoPolicy::minimum();
        let c = Credential::new_password_only(&p, "password")
            .unwrap()
            .update_totp(totp);
        ea.add_ava("primary_credential", Value::new_credential("primary", c));

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("password_import"),
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(
                        &Uuid::parse_str("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap(),
                    )
                    .expect("failed to get entry");
                let c = e
                    .get_ava_single_credential("primary_credential")
                    .expect("failed to get primary cred.");
                match &c.type_ {
                    CredentialType::PasswordMfa(_pw, totp, webauthn, backup_code) => {
                        assert!(totp.is_some());
                        assert!(webauthn.is_empty());
                        assert!(backup_code.is_none());
                    }
                    _ => assert!(false),
                };
            }
        );
    }
}

// Transform password import requests into proper kanidm credentials.
use std::convert::TryFrom;
use std::iter::once;

use kanidm_proto::v1::PluginError;

use crate::credential::{Credential, Password};
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct CredImport {}

impl Plugin for CredImport {
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
        Self::modify_inner(cand)
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
        Self::modify_inner(cand)
    }

    #[instrument(level = "debug", name = "password_import_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand)
    }
}

impl CredImport {
    fn modify_inner<T: Clone>(cand: &mut [Entry<EntryInvalid, T>]) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            // PASSWORD IMPORT
            if let Some(vs) = e.pop_ava("password_import") {
                // if there are multiple, fail.
                let im_pw = vs.to_utf8_single().ok_or_else(|| {
                    OperationError::Plugin(PluginError::CredImport(
                        "password_import has incorrect value type - should be a single utf8 string"
                            .to_string(),
                    ))
                })?;

                // convert the import_password_string to a password
                let pw = Password::try_from(im_pw).map_err(|_| {
                    OperationError::Plugin(PluginError::CredImport(
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
                    }
                    None => {
                        // just set it then!
                        let c = Credential::new_from_password(pw);
                        e.set_ava(
                            "primary_credential",
                            once(Value::new_credential("primary", c)),
                        );
                    }
                }
            };

            // TOTP IMPORT
            if let Some(vs) = e.pop_ava("totp_import") {
                // Get the map.
                let totps = vs.as_totp_map().ok_or_else(|| {
                    OperationError::Plugin(PluginError::CredImport(
                        "totp_import has incorrect value type - should be a map of totp"
                            .to_string(),
                    ))
                })?;

                if let Some(c) = e.get_ava_single_credential("primary_credential") {
                    let c = totps.iter().fold(c.clone(), |acc, (label, totp)| {
                        acc.append_totp(label.clone(), totp.clone())
                    });
                    e.set_ava(
                        "primary_credential",
                        once(Value::new_credential("primary", c)),
                    );
                } else {
                    return Err(OperationError::Plugin(PluginError::CredImport(
                        "totp_import can not be used if primary_credential (password) is missing"
                            .to_string(),
                    )));
                }
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
    use crate::credential::{Credential, CredentialType};
    use crate::prelude::*;
    use kanidm_proto::v1::PluginError;

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
            .append_totp("totp".to_string(), totp);
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
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                let c = e
                    .get_ava_single_credential("primary_credential")
                    .expect("failed to get primary cred.");
                match &c.type_ {
                    CredentialType::PasswordMfa(_pw, totp, webauthn, backup_code) => {
                        assert!(totp.len() == 1);
                        assert!(webauthn.is_empty());
                        assert!(backup_code.is_none());
                    }
                    _ => assert!(false),
                };
            }
        );
    }

    #[test]
    fn test_modify_cred_import_pw_and_multi_totp() {
        let euuid = Uuid::new_v4();

        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson")),
            ("description", Value::Utf8("testperson".to_string())),
            ("displayname", Value::Utf8("testperson".to_string())),
            ("uuid", Value::Uuid(euuid))
        );

        let preload = vec![ea];

        let totp_a = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let totp_b = Totp::generate_secure(TOTP_DEFAULT_STEP);

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![
                Modify::Present(
                    AttrString::from("password_import"),
                    Value::Utf8(IMPORT_HASH.to_string())
                ),
                Modify::Present(
                    AttrString::from("totp_import"),
                    Value::TotpSecret("a".to_string(), totp_a.clone())
                ),
                Modify::Present(
                    AttrString::from("totp_import"),
                    Value::TotpSecret("b".to_string(), totp_b.clone())
                )
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(euuid).expect("failed to get entry");
                let c = e
                    .get_ava_single_credential("primary_credential")
                    .expect("failed to get primary cred.");
                match &c.type_ {
                    CredentialType::PasswordMfa(_pw, totp, webauthn, backup_code) => {
                        assert!(totp.len() == 2);
                        assert!(webauthn.is_empty());
                        assert!(backup_code.is_none());

                        assert!(totp.get("a") == Some(&totp_a));
                        assert!(totp.get("b") == Some(&totp_b));
                    }
                    _ => assert!(false),
                };
            }
        );
    }

    #[test]
    fn test_modify_cred_import_pw_missing_with_totp() {
        let euuid = Uuid::new_v4();

        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson")),
            ("description", Value::Utf8("testperson".to_string())),
            ("displayname", Value::Utf8("testperson".to_string())),
            ("uuid", Value::Uuid(euuid))
        );

        let preload = vec![ea];

        let totp_a = Totp::generate_secure(TOTP_DEFAULT_STEP);

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::CredImport(
                "totp_import can not be used if primary_credential (password) is missing"
                    .to_string()
            ))),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("totp_import"),
                Value::TotpSecret("a".to_string(), totp_a.clone())
            )]),
            None,
            |_| {},
            |_| {}
        );
    }
}

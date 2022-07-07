use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::utils::password_from_random;
use compact_jwt::JwsSigner;

lazy_static! {
    static ref CLASS_OAUTH2_BASIC: PartialValue =
        PartialValue::new_class("oauth2_resource_server_basic");
}

pub struct Oauth2Secrets {}

macro_rules! oauth2_transform {
    (
        $e:expr
    ) => {{
        if $e.attribute_equality("class", &CLASS_OAUTH2_BASIC) {
            if !$e.attribute_pres("oauth2_rs_basic_secret") {
                security_info!("regenerating oauth2 basic secret");
                let v = Value::new_utf8(password_from_random());
                $e.add_ava("oauth2_rs_basic_secret", v);
            }
            if !$e.attribute_pres("oauth2_rs_token_key") {
                security_info!("regenerating oauth2 token key");
                let k = fernet::Fernet::generate_key();
                let v = Value::new_secret_str(&k);
                $e.add_ava("oauth2_rs_token_key", v);
            }
            if !$e.attribute_pres("es256_private_key_der") {
                security_info!("regenerating oauth2 es256 private key");
                let der = JwsSigner::generate_es256()
                    .and_then(|jws| jws.private_key_to_der())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to generate ES256 JwsSigner private key");
                        OperationError::CryptographyError
                    })?;
                let v = Value::new_privatebinary(&der);
                $e.add_ava("es256_private_key_der", v);
            }
            if $e.get_ava_single_bool("oauth2_jwt_legacy_crypto_enable").unwrap_or(false) {
                if !$e.attribute_pres("rs256_private_key_der") {
                    security_info!("regenerating oauth2 legacy rs256 private key");
                    let der = JwsSigner::generate_legacy_rs256()
                        .and_then(|jws| jws.private_key_to_der())
                        .map_err(|e| {
                            admin_error!(err = ?e, "Unable to generate Legacy RS256 JwsSigner private key");
                            OperationError::CryptographyError
                        })?;
                    let v = Value::new_privatebinary(&der);
                    $e.add_ava("rs256_private_key_der", v);
                }
            }
        }
        Ok(())
    }};
}

impl Plugin for Oauth2Secrets {
    fn id() -> &'static str {
        "plugin_oauth2_secrets"
    }

    fn pre_create_transform(
        _qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| oauth2_transform!(e))
    }

    fn pre_modify(
        _qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| oauth2_transform!(e))
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn test_pre_create_oauth2_secrets() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let uuid = Uuid::new_v4();
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("uuid", Value::new_uuid(uuid)),
            ("displayname", Value::new_utf8s("test_resource_server")),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                "oauth2_rs_implicit_scopes",
                Value::new_oauthscope("read").expect("Invalid scope")
            )
        );

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(&uuid)
                    .expect("failed to get oauth2 config");
                assert!(e.attribute_pres("oauth2_rs_basic_secret"));
                assert!(e.attribute_pres("oauth2_rs_token_key"));
            }
        );
    }

    #[test]
    fn test_modify_oauth2_secrets_regenerate() {
        let uuid = Uuid::new_v4();

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("uuid", Value::new_uuid(uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                "oauth2_rs_implicit_scopes",
                Value::new_oauthscope("read").expect("Invalid scope")
            ),
            ("oauth2_rs_basic_secret", Value::new_utf8s("12345")),
            ("oauth2_rs_token_key", Value::new_secret_str("12345"))
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuid(uuid))),
            ModifyList::new_list(vec![
                Modify::Purged(AttrString::from("oauth2_rs_basic_secret"),),
                Modify::Purged(AttrString::from("oauth2_rs_token_key"),)
            ]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(&uuid)
                    .expect("failed to get oauth2 config");
                assert!(e.attribute_pres("oauth2_rs_basic_secret"));
                assert!(e.attribute_pres("oauth2_rs_token_key"));
                // Check the values are different.
                assert!(e.get_ava_single_utf8("oauth2_rs_basic_secret") != Some("12345"));
                assert!(e.get_ava_single_secret("oauth2_rs_token_key") != Some("12345"));
            }
        );
    }
}

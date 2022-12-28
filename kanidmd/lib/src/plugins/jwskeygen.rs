use compact_jwt::JwsSigner;

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::utils::password_from_random;

pub struct JwsKeygen {}

impl Plugin for JwsKeygen {
    fn id() -> &'static str {
        "plugin_jws_keygen"
    }

    #[instrument(level = "debug", name = "jwskeygen_pre_create_transform", skip_all)]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand)
    }

    #[instrument(level = "debug", name = "jwskeygen_pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand)
    }

    #[instrument(level = "debug", name = "jwskeygen_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand)
    }
}

impl JwsKeygen {
    fn modify_inner<T: Clone>(cand: &mut [Entry<EntryInvalid, T>]) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
        if e.attribute_equality("class", &PVCLASS_OAUTH2_BASIC) {
            if !e.attribute_pres("oauth2_rs_basic_secret") {
                security_info!("regenerating oauth2 basic secret");
                let v = Value::SecretValue(password_from_random());
                e.add_ava("oauth2_rs_basic_secret", v);
            }
            if !e.attribute_pres("oauth2_rs_token_key") {
                security_info!("regenerating oauth2 token key");
                let k = fernet::Fernet::generate_key();
                let v = Value::new_secret_str(&k);
                e.add_ava("oauth2_rs_token_key", v);
            }
            if !e.attribute_pres("es256_private_key_der") {
                security_info!("regenerating oauth2 es256 private key");
                let der = JwsSigner::generate_es256()
                    .and_then(|jws| jws.private_key_to_der())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to generate ES256 JwsSigner private key");
                        OperationError::CryptographyError
                    })?;
                let v = Value::new_privatebinary(&der);
                e.add_ava("es256_private_key_der", v);
            }
            if e.get_ava_single_bool("oauth2_jwt_legacy_crypto_enable").unwrap_or(false)
                && !e.attribute_pres("rs256_private_key_der") {
                security_info!("regenerating oauth2 legacy rs256 private key");
                let der = JwsSigner::generate_legacy_rs256()
                    .and_then(|jws| jws.private_key_to_der())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to generate Legacy RS256 JwsSigner private key");
                        OperationError::CryptographyError
                    })?;
                let v = Value::new_privatebinary(&der);
                e.add_ava("rs256_private_key_der", v);
            }
        }

        if (e.attribute_equality("class", &PVCLASS_SERVICE_ACCOUNT) ||
            e.attribute_equality("class", &PVCLASS_SYNC_ACCOUNT)) &&
            !e.attribute_pres("jws_es256_private_key") {
                security_info!("regenerating jws es256 private key");
                let jwssigner = JwsSigner::generate_es256()
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to generate ES256 JwsSigner private key");
                        OperationError::CryptographyError
                    })?;
                let v = Value::JwsKeyEs256(jwssigner);
                e.add_ava("jws_es256_private_key", v);
        }

        Ok(())
        })
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
            ("uuid", Value::Uuid(uuid)),
            ("displayname", Value::new_utf8s("test_resource_server")),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["read".to_string()])
                    .expect("invalid oauthscope")
            )
        );

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid)
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
            ("uuid", Value::Uuid(uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["read".to_string()])
                    .expect("invalid oauthscope")
            ),
            ("oauth2_rs_basic_secret", Value::new_secret_str("12345")),
            ("oauth2_rs_token_key", Value::new_secret_str("12345"))
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::Uuid(uuid))),
            ModifyList::new_list(vec![
                Modify::Purged(AttrString::from("oauth2_rs_basic_secret"),),
                Modify::Purged(AttrString::from("oauth2_rs_token_key"),)
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid)
                    .expect("failed to get oauth2 config");
                assert!(e.attribute_pres("oauth2_rs_basic_secret"));
                assert!(e.attribute_pres("oauth2_rs_token_key"));
                // Check the values are different.
                assert!(e.get_ava_single_secret("oauth2_rs_basic_secret") != Some("12345"));
                assert!(e.get_ava_single_secret("oauth2_rs_token_key") != Some("12345"));
            }
        );
    }
}

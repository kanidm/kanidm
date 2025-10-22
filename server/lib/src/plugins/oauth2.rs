use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::utils::password_from_random;
use crate::valueset::ValueSetUuid;
use compact_jwt::{crypto::JwsRs256Signer, JwsEs256Signer};
use std::sync::Arc;

pub struct OAuth2 {}

impl Plugin for OAuth2 {
    fn id() -> &'static str {
        "plugin_oauth2"
    }

    #[instrument(level = "debug", name = "oauth2_pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "oauth2_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "oauth2_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }
}

impl OAuth2 {
    fn modify_inner<T: Clone>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        let domain_level = qs.get_domain_version();

        // Do I need some other kind of uuid generator here for oauth2 trust provider creds?
        cand.iter_mut()
            .filter(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::PersonOAuth2Trust.into())
            })
            .for_each(|entry| {
                if entry
                    .get_ava_set(Attribute::OAuth2TrustCredentialUuid)
                    .is_none()
                {
                    entry.set_ava_set(
                        &Attribute::OAuth2TrustCredentialUuid,
                        ValueSetUuid::new(Uuid::new_v4()),
                    )
                }
            });

        // Populate attributes into the oauth2 clients.
        cand.iter_mut()
            .filter(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
            })
            .try_for_each(|entry| {
                // Regenerate the basic secret, if needed
                if entry.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServerBasic.into()) &&
                    !entry.attribute_pres(Attribute::OAuth2RsBasicSecret) {
                        security_info!("regenerating oauth2 basic secret");
                        let v = Value::SecretValue(password_from_random());
                        entry.add_ava(Attribute::OAuth2RsBasicSecret, v);
                }

            let has_rs256 = entry.get_ava_single_bool(Attribute::OAuth2JwtLegacyCryptoEnable).unwrap_or(false);

            if domain_level >= DOMAIN_LEVEL_10 {
                debug!("Generating OAuth2 Key Object");
                // OAuth2 now requires a KeyObject, configure it now.
                entry.add_ava(Attribute::Class, EntryClass::KeyObject.to_value());
                entry.add_ava(Attribute::Class, EntryClass::KeyObjectJwtEs256.to_value());
                entry.add_ava(Attribute::Class, EntryClass::KeyObjectJweA128GCM.to_value());
                if has_rs256 {
                    entry.add_ava(Attribute::Class, EntryClass::KeyObjectJwtRs256.to_value());
                }
            } else {
                if !entry.attribute_pres(Attribute::OAuth2RsTokenKey) {
                    security_info!("regenerating oauth2 token key");
                    let k = password_from_random();
                    let v = Value::new_secret_str(&k);
                    entry.add_ava(Attribute::OAuth2RsTokenKey, v);
                }
                if !entry.attribute_pres(Attribute::Es256PrivateKeyDer) {
                    security_info!("regenerating oauth2 es256 private key");
                    let der = JwsEs256Signer::generate_es256()
                        .and_then(|jws| jws.private_key_to_der())
                        .map_err(|e| {
                            admin_error!(err = ?e, "Unable to generate ES256 JwsSigner private key");
                            OperationError::CryptographyError
                        })?;
                    let v = Value::new_privatebinary(&der);
                    entry.add_ava(Attribute::Es256PrivateKeyDer, v);
                }
                    if has_rs256 && !entry.attribute_pres(Attribute::Rs256PrivateKeyDer) {
                    security_info!("regenerating oauth2 legacy rs256 private key");
                    let der = JwsRs256Signer::generate_rs256()
                        .and_then(|jws| jws.private_key_to_der())
                        .map_err(|e| {
                            admin_error!(err = ?e, "Unable to generate Legacy RS256 JwsSigner private key");
                            OperationError::CryptographyError
                        })?;
                    let v = Value::new_privatebinary(&der);
                    entry.add_ava(Attribute::Rs256PrivateKeyDer, v);
                }
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
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::with_capacity(0);

        let uuid = Uuid::new_v4();
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_READ.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let create = vec![e];

        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid)
                    .expect("failed to get oauth2 config");
                assert!(e.attribute_pres(Attribute::OAuth2RsBasicSecret));
            }
        );
    }

    #[test]
    fn test_modify_oauth2_secrets_regenerate() {
        let uuid = Uuid::new_v4();

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_READ.to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsBasicSecret,
                Value::new_secret_str("12345")
            )
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::OAuth2RsBasicSecret,),
                Modify::Purged(Attribute::OAuth2RsTokenKey,)
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid)
                    .expect("failed to get oauth2 config");
                assert!(e.attribute_pres(Attribute::OAuth2RsBasicSecret));
                // Check the values are different.
                assert!(e.get_ava_single_secret(Attribute::OAuth2RsBasicSecret) != Some("12345"));
            }
        );
    }
}

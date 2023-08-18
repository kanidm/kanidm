use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;

use crate::prelude::*;

use super::Plugin;

lazy_static! {
    // it contains all the partialvalues used to match against an Entry's class,
    // we need ALL partialvalues to match in order to target the entry
    static ref DEFAULT_KEY_GROUP: EcGroup = {
        let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
        #[allow(clippy::unwrap_used)]
        EcGroup::from_curve_name(nid).unwrap()
    };
}

pub struct EcdhKeyGen {}

impl EcdhKeyGen {
    // we optionally provide a target_cand to update only the entry with the given uuid
    fn generate_key<STATE: Clone>(
        cands: &mut [Entry<EntryInvalid, STATE>],
    ) -> Result<(), OperationError> {
        for cand in cands.iter_mut() {
            if cand.attribute_equality("class", &EntryClass::Person.to_partialvalue())
                && !cand.attribute_pres("id_verification_eckey")
            {
                debug!("Generating idv_eckey for {}", cand.get_display_id());

                let new_private_key = EcKey::generate(&DEFAULT_KEY_GROUP).map_err(|e| {
                    error!(err = ?e, "Unable to generate id verification ECDH private key");
                    OperationError::CryptographyError
                })?;
                cand.add_ava_if_not_exist(
                    ATTR_ID_VERIFICATION_ECKEY,
                    crate::value::Value::EcKeyPrivate(new_private_key),
                )
            }
        }
        Ok(())
    }
}

impl Plugin for EcdhKeyGen {
    fn id() -> &'static str {
        "plugin_ecdhkey_gen"
    }

    #[instrument(level = "debug", name = "ecdhkeygen::pre_create_transform", skip_all)]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::generate_key(cand)
    }

    #[instrument(level = "debug", name = "ecdhkeygen::pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut crate::server::QueryServerWriteTransaction,
        _pre_cand: &[std::sync::Arc<crate::prelude::EntrySealedCommitted>],
        cand: &mut Vec<crate::prelude::EntryInvalidCommitted>,
        _me: &crate::event::ModifyEvent,
    ) -> Result<(), kanidm_proto::v1::OperationError> {
        Self::generate_key(cand)
    }

    #[instrument(level = "debug", name = "ecdhkeygen::pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        _qs: &mut crate::server::QueryServerWriteTransaction,
        _pre_cand: &[std::sync::Arc<crate::prelude::EntrySealedCommitted>],
        cand: &mut Vec<crate::prelude::EntryInvalidCommitted>,
        _me: &crate::server::batch_modify::BatchModifyEvent,
    ) -> Result<(), kanidm_proto::v1::OperationError> {
        Self::generate_key(cand)
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::constants::*;
    use openssl::ec::EcKey;
    use uuid::Uuid;

    use crate::plugins::eckeygen::DEFAULT_KEY_GROUP;
    use crate::prelude::*;
    use crate::value::Value;
    use crate::valueset;

    #[test]
    fn test_new_user_generate_key() {
        let uuid = Uuid::new_v4();
        let ea = entry_init!(
            (ATTR_CLASS, EntryClass::Account.to_value()),
            (ATTR_CLASS, EntryClass::Person.to_value()),
            (ATTR_CLASS, EntryClass::Object.to_value()),
            (ATTR_NAME, Value::new_iname("test_name")),
            (ATTR_UUID, Value::Uuid(uuid)),
            (ATTR_DESCRIPTION, Value::new_utf8s("testperson")),
            (ATTR_DISPLAYNAME, Value::new_utf8s("Test Person"))
        );
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let create = vec![ea];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(uuid).expect("failed to get entry");

                let key = e
                    .get_ava_single_eckey_private(ATTR_ID_VERIFICATION_ECKEY)
                    .expect("unable to retrieve the ecdh key");

                assert!(key.check_key().is_ok())
            }
        );
    }

    /*
    // Invalid, can't be set due to no impl from clone_value

    #[test]
    fn test_modify_present_ecdkey() {
        let ea = entry_init!(
            (ATTR_CLASS, EntryClass::Account.to_value()),
            (ATTR_CLASS, EntryClass::Person.to_value()),
            (ATTR_CLASS, EntryClass::Object.to_value()),
            (ATTR_NAME, Value::new_iname("test_name")),
            (ATTR_DESCRIPTION, Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("Test person!"))
        );
        let preload = vec![ea];
        let new_private_key = EcKey::generate(&DEFAULT_KEY_GROUP).unwrap();
        run_modify_test!(
            Err(OperationError::SystemProtectedAttribute),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("test_name"))),
            modlist!([m_pres(
                ATTR_ID_VERIFICATION_ECKEY,
                &Value::EcKeyPrivate(new_private_key)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }
    */

    #[test]
    fn test_modify_purge_eckey() {
        let private_key = EcKey::generate(&DEFAULT_KEY_GROUP).unwrap();
        let private_key_value = Value::EcKeyPrivate(private_key.clone());

        let uuid = Uuid::new_v4();

        let ea = entry_init!(
            (ATTR_CLASS, EntryClass::Account.to_value()),
            (ATTR_CLASS, EntryClass::Person.to_value()),
            (ATTR_CLASS, EntryClass::Object.to_value()),
            (ATTR_NAME, Value::new_iname("test_name")),
            (ATTR_UUID, Value::Uuid(uuid)),
            (ATTR_ID_VERIFICATION_ECKEY, private_key_value.clone()),
            (ATTR_DESCRIPTION, Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("Test person!"))
        );
        let key_partialvalue = valueset::from_value_iter(std::iter::once(private_key_value))
            .unwrap()
            .to_partialvalue_iter()
            .next()
            .unwrap();
        let preload = vec![ea];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("test_name"))),
            modlist!([m_purge("id_verification_eckey")]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(uuid).expect("failed to get entry");

                assert!(
                    !e.attribute_equality(ATTR_ID_VERIFICATION_ECKEY, &key_partialvalue)
                        && e.attribute_pres(ATTR_ID_VERIFICATION_ECKEY)
                )
            }
        );
    }
    #[test]
    fn test_modify_remove_eckey() {
        let private_key = EcKey::generate(&DEFAULT_KEY_GROUP).unwrap();
        let private_key_value = Value::EcKeyPrivate(private_key.clone());

        let uuid = Uuid::new_v4();

        let ea = entry_init!(
            (ATTR_CLASS, EntryClass::Account.to_value()),
            (ATTR_CLASS, EntryClass::Person.to_value()),
            (ATTR_CLASS, EntryClass::Object.to_value()),
            (ATTR_NAME, Value::new_iname("test_name")),
            (ATTR_UUID, Value::Uuid(uuid)),
            (ATTR_ID_VERIFICATION_ECKEY, private_key_value.clone()),
            (ATTR_DESCRIPTION, Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("Test person!"))
        );
        let key_partialvalue = valueset::from_value_iter(std::iter::once(private_key_value))
            .unwrap()
            .to_partialvalue_iter()
            .next()
            .unwrap();
        let preload = vec![ea];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("test_name"))),
            modlist!([m_remove("id_verification_eckey", &key_partialvalue)]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(uuid).expect("failed to get entry");

                assert!(
                    !e.attribute_equality(ATTR_ID_VERIFICATION_ECKEY, &key_partialvalue)
                        && e.attribute_pres(ATTR_ID_VERIFICATION_ECKEY)
                )
            }
        );
    }
}

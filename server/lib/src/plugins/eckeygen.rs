use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use sketching::{admin_error, security_info};
use uuid::Uuid;

use super::Plugin;
use crate::event::{CreateEvent, ModifyEvent};
use crate::modify::{ModifyList, ModifyValid};
use crate::prelude::{BatchModifyEvent, EntryInvalidCommitted, Modify};
use crate::prelude::{Entry, EntryInvalid, EntryInvalidNew, OperationError};
use crate::server::QueryServerWriteTransaction;
use crate::value::PartialValue;
use sketching::tagged_event;
use sketching::EventTag;

lazy_static! {
    // it contains all the partialvalues used to match against an Entry's class,
    // we need ALL partialvalues to match in order to target the entry
    static ref CLASSES_TO_UPDATE: [PartialValue; 3] = [PartialValue::new_iutf8("account"), PartialValue::new_iutf8("person"), PartialValue::new_iutf8("object")];

    static ref DEFAULT_KEY_GROUP: EcGroup = {
        let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
        #[allow(clippy::unwrap_used)]
        EcGroup::from_curve_name(nid).unwrap()
    };
}
pub struct EcdhKeyGen {}

impl EcdhKeyGen {
    fn is_entry_to_update<VALUE, STATE>(entry: &mut Entry<VALUE, STATE>) -> bool {
        CLASSES_TO_UPDATE
            .iter()
            .all(|pv| entry.attribute_equality("class", pv))
    }
    // we optionally provide a target_cand to update only the entry with the given uuid
    fn generate_key<STATE: Clone>(
        cands: &mut [Entry<EntryInvalid, STATE>],
        target_cand: Option<Uuid>,
    ) -> Result<(), OperationError> {
        for cand in cands.iter_mut() {
            if Self::is_entry_to_update(cand) {
                if let (Some(target_cand), Some(current_uuid)) = (target_cand, cand.get_uuid()) {
                    if target_cand != current_uuid {
                        continue;
                    }
                }
                let new_private_key = EcKey::generate(&DEFAULT_KEY_GROUP).map_err(|e| {
                    admin_error!(err = ?e, "Unable to generate identification ECDH private key");
                    OperationError::CryptographyError
                })?;
                cand.add_ava_if_not_exist(
                    "id_verification_eckey",
                    crate::value::Value::EcKeyPrivate(new_private_key),
                )
            }
        }
        Ok(())
    }

    fn handle_modify(
        cands: &mut [EntryInvalidCommitted],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        if Self::should_regenerate_ecdh_key(&me.modlist)? {
            security_info!("regenerating personal ecdh secret");
            Self::generate_key(cands, None)?;
        };

        Ok(())
    }

    fn handle_batch_modify(
        cands: &mut [EntryInvalidCommitted],
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        for (uuid, modlist) in me.modset.iter() {
            if Self::should_regenerate_ecdh_key(modlist)? {
                security_info!("regenerating personal ecdh secret");
                Self::generate_key(cands, Some(*uuid))?;
            };
        }
        Ok(())
    }

    fn should_regenerate_ecdh_key(
        modlist: &ModifyList<ModifyValid>,
    ) -> Result<bool, OperationError> {
        let modify_present_attempted = modlist.iter().any(|m| match m {
            Modify::Present(a, _) => a == "id_verification_eckey",
            _ => false,
        });
        if modify_present_attempted {
            Err(OperationError::SystemProtectedAttribute)
        } else {
            let should_regenerate_ecdh_key = modlist.iter().any(|m| match m {
                Modify::Purged(a) | Modify::Removed(a, _) => a == "id_verification_eckey",
                _ => false,
            });
            Ok(should_regenerate_ecdh_key)
        }
    }
}

impl Plugin for EcdhKeyGen {
    fn id() -> &'static str {
        "plugin_ecdhkey_gen"
    }

    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::generate_key(cand, None)
    }

    fn pre_modify(
        _qs: &mut crate::server::QueryServerWriteTransaction,
        _pre_cand: &[std::sync::Arc<crate::prelude::EntrySealedCommitted>],
        cand: &mut Vec<crate::prelude::EntryInvalidCommitted>,
        me: &crate::event::ModifyEvent,
    ) -> Result<(), kanidm_proto::v1::OperationError> {
        Self::handle_modify(cand, me)
    }

    fn pre_batch_modify(
        _qs: &mut crate::server::QueryServerWriteTransaction,
        _pre_cand: &[std::sync::Arc<crate::prelude::EntrySealedCommitted>],
        cand: &mut Vec<crate::prelude::EntryInvalidCommitted>,
        me: &crate::server::batch_modify::BatchModifyEvent,
    ) -> Result<(), kanidm_proto::v1::OperationError> {
        Self::handle_batch_modify(cand, me)
    }
}

#[cfg(test)]
mod tests {
    use openssl::ec::EcKey;
    use uuid::Uuid;

    use crate::plugins::eckeygen::DEFAULT_KEY_GROUP;
    use crate::prelude::{Entry, EntryInit, EntryNew};
    use crate::value::Value;
    use crate::valueset;

    #[test]
    fn test_new_user_generate_key() {
        let uuid = Uuid::new_v4();
        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("object")),
            ("name", Value::new_iname("test_name")),
            ("uuid", Value::Uuid(uuid)),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("Test Person"))
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
                    .get_ava_single_eckey_private("id_verification_eckey")
                    .expect("unable to retrieve the ecdh key");

                assert!(key.check_key().is_ok())
            }
        );
    }

    #[test]
    fn test_modify_present_ecdkey() {
        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("object")),
            ("name", Value::new_iname("test_name")),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("Test person!"))
        );
        let preload = vec![ea];
        let new_private_key = EcKey::generate(&DEFAULT_KEY_GROUP).unwrap();
        run_modify_test!(
            Err(OperationError::SystemProtectedAttribute),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("test_name"))),
            modlist!([m_pres(
                "id_verification_eckey",
                &Value::EcKeyPrivate(new_private_key)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_modify_purge_eckey() {
        let private_key = EcKey::generate(&DEFAULT_KEY_GROUP).unwrap();
        let private_key_value = Value::EcKeyPrivate(private_key.clone());

        let uuid = Uuid::new_v4();

        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("object")),
            ("name", Value::new_iname("test_name")),
            ("uuid", Value::Uuid(uuid)),
            ("id_verification_eckey", private_key_value.clone()),
            ("description", Value::new_utf8s("testperson")),
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
            filter!(f_eq("name", PartialValue::new_iname("test_name"))),
            modlist!([m_purge("id_verification_eckey")]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(uuid).expect("failed to get entry");

                assert!(
                    !e.attribute_equality("id_verification_eckey", &key_partialvalue)
                        && e.attribute_pres("id_verification_eckey")
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
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("object")),
            ("name", Value::new_iname("test_name")),
            ("uuid", Value::Uuid(uuid)),
            ("id_verification_eckey", private_key_value.clone()),
            ("description", Value::new_utf8s("testperson")),
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
            filter!(f_eq("name", PartialValue::new_iname("test_name"))),
            modlist!([m_remove("id_verification_eckey", &key_partialvalue)]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(uuid).expect("failed to get entry");

                assert!(
                    !e.attribute_equality("id_verification_eckey", &key_partialvalue)
                        && e.attribute_pres("id_verification_eckey")
                )
            }
        );
    }
}

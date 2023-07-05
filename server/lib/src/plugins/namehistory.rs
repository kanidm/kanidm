use std::sync::Arc;

use kanidm_proto::v1::OperationError;

use crate::entry::{EntryInvalidCommitted, EntrySealedCommitted};
use crate::event::ModifyEvent;
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::prelude::{BatchModifyEvent, QueryServerWriteTransaction};
use crate::repl::cid::Cid;
use crate::value::PartialValue;

pub struct NameHistory {}

lazy_static! {
    // it contains all the partialvalues used to match against an Entry's class,
    // we just need a partialvalue to match in order to target the entry
    static ref CLASSES_TO_UPDATE: [PartialValue; 1] = [PartialValue::new_iutf8("account")];
    static ref HISTORY_ATTRIBUTES: [&'static str;1] = ["name"];
}

impl NameHistory {
    fn is_entry_to_update<VALUE, STATE>(entry: &mut Entry<VALUE, STATE>) -> bool {
        CLASSES_TO_UPDATE
            .iter()
            .any(|pv| entry.attribute_equality("class", pv))
    }

    fn get_ava_name(history_attr: &str) -> String {
        format!("{}_history", history_attr)
    }

    fn handle_name_updates(
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        for (pre, post) in pre_cand.iter().zip(cand) {
            // here we check if the current entry has at least one of the classes we intend to target
            if Self::is_entry_to_update(post) {
                for history_attr in HISTORY_ATTRIBUTES.iter() {
                    let pre_name_option = pre.get_ava_single(history_attr);
                    let post_name_option = post.get_ava_single(history_attr);
                    if let (Some(pre_name), Some(post_name)) = (pre_name_option, post_name_option) {
                        if pre_name != post_name {
                            let ava_name = Self::get_ava_name(history_attr);
                            //// WARNING!!! this match will have to be adjusted based on what kind of attribute
                            //// we are matching on, for example for displayname we would have to use Value::utf8 instead!!
                            // as of now we're interested just in the name so we use Iname
                            match post_name {
                                Value::Iname(n) => post.add_ava_if_not_exist(
                                    &ava_name,
                                    Value::AuditLogString(cid.clone(), n),
                                ),
                                _ => return Err(OperationError::InvalidValueState),
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_name_creation(
        cands: &mut [EntryInvalidNew],
        cid: &Cid,
    ) -> Result<(), OperationError> {
        for cand in cands.iter_mut() {
            if Self::is_entry_to_update(cand) {
                for history_attr in HISTORY_ATTRIBUTES.iter() {
                    if let Some(name) = cand.get_ava_single(history_attr) {
                        let ava_name = Self::get_ava_name(history_attr);
                        match name {
                            Value::Iname(n) => cand.add_ava_if_not_exist(
                                &ava_name,
                                Value::AuditLogString(cid.clone(), n),
                            ),
                            _ => return Err(OperationError::InvalidValueState),
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Plugin for NameHistory {
    fn id() -> &'static str {
        "plugin_name_history"
    }

    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::handle_name_creation(cand, qs.get_txn_cid())
    }

    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::handle_name_updates(pre_cand, cand, qs.get_txn_cid())
    }

    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::handle_name_updates(pre_cand, cand, qs.get_txn_cid())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::prelude::uuid;
    use crate::repl::cid::Cid;
    use crate::value::Value;

    #[test]
    fn name_purge_and_set() {
        // Add another uuid to a type
        let cid = Cid::new(
            uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"),
            Duration::new(20, 2),
        );
        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("old_name")),
            (
                "uuid",
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            ),
            (
                "name_history",
                Value::new_audit_log_string((cid.clone(), "old_name".to_string())).unwrap()
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("old name person"))
        );
        let preload = vec![ea];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("old_name"))),
            modlist!([
                m_purge("name"),
                m_pres("name", &Value::new_iname("new_name_1"))
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                let c = e
                    .get_ava_set("name_history")
                    .expect("failed to get primary cred.");
                dbg!(c.clone());
                return assert!(
                    c.contains(&PartialValue::new_utf8s("old_name"))
                        && c.contains(&PartialValue::new_utf8s("new_name_1"))
                );
            }
        );
    }

    #[test]
    fn name_creation() {
        // Add another uuid to a type
        let ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("old_name")),
            (
                "uuid",
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47e1"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("old name person"))
        );
        let preload = Vec::new();
        let create = vec![ea];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47e1"))
                    .expect("failed to get entry");
                dbg!(e.get_ava());
                let name_history = e
                    .get_ava_set("name_history")
                    .expect("failed to get name_history ava");

                return assert!(name_history.contains(&PartialValue::new_utf8s(&"old_name")));
            }
        );
    }

    #[test]
    fn name_purge_and_set_with_filled_history() {
        let mut cids: Vec<Cid> = Vec::new();
        for i in 1..8 {
            cids.push(Cid::new(
                uuid!("d2b496bd-8493-47b7-8142-f568b5cf47e1"),
                Duration::new(20 + i, 0),
            ))
        }
        // Add another uuid to a type
        let mut ea = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("old_name8")),
            (
                "uuid",
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("old name person"))
        );
        for (i, cid) in cids.iter().enumerate() {
            let index = 1 + i;
            let name = format!("old_name{index}");
            ea.add_ava("name_history", Value::AuditLogString(cid.clone(), name))
        }
        let preload = vec![ea];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("old_name8"))),
            modlist!([
                m_purge("name"),
                m_pres("name", &Value::new_iname("new_name"))
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                dbg!(e.get_ava());
                let c = e
                    .get_ava_set("name_history")
                    .expect("failed to get name_history ava :/");
                return assert!(
                    !c.contains(&PartialValue::new_utf8s(&"old_name1"))
                        && c.contains(&PartialValue::new_utf8s(&"new_name"))
                );
            }
        );
    }
}

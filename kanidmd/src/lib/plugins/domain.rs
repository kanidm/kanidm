// Manage and generate domain uuid's and/or trust related domain
// management.

// The primary point of this is to generate a unique domain UUID on startup
// which is importart for management of the replication topo and trust
// relationships.
use crate::plugins::Plugin;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryInvalid, EntryNew};
use crate::event::CreateEvent;
use crate::server::QueryServerWriteTransaction;
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::OperationError;

use uuid::Uuid;

lazy_static! {
    static ref PVCLASS_DOMAIN_INFO: PartialValue = PartialValue::new_class("domain_info");
}

pub struct Domain {}

impl Plugin for Domain {
    fn id() -> &'static str {
        "plugin_domain"
    }

    fn pre_create_transform(
        au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        audit_log!(au, "Entering base pre_create_transform");
        cand.iter_mut().for_each(|e| {
            audit_log!(au, "{:?}", e);
            if e.attribute_value_pres("class", &PVCLASS_DOMAIN_INFO)
                && !e.attribute_pres("domain_uuid")
            {
                let u = Value::new_uuid(Uuid::new_v4());
                e.set_avas("domain_uuid", vec![u]);
                audit_log!(au, "Applying uuid transform");
            }
            audit_log!(au, "{:?}", e);
        });
        audit_log!(au, "Ending base pre_create_transform");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
    use uuid::Uuid;
    // test we can create and generate the id
    #[test]
    fn test_domain_generate_uuid() {
        let preload = vec![];
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info", "system"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generaiton"],
                "domain_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"]
            }
        }"#,
        );
        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au, qs_write: &QueryServerWriteTransaction| {
                // Check that a uuid was added?
                let e = qs_write
                    .internal_search_uuid(
                        au,
                        &Uuid::parse_str("96fd1112-28bc-48ae-9dda-5acb4719aaba").unwrap(),
                    )
                    .unwrap();
                assert!(e.get_ava("domain_uuid").is_some());
            }
        );
    }
}

// Manage and generate domain uuid's and/or trust related domain
// management.

// The primary point of this is to generate a unique domain UUID on startup
// which is importart for management of the replication topo and trust
// relationships.
use crate::plugins::Plugin;
use uuid::Uuid;

use crate::audit::AuditScope;
use crate::constants::UUID_DOMAIN_INFO;
use crate::entry::{Entry, EntryInvalid, EntryNew};
use crate::event::CreateEvent;
use crate::server::QueryServerWriteTransaction;
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::OperationError;

lazy_static! {
    static ref PVCLASS_DOMAIN_INFO: PartialValue = PartialValue::new_class("domain_info");
    static ref PVUUID_DOMAIN_INFO: PartialValue = PartialValue::new_uuid(
        Uuid::parse_str(UUID_DOMAIN_INFO).expect("Unable to parse constant UUID_DOMAIN_INFO")
    );
}

pub struct Domain {}

impl Plugin for Domain {
    fn id() -> &'static str {
        "plugin_domain"
    }

    fn pre_create_transform(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        audit_log!(au, "Entering base pre_create_transform");
        cand.iter_mut().for_each(|e| {
            if e.attribute_value_pres("class", &PVCLASS_DOMAIN_INFO)
                && e.attribute_value_pres("uuid", &PVUUID_DOMAIN_INFO)
            {
                // We always set this, because the DB uuid is authorative.
                let u = Value::new_uuid(qs.get_domain_uuid());
                e.set_avas("domain_uuid", vec![u]);
                audit_log!(au, "plugin_domain: Applying uuid transform");
                // We only apply this if one isn't provided.
                if !e.attribute_pres("domain_name") {
                    let n = Value::new_iutf8s("example.com");
                    e.set_avas("domain_name", vec![n]);
                    audit_log!(au, "plugin_domain: Applying domain_name transform");
                }
                audit_log!(au, "{:?}", e);
            }
        });
        audit_log!(au, "Ending base pre_create_transform");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::UUID_DOMAIN_INFO;
    use crate::server::QueryServerTransaction;
    use crate::value::PartialValue;
    use uuid::Uuid;
    // test we can create and generate the id
    #[test]
    fn test_domain_generate_uuid() {
        run_test!(|server: &QueryServer, au: &mut AuditScope| {
            let mut server_txn = server.write(duration_from_epoch_now());
            let uuid_domain = Uuid::parse_str(UUID_DOMAIN_INFO)
                .expect("Unable to parse constant UUID_DOMAIN_INFO");
            let e_dom = server_txn
                .internal_search_uuid(au, &uuid_domain)
                .expect("must not fail");

            let u_dom = server_txn.get_domain_uuid();

            assert!(e_dom.attribute_value_pres("domain_uuid", &PartialValue::new_uuid(u_dom)));
        })
    }
}

// Manage and generate domain uuid's and/or trust related domain
// management.

// The primary point of this is to generate a unique domain UUID on startup
// which is importart for management of the replication topo and trust
// relationships.
use crate::plugins::Plugin;

use crate::event::{CreateEvent, ModifyEvent};
use crate::prelude::*;
// use compact_jwt::JwsSigner;
use kanidm_proto::v1::OperationError;
use std::iter::once;
use tracing::trace;

lazy_static! {
    static ref PVCLASS_SYSTEM_CONFIG: PartialValue = PartialValue::new_class("system_config");
    static ref PVUUID_SYSTEM_CONFIG: PartialValue = PartialValue::new_uuid(UUID_SYSTEM_CONFIG);
}

pub struct SystemConfig {}

impl Plugin for SystemConfig {
    fn id() -> &'static str {
        "plugin_domain"
    }

    fn pre_create_transform(
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            if e.attribute_equality("class", &PVCLASS_SYSTEM_CONFIG)
                && e.attribute_equality("uuid", &PVUUID_SYSTEM_CONFIG)
            {
                // create the domain_display_name if it's missing
                if !e.attribute_pres("domain_display_name") {
                    let domain_display_name = Value::new_utf8(format!("Kanidm {}", qs.get_domain_name()));
                    security_info!(
                        "plugin_system_config: setting default domain_display_name to {:?} in pre_create_transform",
                        domain_display_name
                    );

                    e.set_ava("domain_display_name", once(domain_display_name));
                }
                trace!(?e);
                Ok(())
            } else {
                Ok(())
            }
        })
    }

    fn pre_modify(
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            if e.attribute_equality("class", &PVCLASS_SYSTEM_CONFIG)
                && e.attribute_equality("uuid", &PVUUID_SYSTEM_CONFIG)
            {
                // create the domain_display_name if it's missing
                if !e.attribute_pres("domain_display_name") {
                    let n = Value::new_utf8(format!("Kanidm {}", qs.get_domain_name()));
                    security_info!(
                        "plugin_system_config: pre_modify setting default domain_display_name to {:?}",
                        n
                    );
                    e.set_ava("domain_display_name", once(n));
                }
                trace!(?e);
                Ok(())
            } else {
                Ok(())
            }
        })
    }
}

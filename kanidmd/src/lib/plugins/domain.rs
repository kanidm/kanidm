// Manage and generate domain uuid's and/or trust related domain
// management.

// The primary point of this is to generate a unique domain UUID on startup
// which is importart for management of the replication topo and trust
// relationships.
use crate::plugins::Plugin;

use crate::event::{CreateEvent, ModifyEvent};
use crate::prelude::*;
use bundy::hs512::HS512;
use kanidm_proto::v1::OperationError;
use std::iter::once;
use tracing::trace;

lazy_static! {
    static ref PVCLASS_DOMAIN_INFO: PartialValue = PartialValue::new_class("domain_info");
    static ref PVUUID_DOMAIN_INFO: PartialValue = PartialValue::new_uuidr(&UUID_DOMAIN_INFO);
}

pub struct Domain {}

impl Plugin for Domain {
    fn id() -> &'static str {
        "plugin_domain"
    }

    fn pre_create_transform(
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            if e.attribute_equality("class", &PVCLASS_DOMAIN_INFO)
                && e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)
            {
                // We always set this, because the DB uuid is authorative.
                let u = Value::new_uuid(qs.get_domain_uuid());
                e.set_ava("domain_uuid", once(u));
                trace!("plugin_domain: Applying uuid transform");
                // We only apply this if one isn't provided.
                if !e.attribute_pres("domain_name") {
                    let n = Value::new_iname(qs.get_domain_name());
                    e.set_ava("domain_name", once(n));
                    trace!("plugin_domain: Applying domain_name transform");
                }
                if !e.attribute_pres("domain_token_key") {
                    let k = HS512::generate_key()
                        .map(|k| Value::new_secret_str(&k))
                        .map_err(|e| {
                            admin_error!(err = ?e, "Failed to generate domain_token_key");
                            OperationError::InvalidState
                        })?;
                    e.set_ava("domain_token_key", once(k));
                    trace!("plugin_domain: Applying domain_token_key transform");
                }
                trace!(?e);
                Ok(())
            } else {
                Ok(())
            }
        })
    }

    fn pre_modify(
        _qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            if e.attribute_equality("class", &PVCLASS_DOMAIN_INFO)
                && e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)
            {
                if !e.attribute_pres("domain_token_key") {
                    let k = HS512::generate_key()
                        .map(|k| Value::new_secret_str(&k))
                        .map_err(|e| {
                            admin_error!(err = ?e, "Failed to generate domain_token_key");
                            OperationError::InvalidState
                        })?;
                    e.set_ava("domain_token_key", once(k));
                    trace!("plugin_domain: Applying domain_token_key transform");
                }
                trace!(?e);
                Ok(())
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    // use crate::prelude::*;

    // test we can create and generate the id
    #[test]
    fn test_domain_generate_uuid() {
        run_test!(|server: &QueryServer| {
            let server_txn = server.write(duration_from_epoch_now());
            let e_dom = server_txn
                .internal_search_uuid(&UUID_DOMAIN_INFO)
                .expect("must not fail");

            let u_dom = server_txn.get_domain_uuid();

            assert!(e_dom.attribute_equality("domain_uuid", &PartialValue::new_uuid(u_dom)));
        })
    }
}

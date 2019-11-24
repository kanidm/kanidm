// Generate and manage spn's for all entries in the domain. Also deals with
// the infrequent - but possible - case where a domain is renamed.
use crate::plugins::Plugin;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryInvalid, EntryValid, EntryNew, EntryCommitted};
use crate::event::{CreateEvent, ModifyEvent};
use crate::server::{QueryServerWriteTransaction, QueryServerReadTransaction};
// use crate::value::{PartialValue, Value};
use kanidm_proto::v1::{OperationError, ConsistencyError};

pub struct Spn {}

impl Plugin for Spn {
    fn id() -> &'static str {
        "plugin_spn"
    }

    // hook on pre-create and modify to generate / validate.
    fn pre_create_transform(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Always generate the spn and set it. Why? Because the effort
        // needed to validate is the same as generation, so we may as well
        // just generate and set blindly when required.
        unimplemented!();
    }

    fn pre_modify(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // Always generate and set *if* spn was an attribute on any of the mod
        // list events.
        unimplemented!();
    }

    fn post_modify(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // On modify, if changing domain_name on UUID_DOMAIN_INFO
        //    trigger the spn regen ... which is expensive. Future
        // todo will be a way to batch this I guess ...
        unimplemented!();
    }

    fn verify(
        _au: &mut AuditScope,
        _qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        // Verify that all items with spn's have valid spns.
        //   We need to consider the case that an item has a different origin domain too,
        // so we should be able to verify that *those* spns validate to the trusted domain info
        // we have been sent also. It's not up to use to generate those though ...
        // let mut r = Vec::new();
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_spn_generate_create() {
        // on create don't provide
        unimplemented!();
    }

    #[test]
    fn test_spn_generate_modify() {
        // on a purge of the spen, generate it.
        unimplemented!();
    }

    #[test]
    fn test_spn_validate_create() {
        // on create providing invalid spn, we over-write it.
        unimplemented!();
    }

    #[test]
    fn test_spn_validate_modify() {
        // On modify (removed/present) of the spn, just regenerate it.
        unimplemented!();
    }

    #[test]
    fn test_spn_regen_domain_rename() {
        // get the current domain name

        // check the spn on admin is admin@<initial domain>

        // trigger the domain_name change (this will be a cli option to the server
        // in the final version), but it will still call the same qs function to perform the
        // change.

        // check the spn on admin is admin@<new domain>
        unimplemented!();
    }
}

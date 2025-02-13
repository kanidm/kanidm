// Manage and generate domain uuid's and/or trust related domain
// management.

// The primary point of this is to generate a unique domain UUID on startup
// which is importart for management of the replication topo and trust
// relationships.
use std::iter::once;
use std::sync::Arc;

use regex::Regex;
use tracing::trace;

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

lazy_static! {
    pub static ref DOMAIN_LDAP_BASEDN_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new(r"^(dc|o|ou)=[a-z][a-z0-9]*(,(dc|o|ou)=[a-z][a-z0-9]*)*$")
            .expect("Invalid domain ldap basedn regex")
    };
}

pub struct Domain {}

impl Plugin for Domain {
    fn id() -> &'static str {
        "plugin_domain"
    }

    #[instrument(level = "debug", name = "domain_pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "domain_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "domain_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }
}

impl Domain {
    /// Generates the cookie key for the domain.
    fn modify_inner<T: Clone + std::fmt::Debug>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            if e.attribute_equality(Attribute::Class, &EntryClass::DomainInfo.into())
                && e.attribute_equality(Attribute::Uuid, &PVUUID_DOMAIN_INFO)
            {
                // Validate the domain ldap basedn syntax.
                if let Some(basedn) = e.get_ava_single_iutf8(Attribute::DomainLdapBasedn) {
                    if !DOMAIN_LDAP_BASEDN_RE.is_match(basedn) {
                        error!(
                            "Invalid {} '{}'. Must pass regex \"{}\"",
                            Attribute::DomainLdapBasedn,
                            basedn,
                            *DOMAIN_LDAP_BASEDN_RE
                        );
                        return Err(OperationError::InvalidState);
                    }
                }

                // We always set this, because the DB uuid is authoritative.
                let u = Value::Uuid(qs.get_domain_uuid());
                e.set_ava(&Attribute::DomainUuid, once(u));
                trace!("plugin_domain: Applying uuid transform");

                // We only apply this if one isn't provided.
                if !e.attribute_pres(Attribute::DomainName) {
                    let n = Value::new_iname(qs.get_domain_name());
                    e.set_ava(&Attribute::DomainName, once(n));
                    trace!("plugin_domain: Applying domain_name transform");
                }

                // Setup the minimum functional level if one is not set already.
                if !e.attribute_pres(Attribute::Version) {
                    let n = Value::Uint32(DOMAIN_LEVEL_0);
                    e.set_ava(&Attribute::Version, once(n));
                    warn!("plugin_domain: Applying domain version transform");
                } else {
                    debug!("plugin_domain: NOT Applying domain version transform");
                };

                // create the domain_display_name if it's missing. This was the behaviour in versions
                // prior to DL10. Rather than checking the domain version itself, the issue is we
                // have to check the min remigration level. This is because during a server setup
                // we start from the MIN remigration level and work up, and the domain version == 0.
                //
                // So effectively we only skip setting this value after we know that we are at DL12
                // since we could never go back to anything lower than 10 at that point.
                if DOMAIN_MIN_REMIGRATION_LEVEL < DOMAIN_LEVEL_10
                    && !e.attribute_pres(Attribute::DomainDisplayName)
                {
                    let domain_display_name =
                        Value::new_utf8(format!("Kanidm {}", qs.get_domain_name()));
                    security_info!(
                        "plugin_domain: setting default domain_display_name to {:?}",
                        domain_display_name
                    );

                    e.set_ava(&Attribute::DomainDisplayName, once(domain_display_name));
                }

                Ok(())
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    // test we can create and generate the id
    #[qs_test]
    async fn test_domain_generate_uuid(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let e_dom = server_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("must not fail");

        let u_dom = server_txn.get_domain_uuid();

        assert!(e_dom.attribute_equality(Attribute::DomainUuid, &PartialValue::Uuid(u_dom)));
    }
}

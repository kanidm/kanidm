// Manage and generate domain uuid's and/or trust related domain
// management.

// The primary point of this is to generate a unique domain UUID on startup
// which is importart for management of the replication topo and trust
// relationships.
use std::iter::once;
use std::sync::Arc;

use compact_jwt::JwsSigner;
use kanidm_proto::v1::OperationError;
use rand::prelude::*;
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
    fn modify_inner<T: Clone + std::fmt::Debug>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            if e.attribute_equality("class", &PVCLASS_DOMAIN_INFO)
                && e.attribute_equality("uuid", &PVUUID_DOMAIN_INFO)
            {
                // Validate the domain ldap basedn syntax.
                if let Some(basedn) = e
                    .get_ava_single_iutf8("domain_ldap_basedn") {

                    if !DOMAIN_LDAP_BASEDN_RE.is_match(basedn) {
                        error!("Invalid domain_ldap_basedn. Must pass regex \"{}\"", *DOMAIN_LDAP_BASEDN_RE);
                        return Err(OperationError::InvalidState);
                    }
                }

                // We always set this, because the DB uuid is authoritative.
                let u = Value::Uuid(qs.get_domain_uuid());
                e.set_ava("domain_uuid", once(u));
                trace!("plugin_domain: Applying uuid transform");

                // We only apply this if one isn't provided.
                if !e.attribute_pres("domain_name") {
                    let n = Value::new_iname(qs.get_domain_name());
                    e.set_ava("domain_name", once(n));
                    trace!("plugin_domain: Applying domain_name transform");
                }

                // Setup the minimum functional level if one is not set already.
                if !e.attribute_pres("version") {
                    let n = Value::Uint32(DOMAIN_MIN_LEVEL);
                    e.set_ava("version", once(n));
                    trace!("plugin_domain: Applying domain version transform");
                }

                // create the domain_display_name if it's missing
                if !e.attribute_pres("domain_display_name") {
                    let domain_display_name = Value::new_utf8(format!("Kanidm {}", qs.get_domain_name()));
                    security_info!("plugin_domain: setting default domain_display_name to {:?}", domain_display_name);

                    e.set_ava("domain_display_name", once(domain_display_name));
                }

                if !e.attribute_pres("fernet_private_key_str") {
                    security_info!("regenerating domain token encryption key");
                    let k = fernet::Fernet::generate_key();
                    let v = Value::new_secret_str(&k);
                    e.add_ava("fernet_private_key_str", v);
                }

                if !e.attribute_pres("es256_private_key_der") {
                    security_info!("regenerating domain es256 private key");
                    let der = JwsSigner::generate_es256()
                        .and_then(|jws| jws.private_key_to_der())
                        .map_err(|e| {
                            admin_error!(err = ?e, "Unable to generate ES256 JwsSigner private key");
                            OperationError::CryptographyError
                        })?;
                    let v = Value::new_privatebinary(&der);
                    e.add_ava("es256_private_key_der", v);
                }

                if !e.attribute_pres("private_cookie_key") {
                    security_info!("regenerating domain cookie key");
                    let mut key = [0; 32];
                    let mut rng = StdRng::from_entropy();
                    rng.fill(&mut key);
                    let v = Value::new_privatebinary(&key);
                    e.add_ava("private_cookie_key", v);
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
    use crate::prelude::*;

    // test we can create and generate the id
    #[qs_test]
    async fn test_domain_generate_uuid(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let e_dom = server_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("must not fail");

        let u_dom = server_txn.get_domain_uuid();

        assert!(e_dom.attribute_equality("domain_uuid", &PartialValue::Uuid(u_dom)));
    }
}

use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;

pub struct InitCredentialUpdateEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl InitCredentialUpdateEvent {
    #[cfg(test)]
    pub fn new_impersonate_entry(e: std::sync::Arc<Entry<EntrySealed, EntryCommitted>>) -> Self {
        let ident = Identity::from_impersonate_entry(e);
        let target = ident
            .get_uuid()
            .ok_or(OperationError::InvalidState)
            .expect("Identity has no uuid associated");
        InitCredentialUpdateEvent { ident, target }
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn init_credential_update(&mut self, _event: &InitCredentialUpdateEvent) -> () {
        admin_error!("init_credential_update");

        // Is target an account?

        // Given an ident
        // entry
        // attributes.

        // need a search_permission_check
        // need a modify_permission_check
        // need a create_permission_check (future)
        // need a delete_permission_check (future)

        // Does the ident have permission to modify AND search the user-credentials of the target, given
        // the current status of it's authentication?

        // Build the cred update session.
        // - store account policy (if present)
        // - stash the current state of all associated credentials
        // -

        // Store the update session into the map.

        // - issue the CredentialUpdateToken (enc)
    }
}

#[cfg(test)]
mod tests {
    // use crate::prelude::*;
    use super::InitCredentialUpdateEvent;
    use crate::event::CreateEvent;
    use std::time::Duration;

    const TEST_CURRENT_TIME: u64 = 6000;

    #[test]
    fn test_idm_credential_update_session_init() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            // user without permission - fail
            // - create a user
            // - remove the permission self mod credentials?
            // - init the session with the user via their uat.

            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = idms.proxy_write(ct);

            let testperson_uuid = Uuid::new_v4();

            let e = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("user_account_only")),
                ("uuid", Value::new_uuid(testperson_uuid)),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson"))
            );

            let ce = CreateEvent::new_internal(vec![e.clone()]);
            let cr = idms_prox_write.qs_write.create(&ce);
            assert!(cr.is_ok());

            let testperson = idms_prox_write
                .qs_write
                .internal_search_uuid(&testperson_uuid)
                .expect("failed");

            let _cur = idms_prox_write.init_credential_update(
                &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            );

            // user with permission - success

            // create intent token without permission - fail

            // create intent token with permission - success

            // exchange intent token - invalid - fail

            // exchange intent token - success
        })
    }
}

use crate::prelude::*;

use crate::idm::event::AuthResult;
use crate::idm::server::IdmServerAuthTransaction;

#[derive(Debug)]
pub struct ReauthEvent {
    // pub ident: Option<Identity>,
    // pub step: AuthEventStep,
    // pub sessionid: Option<Uuid>,
}

impl<'a> IdmServerAuthTransaction<'a> {
    pub async fn reauth(
        &mut self,
        _ae: &ReauthEvent,
        _ct: Duration,
    ) -> Result<AuthResult, OperationError> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::idm::credupdatesession::{InitCredentialUpdateEvent, MfaRegStateStatus};
    use crate::idm::delayed::DelayedAction;
    use crate::idm::event::{AuthEvent, AuthResult};
    use crate::idm::server::IdmServerTransaction;
    use crate::idm::AuthState;
    use crate::prelude::*;

    use kanidm_proto::v1::{AuthAllowed, AuthIssueSession, AuthMech};

    use uuid::uuid;

    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;

    const TESTPERSON_UUID: Uuid = uuid!("cf231fea-1a8f-4410-a520-fd9b1a379c86");

    async fn setup_testaccount(idms: &IdmServer, ct: Duration) {
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let e2 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson")),
            ("uuid", Value::Uuid(TESTPERSON_UUID)),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let cr = idms_prox_write.qs_write.internal_create(vec![e2]);
        assert!(cr.is_ok());
        assert!(idms_prox_write.commit().is_ok());
    }

    async fn setup_testaccount_passkey(
        idms: &IdmServer,
        ct: Duration,
    ) -> WebauthnAuthenticator<SoftPasskey> {
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(TESTPERSON_UUID)
            .expect("failed");
        let (cust, _c_status) = idms_prox_write
            .init_credential_update(
                &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
                ct,
            )
            .expect("Failed to begin credential update.");
        idms_prox_write.commit().expect("Failed to commit txn");

        // Update session is setup.

        let cutxn = idms.cred_update_transaction();
        let origin = cutxn.get_origin().clone();

        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new());

        let c_status = cutxn
            .credential_passkey_init(&cust, ct)
            .expect("Failed to initiate passkey registration");

        let passkey_chal = match c_status.mfaregstate() {
            MfaRegStateStatus::Passkey(c) => Some(c),
            _ => None,
        }
        .expect("Unable to access passkey challenge, invalid state");

        let passkey_resp = wa
            .do_registration(origin.clone(), passkey_chal.clone())
            .expect("Failed to create soft passkey");

        // Finish the registration
        let label = "softtoken".to_string();
        let c_status = cutxn
            .credential_passkey_finish(&cust, ct, label, &passkey_resp)
            .expect("Failed to initiate passkey registration");

        assert!(c_status.can_commit());

        drop(cutxn);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        idms_prox_write
            .commit_credential_update(&cust, ct)
            .expect("Failed to commit credential update.");

        idms_prox_write.commit().expect("Failed to commit txn");

        wa
    }

    async fn auth_passkey(
        idms: &IdmServer,
        ct: Duration,
        wa: &mut WebauthnAuthenticator<SoftPasskey>,
        idms_delayed: &mut IdmServerDelayed,
    ) -> Option<String> {
        let mut idms_auth = idms.auth();
        let origin = idms_auth.get_origin().clone();

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = idms_auth.auth(&auth_init, ct).await;
        let ar = r1.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::Passkey);

        let r2 = idms_auth.auth(&auth_begin, ct).await;
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        trace!(?state);

        let rcr = match state {
            AuthState::Continue(mut allowed) => match allowed.pop() {
                Some(AuthAllowed::Passkey(rcr)) => rcr,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        trace!(?rcr);

        let resp = wa
            .do_authentication(origin, rcr)
            .expect("failed to use softtoken to authenticate");

        let passkey_step = AuthEvent::cred_step_passkey(sessionid, resp);

        let r3 = idms_auth.auth(&passkey_step, ct).await;
        debug!("r3 ==> {:?}", r3);
        idms_auth.commit().expect("Must not fail");

        match r3 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token, AuthIssueSession::Token),
                delay: _,
            }) => {
                // Process the webauthn update
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::WebauthnCounterIncrement(_)));
                let r = idms.delayed_action(ct, da).await;
                assert!(r.is_ok());

                // Process the auth session
                let da = idms_delayed.try_recv().expect("invalid");
                assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
                // We have to actually write this one else the following tests
                // won't work!
                let r = idms.delayed_action(ct, da).await;
                assert!(r.is_ok());

                Some(token)
            }
            _ => None,
        }
    }

    async fn token_to_ident(idms: &IdmServer, ct: Duration, token: Option<&str>) -> Identity {
        let mut idms_prox_read = idms.proxy_read().await;

        idms_prox_read
            .validate_and_parse_token_to_ident(token, ct)
            .expect("Invalid UAT")
    }

    #[idm_test]
    async fn test_idm_reauth_passkey(idms: &IdmServer, idms_delayed: &mut IdmServerDelayed) {
        let ct = duration_from_epoch_now();

        // Setup the test account
        setup_testaccount(idms, ct).await;
        let mut passkey = setup_testaccount_passkey(idms, ct).await;

        // Do an initial auth.
        let token = auth_passkey(idms, ct, &mut passkey, idms_delayed)
            .await
            .expect("failed to authenticate with passkey");

        // Token_str to uat
        let ident = token_to_ident(idms, ct, Some(token.as_str())).await;

        // Check that the rw entitlement is not present, and that re-auth is allowed.
        // assert!(matches!(ident.access_scope(), AccessScope::ReadOnly));
        assert!(matches!(ident.access_scope(), AccessScope::ReadWrite));

        // Assert the session is rw capable though.

        // Do a re-auth

        // They now have the entitlement.
    }
}

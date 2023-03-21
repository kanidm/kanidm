use crate::prelude::*;

use crate::credential::softlock::CredSoftLock;
use crate::idm::account::Account;
use crate::idm::authsession::AuthSession;
use crate::idm::event::AuthResult;
use crate::idm::server::IdmServerAuthTransaction;
use crate::utils::uuid_from_duration;

// use webauthn_rs::prelude::Webauthn;

use std::sync::Arc;
use tokio::sync::Mutex;

use kanidm_proto::v1::{AuthCredential, AuthIssueSession};

use super::server::CredSoftLockMutex;

impl<'a> IdmServerAuthTransaction<'a> {
    pub async fn reauth_init(
        &mut self,
        ident: Identity,
        issue: AuthIssueSession,
        ct: Duration,
    ) -> Result<AuthResult, OperationError> {
        // re-auth only works on users, so lets get the user account.
        // hint - it's in the ident!
        let entry = match ident.get_user_entry() {
            Some(entry) => entry,
            None => {
                error!("Ident is not a user and has no entry associated. Unable to proceed.");
                return Err(OperationError::InvalidState);
            }
        };

        // Setup the account record.
        let account = Account::try_from_entry_ro(entry.as_ref(), &mut self.qs_read)?;

        security_info!(
            username = %account.name,
            issue = ?issue,
            uuid = %account.uuid,
            "Initiating Re-Authentication Session",
        );

        // Check that the entry/session can be re-authed.
        let session = entry
            .get_ava_as_session_map("user_auth_token_session")
            .and_then(|sessions| sessions.get(&ident.session_id))
            .ok_or_else(|| {
                error!("Ident session is not present in entry. Perhaps replication is delayed?");
                OperationError::InvalidState
            })?;

        match session.scope {
            SessionScope::PrivilegeCapable => {
                // Yes! This session can re-auth!
            }
            SessionScope::ReadOnly | SessionScope::ReadWrite | SessionScope::Synchronise => {
                // These can not!
                error!("Session scope is not PrivilegeCapable and can not be used in re-auth.");
                return Err(OperationError::InvalidState);
            }
        };

        // Get the credential id.
        let session_cred_id = session.cred_id;

        // == Everything Checked Out! ==
        // Let's setup to proceed with the re-auth.

        // Allocate the session id based on current time / sid.
        let sessionid = uuid_from_duration(ct, self.sid);

        // Start getting things.
        let _session_ticket = self.session_ticket.acquire().await;

        // Setup soft locks here if required.
        let maybe_slock = account
            .primary_cred_uuid_and_policy()
            .and_then(|(cred_uuid, policy)| {
                // Acquire the softlock map
                //
                // We have no issue calling this with .write here, since we
                // already hold the session_ticket above.
                //
                // We only do this if the primary credential being used here is for
                // this re-auth session. Else passkeys/devicekeys are not bounded by this
                // problem.
                if cred_uuid == session_cred_id {
                    let mut softlock_write = self.softlocks.write();
                    let slock_ref: CredSoftLockMutex =
                        if let Some(slock_ref) = softlock_write.get(&cred_uuid) {
                            slock_ref.clone()
                        } else {
                            // Create if not exist, and the cred type supports softlocking.
                            let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                            softlock_write.insert(cred_uuid, slock.clone());
                            slock
                        };
                    softlock_write.commit();
                    Some(slock_ref)
                } else {
                    None
                }
            });

        // Check if the cred is locked! We want to fail fast here! Unlike the auth flow we have
        // already selected our credential so we can test it's slock, else we could be allowing
        // 1-attempt per-reauth.

        let is_valid = if let Some(slock_ref) = maybe_slock {
            let mut slock = slock_ref.lock().await;
            slock.apply_time_step(ct);
            slock.is_valid()
        } else {
            true
        };

        if !is_valid {
            todo!()
        }

        // Create a re-auth session
        let (auth_session, state) =
            AuthSession::new_reauth(account, session_cred_id, issue, self.webauthn, ct);

        // Push the re-auth session to the session maps.
        match auth_session {
            Some(auth_session) => {
                let mut session_write = self.sessions.write();
                if session_write.contains_key(&sessionid) {
                    // If we have a session of the same id, return an error (despite how
                    // unlikely this is ...
                    Err(OperationError::InvalidSessionState)
                } else {
                    session_write.insert(sessionid, Arc::new(Mutex::new(auth_session)));
                    // Debugging: ensure we really inserted ...
                    debug_assert!(session_write.get(&sessionid).is_some());
                    Ok(())
                }?;
                session_write.commit();
            }
            None => {
                security_info!("Authentication Session Unable to begin");
            }
        };

        Ok(AuthResult { sessionid, state })
    }

    pub async fn reauth_step(
        &mut self,
        _ident: Identity,
        _ct: Duration,
        _ra_session_id: Uuid,
        _cred: AuthCredential,
    ) -> Result<AuthResult, OperationError> {
        // Does our session id exist?

        // If so, remove it from the tree and release the lock.

        // Update the slock.

        // On success, re-issue the session with updated scope/values.

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

        let cutxn = idms.cred_update_transaction().await;
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
        let mut idms_auth = idms.auth().await;
        let origin = idms_auth.get_origin().clone();

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = idms_auth.auth(&auth_init, ct).await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::Passkey);

        let r2 = idms_auth.auth(&auth_begin, ct).await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

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

    async fn reauth_passkey(
        idms: &IdmServer,
        ct: Duration,
        ident: &Identity,
        wa: &mut WebauthnAuthenticator<SoftPasskey>,
        idms_delayed: &mut IdmServerDelayed,
    ) -> Option<String> {
        let mut idms_auth = idms.auth().await;
        let origin = idms_auth.get_origin().clone();

        let auth_allowed = idms_auth
            .reauth_init(ident.clone(), AuthIssueSession::Token, ct)
            .await
            .expect("Failed to start reauth.");

        let AuthResult { sessionid, state } = auth_allowed;

        trace!(?state);

        let rcr = match state {
            AuthState::Continue(mut allowed) => match allowed.pop() {
                Some(AuthAllowed::Passkey(rcr)) => rcr,
                _ => return None,
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
            _ => unreachable!(),
        }
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

        // Check that the rw entitlement is not present
        debug!(?ident);
        assert!(matches!(ident.access_scope(), AccessScope::ReadOnly));

        // Assert the session is rw capable though which is what will allow the re-auth
        // to proceed.

        let session = ident.get_session().expect("Unable to access sessions");

        assert!(matches!(session.scope, SessionScope::PrivilegeCapable));

        // Start the re-auth
        let token = reauth_passkey(idms, ct, &ident, &mut passkey, idms_delayed)
            .await
            .expect("Failed to get new session token");

        // Token_str to uat
        let ident = token_to_ident(idms, ct, Some(token.as_str())).await;

        // They now have the entitlement.
        debug!(?ident);
        assert!(matches!(ident.access_scope(), AccessScope::ReadWrite));
    }

    #[idm_test]
    async fn test_idm_reauth_softlocked_pw(
        _idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        todo!();
    }
}

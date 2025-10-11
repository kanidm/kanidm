use crate::credential::totp::{Totp, TotpAlgo, TotpDigits};
use crate::idm::server::IdmServerProxyReadTransaction;
use crate::prelude::*;
use crate::server::identity::Identity;
use crate::server::QueryServerTransaction;
use kanidm_proto::internal::IdentifyUserResponse;
use openssl::ec::EcKey;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use std::sync::Arc;
use uuid::Uuid;

// This is longer than a normal TOTP step as we expect users to be talking
// to each other, so it could take a few minutes.
static TOTP_STEP: u64 = 300;

#[derive(Debug)]
pub struct IdentifyUserStartEvent {
    pub target: Uuid,
    pub ident: Identity,
}

impl IdentifyUserStartEvent {
    pub fn new(target: Uuid, ident: Identity) -> Self {
        IdentifyUserStartEvent { target, ident }
    }
}
pub struct IdentifyUserDisplayCodeEvent {
    pub target: Uuid,
    pub ident: Identity,
}

impl IdentifyUserDisplayCodeEvent {
    pub fn new(target: Uuid, ident: Identity) -> Self {
        IdentifyUserDisplayCodeEvent { target, ident }
    }
}

pub struct IdentifyUserSubmitCodeEvent {
    pub code: u32,
    pub target: Uuid,
    pub ident: Identity,
}

impl IdentifyUserSubmitCodeEvent {
    pub fn new(target: Uuid, ident: Identity, code: u32) -> Self {
        IdentifyUserSubmitCodeEvent {
            target,
            ident,
            code,
        }
    }
}

impl IdmServerProxyReadTransaction<'_> {
    pub fn handle_identify_user_start(
        &mut self,
        IdentifyUserStartEvent { target, ident }: &IdentifyUserStartEvent,
        current_time: Duration,
    ) -> Result<IdentifyUserResponse, OperationError> {
        let (ident_entry, target_entry) = match self.get_involved_entries(ident, *target) {
            Ok(tuple) => tuple,
            Err(early_response) => return Ok(early_response),
        };

        let response = if ident_entry.get_uuid() < target_entry.get_uuid() {
            IdentifyUserResponse::WaitForCode
        } else {
            let totp_secret = self.get_self_totp(&ident_entry, &target_entry)?;

            let totp_value = totp_secret
                .do_totp_duration_from_epoch(&current_time)
                .map_err(|_| OperationError::CryptographyError)?;

            IdentifyUserResponse::ProvideCode {
                step: TOTP_STEP as u32,
                totp: totp_value,
            }
        };
        Ok(response)
    }

    pub fn handle_identify_user_display_code(
        &mut self,
        IdentifyUserDisplayCodeEvent { target, ident }: &IdentifyUserDisplayCodeEvent,
        current_time: Duration,
    ) -> Result<IdentifyUserResponse, OperationError> {
        let (ident_entry, target_entry) = match self.get_involved_entries(ident, *target) {
            Ok(tuple) => tuple,
            Err(early_response) => return Ok(early_response),
        };

        let totp_secret = self.get_self_totp(&ident_entry, &target_entry)?;

        let totp_value = totp_secret
            .do_totp_duration_from_epoch(&current_time)
            .map_err(|_| OperationError::CryptographyError)?;

        Ok(IdentifyUserResponse::ProvideCode {
            step: TOTP_STEP as u32,
            totp: totp_value,
        })
    }

    pub fn handle_identify_user_submit_code(
        &mut self,
        IdentifyUserSubmitCodeEvent {
            target,
            ident,
            code,
        }: &IdentifyUserSubmitCodeEvent,
        current_time: Duration,
    ) -> Result<IdentifyUserResponse, OperationError> {
        let (ident_entry, target_entry) = match self.get_involved_entries(ident, *target) {
            Ok(tuple) => tuple,
            Err(early_response) => return Ok(early_response),
        };

        let totp_secret = self.get_user_totp(&ident_entry, &target_entry)?;

        if !totp_secret.verify(*code, current_time) {
            return Ok(IdentifyUserResponse::CodeFailure);
        }

        // if we are the first it means now it's time to go for ProvideCode, otherwise we just confirm that the code is correct
        // (we know this for a fact as we have already checked that the code is correct)
        let response = if ident_entry.get_uuid() < target_entry.get_uuid() {
            let totp_secret = self.get_self_totp(&ident_entry, &target_entry)?;
            let totp_value = totp_secret
                .do_totp_duration_from_epoch(&current_time)
                .map_err(|_| OperationError::CryptographyError)?;
            IdentifyUserResponse::ProvideCode {
                step: TOTP_STEP as u32,
                totp: totp_value,
            }
        } else {
            IdentifyUserResponse::Success
        };
        Ok(response)
    }

    // End of public functions

    fn get_involved_entries(
        &mut self,
        ident: &Identity,
        target: Uuid,
    ) -> Result<(Arc<EntrySealedCommitted>, Arc<EntrySealedCommitted>), IdentifyUserResponse> {
        let Some(ident_entry) = ident.get_user_entry() else {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        };

        let Ok(target_entry) = self.get_partner_entry(target) else {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        };

        if ident_entry.get_uuid() == target_entry.get_uuid() {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        }

        if target_entry
            .get_ava_single_eckey_public(Attribute::IdVerificationEcKey)
            .is_none()
        {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        }

        if ident_entry
            .get_ava_single_eckey_private(Attribute::IdVerificationEcKey)
            .is_none()
        {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        }

        Ok((ident_entry, target_entry))
    }

    fn get_partner_entry(
        &mut self,
        target: Uuid,
    ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
        self.qs_read
            .internal_search_uuid(target)
            .inspect_err(|err| error!(?err, ?target, "Failed to retrieve entry",))
    }

    fn get_user_own_key(
        &mut self,
        ident_entry: &EntrySealedCommitted,
    ) -> Result<EcKey<Private>, OperationError> {
        ident_entry
            .get_ava_single_eckey_private(Attribute::IdVerificationEcKey)
            .cloned()
            .ok_or(OperationError::AU0001InvalidState)
    }

    fn get_user_public_key(
        &mut self,
        target_entry: &EntrySealedCommitted,
    ) -> Result<EcKey<Public>, OperationError> {
        target_entry
            .get_ava_single_eckey_public(Attribute::IdVerificationEcKey)
            .cloned()
            .ok_or(OperationError::AU0001InvalidState)
    }

    fn get_self_totp(
        &mut self,
        ident_entry: &EntrySealedCommitted,
        target_entry: &EntrySealedCommitted,
    ) -> Result<Totp, OperationError> {
        let self_private = self.get_user_own_key(ident_entry)?;
        let other_user_public_key = self.get_user_public_key(target_entry)?;
        let mut shared_key = self.derive_shared_key(self_private, other_user_public_key)?;
        shared_key.extend_from_slice(ident_entry.get_uuid().as_bytes());

        let totp = Totp::new(shared_key, TOTP_STEP, TotpAlgo::Sha256, TotpDigits::Six);
        Ok(totp)
    }

    fn get_user_totp(
        &mut self,
        ident_entry: &EntrySealedCommitted,
        target_entry: &EntrySealedCommitted,
    ) -> Result<Totp, OperationError> {
        let self_private = self.get_user_own_key(ident_entry)?;
        let other_user_public_key = self.get_user_public_key(target_entry)?;
        let mut shared_key = self.derive_shared_key(self_private, other_user_public_key)?;
        shared_key.extend_from_slice(target_entry.get_uuid().as_bytes());
        let totp = Totp::new(shared_key, TOTP_STEP, TotpAlgo::Sha256, TotpDigits::Six);
        Ok(totp)
    }

    fn derive_shared_key(
        &self,
        private: EcKey<Private>,
        public: EcKey<Public>,
    ) -> Result<Vec<u8>, OperationError> {
        let cryptography_error = |_| OperationError::CryptographyError;
        let pkey_private = PKey::from_ec_key(private).map_err(cryptography_error)?;
        let pkey_public = PKey::from_ec_key(public).map_err(cryptography_error)?;

        let mut private_key_ctx: PkeyCtx<Private> =
            PkeyCtx::new(&pkey_private).map_err(cryptography_error)?;
        private_key_ctx.derive_init().map_err(cryptography_error)?;
        private_key_ctx
            .derive_set_peer(&pkey_public)
            .map_err(cryptography_error)?;
        let keylen = private_key_ctx.derive(None).map_err(cryptography_error)?;
        let mut tmp_vec = vec![0; keylen];
        let buffer = tmp_vec.as_mut_slice();
        private_key_ctx
            .derive(Some(buffer))
            .map_err(cryptography_error)?;
        Ok(buffer.to_vec())
    }
}

#[cfg(test)]
mod test {
    use kanidm_proto::internal::IdentifyUserResponse;

    use crate::idm::identityverification::{
        IdentifyUserDisplayCodeEvent, IdentifyUserStartEvent, IdentifyUserSubmitCodeEvent,
    };
    use crate::prelude::*;

    #[idm_test]
    async fn test_identity_verification_unavailable(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let invalid_user_uuid = Uuid::new_v4();
        let valid_user_uuid = Uuid::new_v4();

        let e1 = create_invalid_user_account(invalid_user_uuid);

        let e2 = create_valid_user_account(valid_user_uuid);

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(invalid_user_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let res = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(invalid_user_uuid, ident.clone()),
            ct,
        );

        assert_eq!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        );

        let res = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(valid_user_uuid, ident.clone()),
            ct,
        );

        assert_eq!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        );

        let res = idms_prox_read.handle_identify_user_display_code(
            &IdentifyUserDisplayCodeEvent::new(valid_user_uuid, ident.clone()),
            ct,
        );

        assert_eq!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        );

        let res = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(valid_user_uuid, ident, 123456),
            ct,
        );

        assert_eq!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        );
    }

    #[idm_test]
    async fn test_invalid_user_id(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let invalid_user_uuid = Uuid::new_v4();
        let valid_user_a_uuid = Uuid::new_v4();
        let valid_user_b_uuid = Uuid::new_v4();

        let e1 = create_invalid_user_account(invalid_user_uuid);

        let e2 = create_valid_user_account(valid_user_a_uuid);

        let e3 = create_valid_user_account(valid_user_b_uuid);

        let ce = CreateEvent::new_internal(vec![e1, e2, e3]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(valid_user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let res = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(invalid_user_uuid, ident.clone()),
            ct,
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));

        let res = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(invalid_user_uuid, ident.clone()),
            ct,
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));

        let res = idms_prox_read.handle_identify_user_display_code(
            &IdentifyUserDisplayCodeEvent::new(invalid_user_uuid, ident.clone()),
            ct,
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));
        let res = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(invalid_user_uuid, ident, 123456),
            ct,
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));
    }

    #[idm_test]
    async fn test_start_event(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let valid_user_a_uuid = Uuid::new_v4();

        let e = create_valid_user_account(valid_user_a_uuid);
        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(valid_user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let res = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(valid_user_a_uuid, ident.clone()),
            ct,
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));
    }

    // actually this is somewhat a duplicate of `test_full_identification_flow` inside the testkit, with the exception that this
    // tests ONLY the totp code correctness and not the flow correctness. To test the correctness it obviously needs to also
    // enforce some flow checks, but this is not the primary scope of this test
    #[idm_test]
    async fn test_code_correctness(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let user_a_uuid = Uuid::new_v4();
        let user_b_uuid = Uuid::new_v4();
        let e1 = create_valid_user_account(user_a_uuid);
        let e2 = create_valid_user_account(user_b_uuid);
        let ce = CreateEvent::new_internal(vec![e1, e2]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident_a = idms_prox_read
            .qs_read
            .internal_search_uuid(user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let ident_b = idms_prox_read
            .qs_read
            .internal_search_uuid(user_b_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let (lower_user, lower_user_uuid, higher_user, higher_user_uuid) =
            if user_a_uuid < user_b_uuid {
                (ident_a, user_a_uuid, ident_b, user_b_uuid)
            } else {
                (ident_b, user_b_uuid, ident_a, user_a_uuid)
            };

        // First the user with the lowest uuid receives the uuid from the other user

        let res_higher_user = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(lower_user_uuid, higher_user.clone()),
            ct,
        );

        let Ok(IdentifyUserResponse::ProvideCode { totp, .. }) = res_higher_user else {
            panic!();
        };

        let res_lower_user_wrong = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(higher_user_uuid, lower_user.clone(), totp + 1),
            ct,
        );

        assert!(matches!(
            res_lower_user_wrong,
            Ok(IdentifyUserResponse::CodeFailure)
        ));

        let res_lower_user_correct = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(higher_user_uuid, lower_user.clone(), totp),
            ct,
        );

        assert!(matches!(
            res_lower_user_correct,
            Ok(IdentifyUserResponse::ProvideCode { .. })
        ));

        // now we need to get the code from the lower_user and submit it to the higher_user

        let Ok(IdentifyUserResponse::ProvideCode { totp, .. }) = res_lower_user_correct else {
            panic!("Invalid");
        };

        let res_higher_user_2_wrong = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(lower_user_uuid, higher_user.clone(), totp + 1),
            ct,
        );

        assert!(matches!(
            res_higher_user_2_wrong,
            Ok(IdentifyUserResponse::CodeFailure)
        ));

        let res_higher_user_2_correct = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(lower_user_uuid, higher_user.clone(), totp),
            ct,
        );

        assert!(matches!(
            res_higher_user_2_correct,
            Ok(IdentifyUserResponse::Success)
        ));
    }

    #[idm_test]
    async fn test_totps_differ(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let user_a_uuid = Uuid::new_v4();
        let user_b_uuid = Uuid::new_v4();
        let e1 = create_valid_user_account(user_a_uuid);
        let e2 = create_valid_user_account(user_b_uuid);
        let ce = CreateEvent::new_internal(vec![e1, e2]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident_a = idms_prox_read
            .qs_read
            .internal_search_uuid(user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let ident_b = idms_prox_read
            .qs_read
            .internal_search_uuid(user_b_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let (lower_user, lower_user_uuid, higher_user, higher_user_uuid) =
            if user_a_uuid < user_b_uuid {
                (ident_a, user_a_uuid, ident_b, user_b_uuid)
            } else {
                (ident_b, user_b_uuid, ident_a, user_a_uuid)
            };

        // First twe retrieve the higher user code

        let res_higher_user = idms_prox_read.handle_identify_user_start(
            &IdentifyUserStartEvent::new(lower_user_uuid, higher_user.clone()),
            ct,
        );

        let Ok(IdentifyUserResponse::ProvideCode {
            totp: higher_user_totp,
            ..
        }) = res_higher_user
        else {
            panic!();
        };

        // then we get the lower user code

        let res_lower_user_correct = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(
                higher_user_uuid,
                lower_user.clone(),
                higher_user_totp,
            ),
            ct,
        );

        if let Ok(IdentifyUserResponse::ProvideCode {
            totp: lower_user_totp,
            ..
        }) = res_lower_user_correct
        {
            assert_ne!(higher_user_totp, lower_user_totp);
        } else {
            debug_assert!(false);
        }
    }

    fn create_valid_user_account(uuid: Uuid) -> EntryInitNew {
        let mut name = String::from("valid_user");
        name.push_str(&uuid.to_string());
        // if anyone from the future will see this test failing because of a schema violation
        // and wonders to this line of code I'm sorry to have wasted your time
        name.truncate(14);
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname(&name)),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::Description, Value::new_utf8s("some valid user")),
            (Attribute::DisplayName, Value::new_utf8s("Some valid user"))
        )
    }

    fn create_invalid_user_account(uuid: Uuid) -> EntryInitNew {
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("invalid_user")),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::Description, Value::new_utf8s("invalid_user")),
            (Attribute::DisplayName, Value::new_utf8s("Invalid user"))
        )
    }
}

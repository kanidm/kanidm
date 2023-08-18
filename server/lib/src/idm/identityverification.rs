use std::time::SystemTime;

use kanidm_proto::constants::ATTR_ID_VERIFICATION_ECKEY;
use kanidm_proto::{internal::IdentifyUserResponse, v1::OperationError};
use openssl::ec::EcKey;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use sketching::admin_error;
use uuid::Uuid;

use crate::credential::totp::{Totp, TotpAlgo, TotpDigits};
use crate::prelude::{tagged_event, EventTag};
use crate::server::QueryServerTransaction;
use crate::{event::SearchEvent, server::identity::Identity};

use crate::idm::server::IdmServerProxyReadTransaction;

static TOTP_STEP: u64 = 30;

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

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn handle_identify_user_start(
        &mut self,
        IdentifyUserStartEvent { target, ident }: &IdentifyUserStartEvent,
    ) -> Result<IdentifyUserResponse, OperationError> {
        if let Some(early_response) = self.check_for_early_return_conditions(ident, target)? {
            return Ok(early_response);
        }
        let response = if ident.get_uuid() < Some(*target) {
            IdentifyUserResponse::WaitForCode
        } else {
            let totp_secret = self.get_self_totp_secret(target, ident)?;
            let totp = self.compute_totp(totp_secret)?;
            IdentifyUserResponse::ProvideCode {
                step: TOTP_STEP as u32,
                totp,
            }
        };
        Ok(response)
    }

    pub fn handle_identify_user_display_code(
        &mut self,
        IdentifyUserDisplayCodeEvent { target, ident }: &IdentifyUserDisplayCodeEvent,
    ) -> Result<IdentifyUserResponse, OperationError> {
        if let Some(early_response) = self.check_for_early_return_conditions(ident, target)? {
            return Ok(early_response);
        }

        let totp_secret = self.get_self_totp_secret(target, ident)?;
        let totp = self.compute_totp(totp_secret)?;
        Ok(IdentifyUserResponse::ProvideCode {
            step: TOTP_STEP as u32,
            totp,
        })
    }

    pub fn handle_identify_user_submit_code(
        &mut self,
        IdentifyUserSubmitCodeEvent {
            target,
            ident,
            code,
        }: &IdentifyUserSubmitCodeEvent,
    ) -> Result<IdentifyUserResponse, OperationError> {
        if let Some(early_response) = self.check_for_early_return_conditions(ident, target)? {
            return Ok(early_response);
        }

        let totp_secret = self.get_other_user_totp_secret(target, ident)?;
        let other_user_totp = self.compute_totp(totp_secret)?;
        if other_user_totp != *code {
            return Ok(IdentifyUserResponse::CodeFailure);
        }
        // if we are the first it means now it's time to go for ProvideCode, otherwise we just confirm that the code is correct
        // (we know this for a fact as we have already checked that the code is correct)
        let res = if ident.get_uuid() < Some(*target) {
            let shared_secret = self.get_self_totp_secret(target, ident)?;
            let totp = self.compute_totp(shared_secret)?;
            IdentifyUserResponse::ProvideCode {
                step: TOTP_STEP as u32,
                totp,
            }
        } else {
            IdentifyUserResponse::Success
        };
        Ok(res)
    }

    // End of public functions

    fn check_for_early_return_conditions(
        &mut self,
        ident: &Identity,
        target: &Uuid,
    ) -> Result<Option<IdentifyUserResponse>, OperationError> {
        // here we check that the identify user feature is available before we do anything else
        if !self.check_if_identify_feature_available(ident)? {
            return Ok(Some(IdentifyUserResponse::IdentityVerificationUnavailable));
        };

        if !self.is_valid_user_uuid(ident, target)? {
            return Ok(Some(IdentifyUserResponse::InvalidUserId));
        };
        // here we check if the user provided their own uuid, if they did we just respond with IdentityVerificationAvailable.
        if ident.get_uuid().eq(&Some(*target)) {
            return Ok(Some(IdentifyUserResponse::IdentityVerificationAvailable));
        };
        Ok(None)
    }

    fn check_if_identify_feature_available(
        &mut self,
        ident: &Identity,
    ) -> Result<bool, OperationError> {
        let search = match SearchEvent::from_whoami_request(ident.clone(), &self.qs_read) {
            Ok(s) => s,
            Err(e) => {
                admin_error!("Failed to generate whoami search event: {:?}", e);
                return Err(e);
            }
        };
        self.qs_read
            .search(&search)
            .and_then(|mut entries| entries.pop().ok_or(OperationError::NoMatchingEntries))
            .map(
                |entry| match entry.get_ava_single_eckey_private(ATTR_ID_VERIFICATION_ECKEY) {
                    Some(key) => key.check_key().is_ok(),
                    None => false,
                },
            )
    }

    fn is_valid_user_uuid(
        &mut self,
        ident: &Identity,
        target: &Uuid,
    ) -> Result<bool, OperationError> {
        let search =
            match SearchEvent::from_target_uuid_request(ident.clone(), *target, &self.qs_read) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to retrieve user with the given UUID: {:?}", e);
                    return Err(e);
                }
            };

        let user_entry = self
            .qs_read
            .search(&search)
            .and_then(|mut entries| entries.pop().ok_or(OperationError::NoMatchingEntries))?;

        match user_entry.get_ava_single_eckey_public(ATTR_ID_VERIFICATION_ECKEY) {
            Some(key) => Ok(key.check_key().is_ok()),
            None => Ok(false),
        }
    }

    fn get_user_own_key(&mut self, ident: &Identity) -> Result<EcKey<Private>, OperationError> {
        let search = match SearchEvent::from_whoami_request(ident.clone(), &self.qs_read) {
            Ok(s) => s,
            Err(e) => {
                admin_error!(
                    "Failed to retrieve user with the given UUID: {}. \n{:?}",
                    ident.get_uuid().unwrap_or_default(),
                    e
                );
                return Err(e);
            }
        };

        self.qs_read
            .search(&search)
            .and_then(|mut entries| entries.pop().ok_or(OperationError::NoMatchingEntries))
            .and_then(|entry| {
                match entry.get_ava_single_eckey_private(ATTR_ID_VERIFICATION_ECKEY) {
                    Some(key) => Ok(key.clone()),
                    None => Err(OperationError::InvalidAccountState(format!(
                        "{}'s private key is missing!",
                        ident.get_uuid().unwrap_or_default()
                    ))),
                }
            })
    }

    fn get_other_user_public_key(
        &mut self,
        target: &Uuid,
        ident: &Identity,
    ) -> Result<EcKey<Public>, OperationError> {
        let search =
            match SearchEvent::from_target_uuid_request(ident.clone(), *target, &self.qs_read) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!(
                        "Failed to retrieve user with the given UUID: {}. \n{:?}",
                        ident.get_uuid().unwrap_or_default(),
                        e
                    );
                    return Err(e);
                }
            };
        self.qs_read
            .search(&search)
            .and_then(|mut entries| entries.pop().ok_or(OperationError::NoMatchingEntries))
            .and_then(
                |entry| match entry.get_ava_single_eckey_public(ATTR_ID_VERIFICATION_ECKEY) {
                    Some(key) => Ok(key.clone()),
                    None => Err(OperationError::InvalidAccountState(format!(
                        "{target}'s public key is missing!",
                    ))),
                },
            )
    }

    fn compute_totp(&mut self, totp_secret: Vec<u8>) -> Result<u32, OperationError> {
        let totp = Totp::new(totp_secret, TOTP_STEP, TotpAlgo::Sha256, TotpDigits::Six);
        let current_time = SystemTime::now();
        totp.do_totp(&current_time)
            .map_err(|_| OperationError::CryptographyError)
    }

    fn get_self_totp_secret(
        &mut self,
        target: &Uuid,
        ident: &Identity,
    ) -> Result<Vec<u8>, OperationError> {
        let self_private = self.get_user_own_key(ident)?;
        let other_user_public_key = self.get_other_user_public_key(target, ident)?;
        let mut shared_key = self.derive_shared_key(self_private, other_user_public_key)?;
        let Some(self_uuid) = ident.get_uuid() else {
            return Err(OperationError::NotAuthenticated)
        };
        shared_key.extend_from_slice(self_uuid.as_bytes());
        Ok(shared_key)
    }

    fn get_other_user_totp_secret(
        &mut self,
        target: &Uuid,
        ident: &Identity,
    ) -> Result<Vec<u8>, OperationError> {
        let self_private = self.get_user_own_key(ident)?;
        let other_user_public_key = self.get_other_user_public_key(target, ident)?;
        let mut shared_key = self.derive_shared_key(self_private, other_user_public_key)?;
        shared_key.extend_from_slice(target.as_bytes());
        Ok(shared_key)
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
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let self_uuid = Uuid::new_v4();
        let valid_user_uuid = Uuid::new_v4();

        let e1 = create_invalid_user_account(self_uuid);

        let e2 = create_valid_user_account(valid_user_uuid);

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(self_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let res = idms_prox_read
            .handle_identify_user_start(&IdentifyUserStartEvent::new(self_uuid, ident.clone()));

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));

        let res = idms_prox_read.handle_identify_user_start(&IdentifyUserStartEvent::new(
            valid_user_uuid,
            ident.clone(),
        ));

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));

        let res = idms_prox_read.handle_identify_user_display_code(
            &IdentifyUserDisplayCodeEvent::new(valid_user_uuid, ident.clone()),
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));
        let res = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(valid_user_uuid, ident, 123456),
        );

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationUnavailable)
        ));
    }

    #[idm_test]
    async fn test_invalid_user_id(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let invalid_user_uuid = Uuid::new_v4();
        let valid_user_a_uuid = Uuid::new_v4();
        let valid_user_b_uuid = Uuid::new_v4();

        let e1 = create_invalid_user_account(invalid_user_uuid);

        let e2 = create_valid_user_account(valid_user_a_uuid);

        let e3 = create_valid_user_account(valid_user_b_uuid);

        let ce = CreateEvent::new_internal(vec![e1, e2, e3]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(valid_user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let res = idms_prox_read.handle_identify_user_start(&IdentifyUserStartEvent::new(
            invalid_user_uuid,
            ident.clone(),
        ));

        assert!(matches!(res, Ok(IdentifyUserResponse::InvalidUserId)));

        let res = idms_prox_read.handle_identify_user_start(&IdentifyUserStartEvent::new(
            invalid_user_uuid,
            ident.clone(),
        ));

        assert!(matches!(res, Ok(IdentifyUserResponse::InvalidUserId)));

        let res = idms_prox_read.handle_identify_user_display_code(
            &IdentifyUserDisplayCodeEvent::new(invalid_user_uuid, ident.clone()),
        );

        assert!(matches!(res, Ok(IdentifyUserResponse::InvalidUserId)));
        let res = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(invalid_user_uuid, ident, 123456),
        );

        assert!(matches!(res, Ok(IdentifyUserResponse::InvalidUserId)));
    }

    #[idm_test]
    async fn test_start_event(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let valid_user_a_uuid = Uuid::new_v4();

        let e = create_valid_user_account(valid_user_a_uuid);
        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(valid_user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let res = idms_prox_read.handle_identify_user_start(&IdentifyUserStartEvent::new(
            valid_user_a_uuid,
            ident.clone(),
        ));

        assert!(matches!(
            res,
            Ok(IdentifyUserResponse::IdentityVerificationAvailable)
        ));
    }

    #[idm_test] // actually this is somewhat a duplicate of `test_full_identification_flow` inside the testkit, with the exception that this
                //tests ONLY the totp code correctness and not the flow correctness. To test the correctness it obviously needs to also
                // enforce some flow checks, but this is not the primary scope of this test
    async fn test_code_correctness(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let user_a_uuid = Uuid::new_v4();
        let user_b_uuid = Uuid::new_v4();
        let e1 = create_valid_user_account(user_a_uuid);
        let e2 = create_valid_user_account(user_b_uuid);
        let ce = CreateEvent::new_internal(vec![e1, e2]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;

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
        );

        let Ok(IdentifyUserResponse::ProvideCode { totp, .. }) = res_higher_user else {
                return assert!(false);
            };

        let res_lower_user_wrong = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(higher_user_uuid, lower_user.clone(), totp + 1),
        );

        assert!(matches!(
            res_lower_user_wrong,
            Ok(IdentifyUserResponse::CodeFailure)
        ));

        let res_lower_user_correct = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(higher_user_uuid, lower_user.clone(), totp),
        );

        assert!(matches!(
            res_lower_user_correct,
            Ok(IdentifyUserResponse::ProvideCode { .. })
        ));

        // now we need to get the code from the lower_user and submit it to the higher_user

        let Ok(IdentifyUserResponse::ProvideCode{totp, ..}) = res_lower_user_correct else {
                return assert!(false);
            };

        let res_higher_user_2_wrong = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(lower_user_uuid, higher_user.clone(), totp + 1),
        );

        assert!(matches!(
            res_higher_user_2_wrong,
            Ok(IdentifyUserResponse::CodeFailure)
        ));

        let res_higher_user_2_correct = idms_prox_read.handle_identify_user_submit_code(
            &IdentifyUserSubmitCodeEvent::new(lower_user_uuid, higher_user.clone(), totp),
        );

        assert!(matches!(
            res_higher_user_2_correct,
            Ok(IdentifyUserResponse::Success)
        ));
    }

    #[idm_test]

    async fn test_totps_differ(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let user_a_uuid = Uuid::new_v4();
        let user_b_uuid = Uuid::new_v4();
        let e1 = create_valid_user_account(user_a_uuid);
        let e2 = create_valid_user_account(user_b_uuid);
        let ce = CreateEvent::new_internal(vec![e1, e2]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;

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
        );

        let Ok(IdentifyUserResponse::ProvideCode { totp: higher_user_totp, .. }) = res_higher_user else {
                return assert!(false);
            };

        // then we get the lower user code

        let res_lower_user_correct =
            idms_prox_read.handle_identify_user_submit_code(&IdentifyUserSubmitCodeEvent::new(
                higher_user_uuid,
                lower_user.clone(),
                higher_user_totp,
            ));

        if let Ok(IdentifyUserResponse::ProvideCode {
            totp: lower_user_totp,
            ..
        }) = res_lower_user_correct
        {
            assert_ne!(higher_user_totp, lower_user_totp);
        } else {
            assert!(false);
        }
    }

    fn create_valid_user_account(uuid: Uuid) -> EntryInitNew {
        let mut name = String::from("valid_user");
        name.push_str(&uuid.to_string());
        // if anyone from the future will see this test failing because of a schema violation
        // and wonders to this line of code I'm sorry to have wasted your time
        name.truncate(14);
        entry_init!(
            (ATTR_CLASS, ValueClass::Object.to_value()),
            (ATTR_CLASS, ValueClass::Class.to_value()),
            (ATTR_CLASS, ValueClass::Person.to_value()),
            (ATTR_NAME, Value::new_iname(&name)),
            (ATTR_UUID, Value::Uuid(uuid)),
            (ATTR_DESCRIPTION, Value::new_utf8s("some valid user")),
            (ATTR_DISPLAYNAME, Value::new_utf8s("Some valid user"))
        )
    }

    fn create_invalid_user_account(uuid: Uuid) -> EntryInitNew {
        entry_init!(
            (ATTR_CLASS, ValueClass::Object.to_value()),
            (ATTR_CLASS, ValueClass::Class.to_value()),
            (ATTR_CLASS, ValueClass::ServiceAccount.to_value()),
            (ATTR_NAME, Value::new_iname("invalid_user")),
            (ATTR_UUID, Value::Uuid(uuid)),
            (ATTR_DESCRIPTION, Value::new_utf8s("invalid_user")),
            (ATTR_DISPLAYNAME, Value::new_utf8s("Invalid user"))
        )
    }
}

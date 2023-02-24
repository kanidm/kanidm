use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use kanidm_proto::v1::{
    AuthType, BackupCodesView, CredentialStatus, OperationError, UatPurpose, UatStatus, UiHint,
    UserAuthToken,
};
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CredentialID, DeviceKey as DeviceKeyV4, Passkey as PasskeyV4,
};

use crate::constants::UUID_ANONYMOUS;
use crate::credential::policy::CryptoPolicy;
use crate::credential::softlock::CredSoftLockPolicy;
use crate::credential::Credential;
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntrySealed};
use crate::event::SearchEvent;
use crate::idm::group::Group;
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::modify::{ModifyInvalid, ModifyList};
use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::value::{IntentTokenState, PartialValue, Value};

macro_rules! try_from_entry {
    ($value:expr, $groups:expr) => {{
        // Check the classes
        if !$value.attribute_equality("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        // Now extract our needed attributes
        let name = $value
            .get_ava_single_iname("name")
            .map(|s| s.to_string())
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: name".to_string(),
            ))?;

        let displayname = $value
            .get_ava_single_utf8("displayname")
            .map(|s| s.to_string())
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: displayname".to_string(),
            ))?;

        let primary = $value
            .get_ava_single_credential("primary_credential")
            .map(|v| v.clone());

        let passkeys = $value
            .get_ava_passkeys("passkeys")
            .cloned()
            .unwrap_or_default();

        let devicekeys = $value
            .get_ava_devicekeys("devicekeys")
            .cloned()
            .unwrap_or_default();

        let spn = $value.get_ava_single_proto_string("spn").ok_or(
            OperationError::InvalidAccountState("Missing attribute: spn".to_string()),
        )?;

        let mail_primary = $value.get_ava_mail_primary("mail").map(str::to_string);

        let mail = $value
            .get_ava_iter_mail("mail")
            .map(|i| i.map(str::to_string).collect())
            .unwrap_or_else(Vec::new);

        let valid_from = $value.get_ava_single_datetime("account_valid_from");

        let expire = $value.get_ava_single_datetime("account_expire");

        let radius_secret = $value
            .get_ava_single_secret("radius_secret")
            .map(str::to_string);

        // Resolved by the caller
        let groups = $groups;

        let uuid = $value.get_uuid().clone();

        let credential_update_intent_tokens = $value
            .get_ava_as_intenttokens("credential_update_intent_token")
            .cloned()
            .unwrap_or_default();

        // Provide hints from groups.
        let mut ui_hints: BTreeSet<_> = groups
            .iter()
            .map(|group: &Group| group.ui_hints.iter())
            .flatten()
            .copied()
            .collect();

        if !$value.attribute_equality("class", &PVCLASS_SYNC_OBJECT) {
            ui_hints.insert(UiHint::CredentialUpdate);
        }

        if $value.attribute_equality("class", &PVCLASS_POSIXACCOUNT) {
            ui_hints.insert(UiHint::PosixAccount);
        }

        Ok(Account {
            uuid,
            name,
            displayname,
            groups,
            primary,
            passkeys,
            devicekeys,
            valid_from,
            expire,
            radius_secret,
            spn,
            ui_hints,
            mail_primary,
            mail,
            credential_update_intent_tokens,
        })
    }};
}

#[derive(Debug, Clone)]
pub struct Account {
    // Later these could be &str if we cache entry here too ...
    // They can't because if we mod the entry, we'll lose the ref.
    //
    // We do need to decide if we'll cache the entry, or if we just "work out"
    // what the ops should be based on the values we cache here ... That's a future
    // william problem I think :)
    pub name: String,
    pub displayname: String,
    pub uuid: Uuid,
    // We want to allow this so that in the future we can populate this into oauth2 tokens
    #[allow(dead_code)]
    pub groups: Vec<Group>,
    pub primary: Option<Credential>,
    pub passkeys: BTreeMap<Uuid, (String, PasskeyV4)>,
    pub devicekeys: BTreeMap<Uuid, (String, DeviceKeyV4)>,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
    pub radius_secret: Option<String>,
    pub spn: String,
    pub ui_hints: BTreeSet<UiHint>,
    // TODO #256: When you add mail, you should update the check to zxcvbn
    // to include these.
    pub mail_primary: Option<String>,
    pub mail: Vec<String>,
    pub credential_update_intent_tokens: BTreeMap<String, IntentTokenState>,
}

impl Account {
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let groups = Group::try_from_account_entry_ro(value, qs)?;
        try_from_entry!(value, groups)
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let groups = Group::try_from_account_entry_rw(value, qs)?;
        try_from_entry!(value, groups)
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let groups = Group::try_from_account_entry_red_ro(value, qs)?;
        try_from_entry!(value, groups)
    }

    pub(crate) fn try_from_entry_no_groups(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_entry!(value, vec![])
    }

    /// Given the session_id and other metadata, create a user authentication token
    /// that represents a users session. Since this metadata can vary from session
    /// to session, this userauthtoken may contain some data (claims) that may yield
    /// different privileges to the bearer.
    pub(crate) fn to_userauthtoken(
        &self,
        session_id: Uuid,
        ct: Duration,
        auth_type: AuthType,
        expiry_secs: Option<u64>,
    ) -> Option<UserAuthToken> {
        // This could consume self?
        // The cred handler provided is what authenticated this user, so we can use it to
        // process what the proper claims should be.
        // Get the claims from the cred_h

        // TODO: Apply policy to this expiry time.
        let expiry = expiry_secs
            .map(|offset| OffsetDateTime::unix_epoch() + ct + Duration::from_secs(offset));

        let issued_at = OffsetDateTime::unix_epoch() + ct;

        // TODO: Apply priv expiry, and what type of token this is (ident, ro, rw).
        let purpose = UatPurpose::ReadWrite { expiry };

        Some(UserAuthToken {
            session_id,
            auth_type,
            expiry,
            issued_at,
            purpose,
            uuid: self.uuid,
            displayname: self.displayname.clone(),
            spn: self.spn.clone(),
            mail_primary: self.mail_primary.clone(),
            ui_hints: self.ui_hints.clone(),
            // application: None,
            // groups: self.groups.iter().map(|g| g.to_proto()).collect(),
        })
    }

    pub fn check_within_valid_time(
        ct: Duration,
        valid_from: Option<&OffsetDateTime>,
        expire: Option<&OffsetDateTime>,
    ) -> bool {
        let cot = OffsetDateTime::unix_epoch() + ct;

        let vmin = if let Some(vft) = valid_from {
            // If current time greater than start time window
            vft <= &cot
        } else {
            // We have no time, not expired.
            true
        };
        let vmax = if let Some(ext) = expire {
            // If exp greater than ct then expired.
            &cot <= ext
        } else {
            // If not present, we are not expired
            true
        };
        // Mix the results
        vmin && vmax
    }

    pub fn is_within_valid_time(&self, ct: Duration) -> bool {
        Self::check_within_valid_time(ct, self.valid_from.as_ref(), self.expire.as_ref())
    }

    // Get related inputs, such as account name, email, etc.
    pub fn related_inputs(&self) -> Vec<&str> {
        let mut inputs = Vec::with_capacity(4 + self.mail.len());
        self.mail.iter().for_each(|m| {
            inputs.push(m.as_str());
        });
        inputs.push(self.name.as_str());
        inputs.push(self.spn.as_str());
        inputs.push(self.displayname.as_str());
        if let Some(s) = self.radius_secret.as_deref() {
            inputs.push(s);
        }
        inputs
    }

    pub fn primary_cred_uuid(&self) -> Option<Uuid> {
        self.primary.as_ref().map(|cred| cred.uuid).or_else(|| {
            if self.is_anonymous() {
                Some(UUID_ANONYMOUS)
            } else {
                None
            }
        })
    }

    pub fn primary_cred_uuid_and_policy(&self) -> Option<(Uuid, CredSoftLockPolicy)> {
        self.primary
            .as_ref()
            .map(|cred| (cred.uuid, cred.softlock_policy()))
            .or_else(|| {
                if self.is_anonymous() {
                    Some((UUID_ANONYMOUS, CredSoftLockPolicy::Unrestricted))
                } else {
                    None
                }
            })
    }

    pub fn is_anonymous(&self) -> bool {
        self.uuid == UUID_ANONYMOUS
    }

    pub(crate) fn gen_generatedpassword_recover_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let ncred = Credential::new_generatedpassword_only(crypto_policy, cleartext)?;
        let vcred = Value::new_credential("primary", ncred);
        Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
    }

    pub(crate) fn gen_password_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let ncred = primary.set_password(crypto_policy, cleartext)?;
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
            }
            // Make a new credential instead
            None => {
                let ncred = Credential::new_password_only(crypto_policy, cleartext)?;
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
            }
        }
    }

    pub(crate) fn gen_webauthn_counter_mod(
        &mut self,
        auth_result: &AuthenticationResult,
    ) -> Result<Option<ModifyList<ModifyInvalid>>, OperationError> {
        let mut ml = Vec::with_capacity(2);
        // Where is the credential we need to update?
        let opt_ncred = match self.primary.as_ref() {
            Some(primary) => primary.update_webauthn_properties(auth_result)?,
            None => None,
        };

        if let Some(ncred) = opt_ncred {
            let vcred = Value::new_credential("primary", ncred);
            ml.push(Modify::Purged("primary_credential".into()));
            ml.push(Modify::Present("primary_credential".into(), vcred));
        }

        // Is it a passkey?
        self.passkeys.iter_mut().for_each(|(u, (t, k))| {
            if let Some(true) = k.update_credential(auth_result) {
                ml.push(Modify::Removed(
                    "passkeys".into(),
                    PartialValue::Passkey(*u),
                ));

                ml.push(Modify::Present(
                    "passkeys".into(),
                    Value::Passkey(*u, t.clone(), k.clone()),
                ));
            }
        });

        if ml.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ModifyList::new_list(ml)))
        }
    }

    pub(crate) fn invalidate_backup_code_mod(
        self,
        code_to_remove: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match self.primary {
            // Change the cred
            Some(primary) => {
                let r_ncred = primary.invalidate_backup_code(code_to_remove);
                match r_ncred {
                    Ok(ncred) => {
                        let vcred = Value::new_credential("primary", ncred);
                        Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
                    }
                    Err(e) => Err(e),
                }
            }
            None => {
                // No credential exists, we can't supplementy it.
                Err(OperationError::InvalidState)
            }
        }
    }

    pub(crate) fn check_credential_pw(&self, cleartext: &str) -> Result<bool, OperationError> {
        self.primary
            .as_ref()
            .ok_or(OperationError::InvalidState)
            .and_then(|cred| cred.password_ref().and_then(|pw| pw.verify(cleartext)))
    }

    pub(crate) fn regenerate_radius_secret_mod(
        &self,
        cleartext: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let vcred = Value::new_secret_str(cleartext);
        Ok(ModifyList::new_purge_and_set("radius_secret", vcred))
    }

    pub(crate) fn to_credentialstatus(&self) -> Result<CredentialStatus, OperationError> {
        // In the future this will need to handle multiple credentials, not just single.

        self.primary
            .as_ref()
            .map(|cred| CredentialStatus {
                creds: vec![cred.into()],
            })
            .ok_or(OperationError::NoMatchingAttributes)
    }

    pub(crate) fn to_backupcodesview(&self) -> Result<BackupCodesView, OperationError> {
        self.primary
            .as_ref()
            .ok_or(OperationError::InvalidState)
            .and_then(|cred| cred.get_backup_code_view())
    }

    pub(crate) fn existing_credential_id_list(&self) -> Option<Vec<CredentialID>> {
        // TODO!!!
        // Used in registrations only for disallowing existing credentials.
        None
    }

    pub(crate) fn check_user_auth_token_valid(
        ct: Duration,
        uat: &UserAuthToken,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> bool {
        // Remember, token expiry is checked by validate_and_parse_token_to_token.
        // If we wanted we could check other properties of the uat here?
        // Alternatelly, we could always store LESS in the uat because of this?

        let within_valid_window = Account::check_within_valid_time(
            ct,
            entry.get_ava_single_datetime("account_valid_from").as_ref(),
            entry.get_ava_single_datetime("account_expire").as_ref(),
        );

        if !within_valid_window {
            security_info!("Account has expired or is not yet valid, not allowing to proceed");
            return false;
        }

        // Anonymous does NOT record it's sessions, so we simply check the expiry time
        // of the token. This is already done for us as noted above.

        if uat.auth_type == AuthType::Anonymous {
            security_info!("Anonymous sessions do not have session records, session is valid.");
            true
        } else {
            // Get the sessions.
            let session_present = entry
                .get_ava_as_session_map("user_auth_token_session")
                .map(|session_map| session_map.get(&uat.session_id).is_some())
                .unwrap_or(false);

            if session_present {
                security_info!("A valid session value exists for this token");
                true
            } else {
                let grace = uat.issued_at + GRACE_WINDOW;
                let current = time::OffsetDateTime::unix_epoch() + ct;
                trace!(%grace, %current);
                if current >= grace {
                    security_info!(
                        "The token grace window has passed, and no session exists. Assuming invalid."
                    );
                    false
                } else {
                    security_info!("The token grace window is in effect. Assuming valid.");
                    true
                }
            }
        }
    }
}

// Need to also add a "to UserAuthToken" ...

// Need tests for conversion and the cred validations

pub struct DestroySessionTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // Which token id.
    pub token_id: Uuid,
}

impl DestroySessionTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, token_id: Uuid) -> Self {
        DestroySessionTokenEvent {
            ident: Identity::from_internal(),
            target,
            token_id,
        }
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn account_destroy_session_token(
        &mut self,
        dte: &DestroySessionTokenEvent,
    ) -> Result<(), OperationError> {
        // Delete the attribute with uuid.
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            AttrString::from("user_auth_token_session"),
            PartialValue::Refer(dte.token_id),
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_and!([
                    f_eq("uuid", PartialValue::Uuid(dte.target)),
                    f_eq("user_auth_token_session", PartialValue::Refer(dte.token_id))
                ])),
                // Filter as intended (acp)
                &filter_all!(f_and!([
                    f_eq("uuid", PartialValue::Uuid(dte.target)),
                    f_eq("user_auth_token_session", PartialValue::Refer(dte.token_id))
                ])),
                &modlist,
                // Provide the event to impersonate
                &dte.ident,
            )
            .map_err(|e| {
                admin_error!("Failed to destroy user auth token {:?}", e);
                e
            })
    }

    pub fn service_account_into_person(
        &mut self,
        ident: &Identity,
        target_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let schema_ref = self.qs_write.get_schema();

        // Get the entry.
        let account_entry = self
            .qs_write
            .internal_search_uuid(target_uuid)
            .map_err(|e| {
                admin_error!("Failed to start service account into person -> {:?}", e);
                e
            })?;

        // Copy the current classes
        let prev_classes: BTreeSet<_> = account_entry
            .get_ava_as_iutf8_iter("class")
            .ok_or_else(|| {
                admin_error!("Invalid entry, class attribute is not present or not iutf8");
                OperationError::InvalidAccountState("Missing attribute: class".to_string())
            })?
            .collect();

        // Remove the service account class.
        // Add the person class.
        let mut new_classes = prev_classes.clone();
        new_classes.remove("service_account");
        new_classes.insert("person");

        // diff the schema attrs, and remove the ones that are service_account only.
        let (_added, removed) = schema_ref
            .query_attrs_difference(&prev_classes, &new_classes)
            .map_err(|se| {
                admin_error!("While querying the schema, it reported that requested classes may not be present indicating a possible corruption");
                OperationError::SchemaViolation(
                    se
                )
            })?;

        // Now construct the modlist which:
        // removes service_account
        let mut modlist =
            ModifyList::new_remove("class", PartialValue::new_class("service_account"));
        // add person
        modlist.push_mod(Modify::Present("class".into(), Value::new_class("person")));
        // purge the other attrs that are SA only.
        removed
            .into_iter()
            .for_each(|attr| modlist.push_mod(Modify::Purged(attr.into())));
        // purge existing sessions

        // Modify
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::Uuid(target_uuid))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::Uuid(target_uuid))),
                &modlist,
                // Provide the entry to impersonate
                ident,
            )
            .map_err(|e| {
                admin_error!("Failed to migrate service account to person - {:?}", e);
                e
            })
    }
}

pub struct ListUserAuthTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn account_list_user_auth_tokens(
        &mut self,
        lte: &ListUserAuthTokenEvent,
    ) -> Result<Vec<UatStatus>, OperationError> {
        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            lte.ident.clone(),
            lte.target,
            &self.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                admin_error!("Failed to begin account list user auth tokens: {:?}", e);
                return Err(e);
            }
        };

        match self.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                entries
                    .pop()
                    // get the first entry
                    .and_then(|e| {
                        let account_id = e.get_uuid();
                        // From the entry, turn it into the value
                        e.get_ava_as_session_map("user_auth_token_session")
                            .map(|smap| {
                                smap.iter()
                                    .map(|(u, s)| {
                                        s.scope
                                            .try_into()
                                            .map(|purpose| UatStatus {
                                                account_id,
                                                session_id: *u,
                                                expiry: s.expiry,
                                                issued_at: s.issued_at,
                                                purpose,
                                            })
                                            .map_err(|e| {
                                                admin_error!("Invalid user auth token {}", u);
                                                e
                                            })
                                    })
                                    .collect::<Result<Vec<_>, _>>()
                            })
                    })
                    .unwrap_or_else(|| {
                        // No matching entry? Return none.
                        Ok(Vec::new())
                    })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use async_std::task;
    use kanidm_proto::v1::{AuthType, UiHint};

    #[test]
    fn test_idm_account_from_anonymous() {
        let anon_e = entry_str_to_account!(JSON_ANONYMOUS_V1);
        debug!("{:?}", anon_e);
        // I think that's it? we may want to check anonymous mech ...
    }

    #[test]
    fn test_idm_account_ui_hints() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = duration_from_epoch_now();
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));

            let target_uuid = Uuid::new_v4();

            // Create a user. So far no ui hints.
            // Create a service account
            let e = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testaccount")),
                ("uuid", Value::Uuid(target_uuid)),
                ("description", Value::new_utf8s("testaccount")),
                ("displayname", Value::new_utf8s("Test Account"))
            );

            let ce = CreateEvent::new_internal(vec![e]);
            assert!(idms_prox_write.qs_write.create(&ce).is_ok());

            let account = idms_prox_write
                .target_to_account(target_uuid)
                .expect("account must exist");
            let session_id = uuid::Uuid::new_v4();
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::Passkey, None)
                .expect("Unable to create uat");

            // Check the ui hints are as expected.
            assert!(uat.ui_hints.len() == 1);
            assert!(uat.ui_hints.contains(&UiHint::CredentialUpdate));

            // Modify the user to be a posix account, ensure they get the hint.
            let me_posix = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testaccount"))),
                    ModifyList::new_list(vec![
                        Modify::Present(
                            AttrString::from("class"),
                            Value::new_class("posixaccount"),
                        ),
                        Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                    ]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

            // Check the ui hints are as expected.
            let account = idms_prox_write
                .target_to_account(target_uuid)
                .expect("account must exist");
            let session_id = uuid::Uuid::new_v4();
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::Passkey, None)
                .expect("Unable to create uat");

            assert!(uat.ui_hints.len() == 2);
            assert!(uat.ui_hints.contains(&UiHint::PosixAccount));
            assert!(uat.ui_hints.contains(&UiHint::CredentialUpdate));

            // Add a group with a ui hint, and then check they get the hint.
            let e = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("group")),
                ("name", Value::new_iname("test_uihint_group")),
                ("member", Value::Refer(target_uuid)),
                ("grant_ui_hint", Value::UiHint(UiHint::ExperimentalFeatures))
            );

            let ce = CreateEvent::new_internal(vec![e]);
            assert!(idms_prox_write.qs_write.create(&ce).is_ok());

            // Check the ui hints are as expected.
            let account = idms_prox_write
                .target_to_account(target_uuid)
                .expect("account must exist");
            let session_id = uuid::Uuid::new_v4();
            let uat = account
                .to_userauthtoken(session_id, ct, AuthType::Passkey, None)
                .expect("Unable to create uat");

            assert!(uat.ui_hints.len() == 3);
            assert!(uat.ui_hints.contains(&UiHint::PosixAccount));
            assert!(uat.ui_hints.contains(&UiHint::ExperimentalFeatures));
            assert!(uat.ui_hints.contains(&UiHint::CredentialUpdate));

            assert!(idms_prox_write.commit().is_ok());
        })
    }
}

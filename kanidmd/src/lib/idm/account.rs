use crate::credential::BackupCodes;
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntrySealed};
use crate::prelude::*;

use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{AuthType, UserAuthToken};
use kanidm_proto::v1::{BackupCodesView, CredentialStatus};

use crate::constants::UUID_ANONYMOUS;
use crate::credential::policy::CryptoPolicy;
use crate::credential::totp::Totp;
use crate::credential::{softlock::CredSoftLockPolicy, Credential};
use crate::idm::group::Group;
use crate::modify::{ModifyInvalid, ModifyList};
use crate::value::{PartialValue, Value};

use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::proto::Credential as WebauthnCredential;
use webauthn_rs::proto::{Counter, CredentialID};

lazy_static! {
    static ref PVCLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
}

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
            .get_ava_single_str("name")
            .map(|s| s.to_string())
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: name".to_string(),
            ))?;

        let displayname = $value
            .get_ava_single_str("displayname")
            .map(|s| s.to_string())
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: displayname".to_string(),
            ))?;

        let primary = $value
            .get_ava_single_credential("primary_credential")
            .map(|v| v.clone());

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

        Ok(Account {
            uuid,
            name,
            displayname,
            groups,
            primary,
            valid_from,
            expire,
            radius_secret,
            spn,
            mail_primary,
            mail,
        })
    }};
}

#[derive(Debug, Clone)]
pub(crate) struct Account {
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
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
    pub radius_secret: Option<String>,
    // primary: Credential
    // app_creds: Vec<Credential>
    // account expiry? (as opposed to cred expiry)
    pub spn: String,
    // TODO #256: When you add mail, you should update the check to zxcvbn
    // to include these.
    pub mail_primary: Option<String>,
    pub mail: Vec<String>,
}

impl Account {
    pub(crate) fn try_from_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        spanned!("idm::account::try_from_entry_ro", {
            let groups = Group::try_from_account_entry_ro(value, qs)?;
            try_from_entry!(value, groups)
        })
    }

    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        spanned!("idm::account::try_from_entry_rw", {
            let groups = Group::try_from_account_entry_rw(value, qs)?;
            try_from_entry!(value, groups)
        })
    }

    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        spanned!("idm::account::try_from_entry_reduced", {
            let groups = Group::try_from_account_entry_red_ro(value, qs)?;
            try_from_entry!(value, groups)
        })
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
    ) -> Option<UserAuthToken> {
        // This could consume self?
        // The cred handler provided is what authenticated this user, so we can use it to
        // process what the proper claims should be.
        // Get the claims from the cred_h

        // TODO: Apply policy to this expiry time.
        let expiry = OffsetDateTime::unix_epoch() + ct + Duration::from_secs(AUTH_SESSION_EXPIRY);

        Some(UserAuthToken {
            session_id,
            auth_type,
            expiry,
            uuid: self.uuid,
            // name: self.name.clone(),
            displayname: self.displayname.clone(),
            spn: self.spn.clone(),
            mail_primary: self.mail_primary.clone(),
            // application: None,
            // groups: self.groups.iter().map(|g| g.to_proto()).collect(),
            // What's the best way to get access to these limits with regard to claims/other?
            lim_uidx: false,
            lim_rmax: 128,
            lim_pmax: 256,
            lim_fmax: 32,
        })
    }

    pub fn check_within_valid_time(
        ct: Duration,
        valid_from: Option<&OffsetDateTime>,
        expire: Option<&OffsetDateTime>,
    ) -> bool {
        let cot = OffsetDateTime::unix_epoch() + ct;

        let vmin = if let Some(vft) = valid_from {
            // If current time greater than strat time window
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

    pub fn primary_cred_uuid(&self) -> Uuid {
        match &self.primary {
            Some(cred) => cred.uuid,
            None => UUID_ANONYMOUS,
        }
    }

    pub fn primary_cred_softlock_policy(&self) -> Option<CredSoftLockPolicy> {
        self.primary
            .as_ref()
            .and_then(|cred| cred.softlock_policy())
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

    pub(crate) fn gen_totp_mod(
        &self,
        token: Totp,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let ncred = primary.update_totp(token);
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
            }
            None => {
                // No credential exists, we can't supplementy it.
                Err(OperationError::InvalidState)
            }
        }
    }

    pub(crate) fn gen_totp_remove_mod(&self) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let ncred = primary.remove_totp();
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
            }
            None => {
                // No credential exists, we can't remove what is not real.
                Err(OperationError::InvalidState)
            }
        }
    }

    pub(crate) fn gen_webauthn_mod(
        &self,
        label: String,
        cred: WebauthnCredential,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let ncred = match &self.primary {
            Some(primary) => primary.append_webauthn(label, cred)?,
            None => Credential::new_webauthn_only(label, cred),
        };
        let vcred = Value::new_credential("primary", ncred);
        Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
    }

    pub(crate) fn gen_webauthn_remove_mod(
        &self,
        label: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let ncred = primary.remove_webauthn(label)?;
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
            }
            None => {
                // No credential exists, we can't remove what is not real.
                Err(OperationError::InvalidState)
            }
        }
    }

    #[allow(clippy::ptr_arg)]
    pub(crate) fn gen_webauthn_counter_mod(
        &self,
        cid: &CredentialID,
        counter: Counter,
    ) -> Result<Option<ModifyList<ModifyInvalid>>, OperationError> {
        //
        let opt_ncred = match self.primary.as_ref() {
            Some(primary) => primary.update_webauthn_counter(cid, counter)?,
            None => None,
        };

        match opt_ncred {
            Some(ncred) => {
                let vcred = Value::new_credential("primary", ncred);
                Ok(Some(ModifyList::new_purge_and_set(
                    "primary_credential",
                    vcred,
                )))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn gen_backup_code_mod(
        &self,
        backup_codes: BackupCodes,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let r_ncred = primary.update_backup_code(backup_codes);
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

    pub(crate) fn gen_backup_code_remove_mod(
        &self,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let r_ncred = primary.remove_backup_code();
                match r_ncred {
                    Ok(ncred) => {
                        let vcred = Value::new_credential("primary", ncred);
                        Ok(ModifyList::new_purge_and_set("primary_credential", vcred))
                    }
                    Err(e) => Err(e),
                }
            }
            None => {
                // No credential exists, we can't remove what is not real.
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
}

// Need to also add a "to UserAuthToken" ...

// Need tests for conversion and the cred validations

#[cfg(test)]
mod tests {
    use crate::constants::JSON_ANONYMOUS_V1;
    // use crate::entry::{Entry, EntryNew, EntrySealed};
    // use crate::idm::account::Account;

    #[test]
    fn test_idm_account_from_anonymous() {
        let anon_e = entry_str_to_account!(JSON_ANONYMOUS_V1);
        debug!("{:?}", anon_e);
        // I think that's it? we may want to check anonymous mech ...
    }

    #[test]
    fn test_idm_account_from_real() {
        // For now, nothing, but later, we'll test different types of cred
        // passing.
    }

    #[test]
    fn test_idm_account_set_credential() {
        // Using a real entry, set a credential back to it's entry.
        // In the end, this boils down to a modify operation on the Value
    }
}

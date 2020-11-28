use crate::entry::{Entry, EntryCommitted, EntrySealed};
use kanidm_proto::v1::OperationError;

use kanidm_proto::v1::UserAuthToken;

use crate::audit::AuditScope;
use crate::constants::UUID_ANONYMOUS;
use crate::credential::policy::CryptoPolicy;
use crate::credential::totp::TOTP;
use crate::credential::{softlock::CredSoftLockPolicy, Credential};
use crate::idm::claim::Claim;
use crate::idm::group::Group;
use crate::modify::{ModifyInvalid, ModifyList};
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};
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
        if !$value.attribute_value_pres("class", &PVCLASS_ACCOUNT) {
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

        let spn = $value
            .get_ava_single("spn")
            .map(|s| {
                debug_assert!(s.is_spn());
                s.to_proto_string_clone()
            })
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: spn".to_string(),
            ))?;

        let valid_from = $value.get_ava_single_datetime("account_valid_from");

        let expire = $value.get_ava_single_datetime("account_expire");

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
            spn,
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
    pub groups: Vec<Group>,
    pub primary: Option<Credential>,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
    // primary: Credential
    // app_creds: Vec<Credential>
    // account expiry? (as opposed to cred expiry)
    pub spn: String,
    // TODO #256: When you add mail, you should update the check to zxcvbn
    // to include these.
    // pub mail: Vec<String>
}

impl Account {
    pub(crate) fn try_from_entry_ro(
        au: &mut AuditScope,
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        lperf_trace_segment!(au, "idm::account::try_from_entry_ro", || {
            let groups = Group::try_from_account_entry_ro(au, value, qs)?;
            try_from_entry!(value, groups)
        })
    }

    pub(crate) fn try_from_entry_rw(
        au: &mut AuditScope,
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let groups = Group::try_from_account_entry_rw(au, value, qs)?;
        try_from_entry!(value, groups)
    }

    #[cfg(test)]
    pub(crate) fn try_from_entry_no_groups(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_entry!(value, vec![])
    }

    // Could this actually take a claims list and application instead?
    pub(crate) fn to_userauthtoken(&self, claims: &[Claim]) -> Option<UserAuthToken> {
        // This could consume self?
        // The cred handler provided is what authenticated this user, so we can use it to
        // process what the proper claims should be.
        // Get the claims from the cred_h

        Some(UserAuthToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            displayname: self.name.clone(),
            uuid: self.uuid.to_hyphenated_ref().to_string(),
            // application: None,
            groups: self.groups.iter().map(|g| g.to_proto()).collect(),
            claims: claims.iter().map(|c| c.to_proto()).collect(),
            // What's the best way to get access to these limits with regard to claims/other?
            lim_uidx: false,
            lim_rmax: 128,
            lim_pmax: 256,
            lim_fmax: 32,
        })
    }

    pub fn is_within_valid_time(&self, ct: Duration) -> bool {
        let cot = OffsetDateTime::unix_epoch() + ct;

        let vmin = if let Some(vft) = &self.valid_from {
            // If current time greater than strat time window
            vft < &cot
        } else {
            // We have no time, not expired.
            true
        };
        let vmax = if let Some(ext) = &self.expire {
            // If exp greater than ct then expired.
            &cot < ext
        } else {
            // If not present, we are not expired
            true
        };
        // Mix the results
        vmin && vmax
    }

    pub fn primary_cred_uuid(&self) -> Uuid {
        match &self.primary {
            Some(cred) => cred.uuid,
            None => *UUID_ANONYMOUS,
        }
    }

    pub fn primary_cred_softlock_policy(&self) -> Option<CredSoftLockPolicy> {
        self.primary
            .as_ref()
            .and_then(|cred| cred.softlock_policy())
    }

    pub fn is_anonymous(&self) -> bool {
        self.uuid == *UUID_ANONYMOUS
    }

    pub(crate) fn gen_password_mod(
        &self,
        cleartext: &str,
        appid: &Option<String>,
        crypto_policy: &CryptoPolicy,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        // What should this look like? Probablf an appid + stuff -> modify?
        // then the caller has to apply the modify under the requests event
        // for proper auth checks.
        match appid {
            Some(_) => Err(OperationError::InvalidState),
            None => {
                // TODO #59: Enforce PW policy. Can we allow this change?
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
            } // no appid
        }
    }

    pub(crate) fn gen_totp_mod(
        &self,
        token: TOTP,
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
                Ok(Some(ModifyList::new_purge_and_set("primary_credential", vcred)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn check_credential_pw(
        &self,
        cleartext: &str,
        appid: &Option<String>,
    ) -> Result<bool, OperationError> {
        match appid {
            Some(_) => Err(OperationError::InvalidState),
            None => {
                match &self.primary {
                    // Check the cred's associated pw.
                    Some(ref primary) => primary
                        .password
                        .as_ref()
                        .ok_or(OperationError::InvalidState)
                        .and_then(|pw| pw.verify(cleartext)),
                    None => Err(OperationError::InvalidState),
                }
            } // no appid
        }
    }

    pub(crate) fn regenerate_radius_secret_mod(
        &self,
        cleartext: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let vcred = Value::new_radius_str(cleartext);
        Ok(ModifyList::new_purge_and_set("radius_secret", vcred))
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

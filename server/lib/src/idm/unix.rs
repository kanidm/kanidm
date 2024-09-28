use std::iter;
// use crossbeam::channel::Sender;
use std::time::Duration;

use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};
use time::OffsetDateTime;
use tokio::sync::mpsc::UnboundedSender as Sender;
use uuid::Uuid;

use kanidm_lib_crypto::CryptoPolicy;

use crate::credential::softlock::CredSoftLockPolicy;
use crate::credential::Credential;
use crate::idm::delayed::{DelayedAction, UnixPasswordUpgrade};
use crate::modify::{ModifyInvalid, ModifyList};
use crate::prelude::*;

#[derive(Debug, Clone)]
pub(crate) struct UnixUserAccount {
    pub name: String,
    pub spn: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
    pub radius_secret: Option<String>,
    pub mail: Vec<String>,

    cred: Option<Credential>,
    pub shell: Option<String>,
    pub sshkeys: Vec<String>,
    pub gidnumber: u32,
    pub groups: Vec<UnixGroup>,
}

macro_rules! try_from_entry {
    ($value:expr, $groups:expr) => {{
        if !$value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !$value.attribute_equality(
            Attribute::Class,
            &EntryClass::PosixAccount.to_partialvalue(),
        ) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = $value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Spn
                ))
            })?;

        let uuid = $value.get_uuid();

        let displayname = $value
            .get_ava_single_utf8(Attribute::DisplayName)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::DisplayName
                ))
            })?;

        let gidnumber = $value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::GidNumber
                ))
            })?;

        let shell = $value
            .get_ava_single_iutf8(Attribute::LoginShell)
            .map(|s| s.to_string());

        let sshkeys = $value
            .get_ava_iter_sshpubkeys(Attribute::SshPublicKey)
            .map(|i| i.map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let cred = $value
            .get_ava_single_credential(Attribute::UnixPassword)
            .cloned();

        let radius_secret = $value
            .get_ava_single_secret(Attribute::RadiusSecret)
            .map(str::to_string);

        let mail = $value
            .get_ava_iter_mail(Attribute::Mail)
            .map(|i| i.map(str::to_string).collect())
            .unwrap_or_default();

        let valid_from = $value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let expire = $value.get_ava_single_datetime(Attribute::AccountExpire);

        Ok(UnixUserAccount {
            name,
            spn,
            uuid,
            displayname,
            gidnumber,
            shell,
            sshkeys,
            groups: $groups,
            cred,
            valid_from,
            expire,
            radius_secret,
            mail,
        })
    }};
}

#[allow(dead_code)]
impl UnixUserAccount {
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_rw(value, qs)?;
        try_from_entry!(value, groups)
    }

    pub(crate) fn try_from_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
        allow_default_cred_fallback: bool,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_ro(value, qs)?;
        let result: Result<UnixUserAccount, OperationError> = try_from_entry!(value, groups);
        let mut result = match result {
            Ok(v) => v,
            Err(_) => unreachable!(),
        };

        if result.cred.is_none() && allow_default_cred_fallback {
            result.cred = value
                .get_ava_single_credential(Attribute::PrimaryCredential)
                .cloned();
        }

        Ok(result)
    }

    pub(crate) fn to_unixusertoken(&self, ct: Duration) -> Result<UnixUserToken, OperationError> {
        let groups: Result<Vec<_>, _> = self.groups.iter().map(|g| g.to_unixgrouptoken()).collect();
        let groups = groups?;

        Ok(UnixUserToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            displayname: self.displayname.clone(),
            gidnumber: self.gidnumber,
            uuid: self.uuid,
            shell: self.shell.clone(),
            groups,
            sshkeys: self.sshkeys.clone(),
            valid: self.is_within_valid_time(ct),
        })
    }

    pub fn unix_cred_uuid_and_policy(&self) -> Option<(Uuid, CredSoftLockPolicy)> {
        self.cred
            .as_ref()
            .map(|cred| (cred.uuid, cred.softlock_policy()))
    }

    pub fn is_anonymous(&self) -> bool {
        self.uuid == UUID_ANONYMOUS
    }

    pub(crate) fn gen_password_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let ncred = Credential::new_password_only(crypto_policy, cleartext)?;
        let vcred = Value::new_credential("unix", ncred);
        Ok(ModifyList::new_purge_and_set(
            Attribute::UnixPassword,
            vcred,
        ))
    }

    pub(crate) fn gen_password_upgrade_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<Option<ModifyList<ModifyInvalid>>, OperationError> {
        match &self.cred {
            // Change the cred
            Some(ucred) => {
                if let Some(ncred) = ucred.upgrade_password(crypto_policy, cleartext)? {
                    let vcred = Value::new_credential("primary", ncred);
                    Ok(Some(ModifyList::new_purge_and_set(
                        Attribute::UnixPassword,
                        vcred,
                    )))
                } else {
                    // No action, not the same pw
                    Ok(None)
                }
            }
            // Nothing to do.
            None => Ok(None),
        }
    }

    pub fn is_within_valid_time(&self, ct: Duration) -> bool {
        let cot = OffsetDateTime::UNIX_EPOCH + ct;

        let vmin = if let Some(vft) = &self.valid_from {
            // If current time greater than start time window
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

    pub(crate) fn verify_unix_credential(
        &self,
        cleartext: &str,
        async_tx: &Sender<DelayedAction>,
        ct: Duration,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        // Is the cred locked?
        // NOW checked by the caller!

        /*
        if !self.is_within_valid_time(ct) {
            lsecurity!(au, "Account is not within valid time period");
            return Ok(None);
        }
        */

        // is the cred some or none?
        match &self.cred {
            Some(cred) => {
                cred.password_ref().and_then(|pw| {
                    let valid = pw.verify(cleartext).map_err(|e| {
                        error!(crypto_err = ?e);
                        e.into()
                    })?;
                    if valid {
                        security_info!("Successful unix cred handling");
                        if pw.requires_upgrade() {
                            async_tx
                                .send(DelayedAction::UnixPwUpgrade(UnixPasswordUpgrade {
                                    target_uuid: self.uuid,
                                    existing_password: cleartext.to_string(),
                                }))
                                .map_err(|_| {
                                    admin_error!(
                                        "failed to queue delayed action - unix password upgrade"
                                    );
                                    OperationError::InvalidState
                                })?;
                        }

                        // Technically this means we check the times twice, but that doesn't
                        // seem like a big deal when we want to short cut return on invalid.
                        Some(self.to_unixusertoken(ct)).transpose()
                    } else {
                        // Failed to auth
                        security_info!("Failed unix cred handling (denied)");
                        Ok(None)
                    }
                })
            }
            // They don't have a unix cred, fail the auth.
            None => {
                security_info!("Failed unix cred handling (no cred present)");
                Ok(None)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UnixGroup {
    pub name: String,
    pub spn: String,
    pub gidnumber: u32,
    pub uuid: Uuid,
}

macro_rules! try_from_group_e {
    ($value:expr) => {{
        // We could be looking at a user for their UPG, OR a true group.

        if !(($value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue())
            && $value.attribute_equality(
                Attribute::Class,
                &EntryClass::PosixAccount.to_partialvalue(),
            ))
            || ($value.attribute_equality(Attribute::Class, &EntryClass::Group.to_partialvalue())
                && $value.attribute_equality(
                    Attribute::Class,
                    &EntryClass::PosixGroup.to_partialvalue(),
                )))
        {
            return Err(OperationError::InvalidAccountState(format!(
                "Missing {}: {} && {} OR {} && {}",
                Attribute::Class,
                Attribute::Account,
                EntryClass::PosixAccount,
                Attribute::Group,
                EntryClass::PosixGroup,
            )));
        }

        let name = $value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Spn
                ))
            })?;

        let uuid = $value.get_uuid();

        let gidnumber = $value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::GidNumber
                ))
            })?;

        Ok(UnixGroup {
            name,
            spn,
            gidnumber,
            uuid,
        })
    }};
}

macro_rules! try_from_account_group_e {
    ($value:expr, $qs:expr) => {{
        // First synthesise the self-group from the account.
        // We have already checked these, but paranoia is better than
        // complacency.
        if !$value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue()) {
            return Err(OperationError::InvalidAccountState(format!(
                "Missing class: {}",
                EntryClass::Account
            )));
        }

        if !$value.attribute_equality(
            Attribute::Class,
            &EntryClass::PosixAccount.to_partialvalue(),
        ) {
            return Err(OperationError::InvalidAccountState(format!(
                "Missing class: {}",
                EntryClass::PosixAccount
            )));
        }

        let name = $value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Spn
                ))
            })?;

        let uuid = $value.get_uuid();

        let gidnumber = $value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::GidNumber
                ))
            })?;

        // This is the user private group.
        let upg = UnixGroup {
            name,
            spn,
            gidnumber,
            uuid,
        };

        match $value.get_ava_as_refuuid(Attribute::MemberOf) {
            Some(riter) => {
                let f = filter!(f_and!([
                    f_eq(Attribute::Class, EntryClass::PosixGroup.into()),
                    f_eq(Attribute::Class, EntryClass::Group.into()),
                    f_or(
                        riter
                            .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                            .collect()
                    )
                ]));
                let group_entries: Vec<_> = $qs.internal_search(f)?;
                let groups: Result<Vec<_>, _> = iter::once(Ok(upg))
                    .chain(
                        group_entries
                            .iter()
                            .map(|e| UnixGroup::try_from_entry(e.as_ref())),
                    )
                    .collect();
                groups
            }
            None => {
                // No memberof, no groups!
                Ok(vec![upg])
            }
        }
    }};
}

impl UnixGroup {
    pub(crate) fn try_from_account_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(value, qs)
    }

    pub(crate) fn try_from_account_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(value, qs)
    }

    /*
    pub fn try_from_account_entry_red_ro(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(au, value, qs)
    }
    */

    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_group_e!(value)
    }

    pub(crate) fn try_from_entry(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_group_e!(value)
    }

    pub(crate) fn to_unixgrouptoken(&self) -> Result<UnixGroupToken, OperationError> {
        Ok(UnixGroupToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            uuid: self.uuid,
            gidnumber: self.gidnumber,
        })
    }
}

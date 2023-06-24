use std::iter;
// use crossbeam::channel::Sender;
use std::time::Duration;

use kanidm_proto::v1::{OperationError, UnixGroupToken, UnixUserToken};
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
    pub gidnumber: u32,
    pub uuid: Uuid,
    pub shell: Option<String>,
    pub sshkeys: Vec<String>,
    pub groups: Vec<UnixGroup>,
    cred: Option<Credential>,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
    pub radius_secret: Option<String>,
    pub mail: Vec<String>,
}

macro_rules! try_from_entry {
    ($value:expr, $groups:expr) => {{
        if !$value.attribute_equality("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !$value.attribute_equality("class", &PVCLASS_POSIXACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = $value
            .get_ava_single_iname("name")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;

        let spn = $value.get_ava_single_proto_string("spn").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: spn".to_string())
        })?;

        let uuid = $value.get_uuid();

        let displayname = $value
            .get_ava_single_utf8("displayname")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: displayname".to_string())
            })?;

        let gidnumber = $value.get_ava_single_uint32("gidnumber").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: gidnumber".to_string())
        })?;

        let shell = $value
            .get_ava_single_iutf8("loginshell")
            .map(|s| s.to_string());

        let sshkeys = $value
            .get_ava_iter_sshpubkeys("ssh_publickey")
            .map(|i| i.map(|s| s.to_string()).collect())
            .unwrap_or_else(Vec::new);

        let cred = $value
            .get_ava_single_credential("unix_password")
            .map(|v| v.clone());

        let radius_secret = $value
            .get_ava_single_secret("radius_secret")
            .map(str::to_string);

        let mail = $value
            .get_ava_iter_mail("mail")
            .map(|i| i.map(str::to_string).collect())
            .unwrap_or_else(Vec::new);

        let valid_from = $value.get_ava_single_datetime("account_valid_from");

        let expire = $value.get_ava_single_datetime("account_expire");

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
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_ro(value, qs)?;
        try_from_entry!(value, groups)
    }

    /*
    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_red_ro(au, value, qs)?;
        try_from_entry!(value, groups)
    }
    */

    pub(crate) fn to_unixusertoken(&self, ct: Duration) -> Result<UnixUserToken, OperationError> {
        let groups: Result<Vec<_>, _> = self.groups.iter().map(|g| g.to_unixgrouptoken()).collect();
        let groups = groups?;

        Ok(UnixUserToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            displayname: self.displayname.clone(),
            gidnumber: self.gidnumber,
            uuid: self.uuid.as_hyphenated().to_string(),
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
        Ok(ModifyList::new_purge_and_set("unix_password", vcred))
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

    pub(crate) fn check_existing_pw(&self, cleartext: &str) -> Result<bool, OperationError> {
        match &self.cred {
            Some(cred) => cred.password_ref().and_then(|pw| {
                pw.verify(cleartext).map_err(|e| {
                    error!(crypto_err = ?e);
                    e.into()
                })
            }),
            None => Err(OperationError::InvalidState),
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

        if !(($value.attribute_equality("class", &PVCLASS_ACCOUNT)
            && $value.attribute_equality("class", &PVCLASS_POSIXACCOUNT))
            || ($value.attribute_equality("class", &PVCLASS_GROUP)
                && $value.attribute_equality("class", &PVCLASS_POSIXGROUP)))
        {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account && posixaccount OR group && posixgroup".to_string(),
            ));
        }

        let name = $value
            .get_ava_single_iname("name")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;

        let spn = $value.get_ava_single_proto_string("spn").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: spn".to_string())
        })?;

        let uuid = $value.get_uuid();

        let gidnumber = $value.get_ava_single_uint32("gidnumber").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: gidnumber".to_string())
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
        if !$value.attribute_equality("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !$value.attribute_equality("class", &PVCLASS_POSIXACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = $value
            .get_ava_single_iname("name")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;

        let spn = $value.get_ava_single_proto_string("spn").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: spn".to_string())
        })?;

        let uuid = $value.get_uuid();

        let gidnumber = $value.get_ava_single_uint32("gidnumber").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: gidnumber".to_string())
        })?;

        // This is the user private group.
        let upg = UnixGroup {
            name,
            spn,
            gidnumber,
            uuid,
        };

        match $value.get_ava_as_refuuid("memberof") {
            Some(riter) => {
                let f = filter!(f_and!([
                    f_eq("class", PVCLASS_POSIXGROUP.clone()),
                    f_eq("class", PVCLASS_GROUP.clone()),
                    f_or(riter.map(|u| f_eq("uuid", PartialValue::Uuid(u))).collect())
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
    pub fn try_from_account_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(value, qs)
    }

    pub fn try_from_account_entry_ro(
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

    pub fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_group_e!(value)
    }

    pub fn try_from_entry(
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_group_e!(value)
    }

    pub(crate) fn to_unixgrouptoken(&self) -> Result<UnixGroupToken, OperationError> {
        Ok(UnixGroupToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            uuid: self.uuid.as_hyphenated().to_string(),
            gidnumber: self.gidnumber,
        })
    }
}

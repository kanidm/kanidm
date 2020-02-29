use uuid::Uuid;

use crate::audit::AuditScope;
use crate::constants::UUID_ANONYMOUS;
use crate::credential::Credential;
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntryValid};
use crate::modify::{ModifyInvalid, ModifyList};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};

use std::iter;

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
}

lazy_static! {
    static ref PVCLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
    static ref PVCLASS_POSIXACCOUNT: PartialValue = PartialValue::new_class("posixaccount");
    static ref PVCLASS_GROUP: PartialValue = PartialValue::new_class("group");
    static ref PVCLASS_POSIXGROUP: PartialValue = PartialValue::new_class("posixgroup");
}

macro_rules! try_from_entry {
    ($value:expr, $groups:expr) => {{
        if !$value.attribute_value_pres("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !$value.attribute_value_pres("class", &PVCLASS_POSIXACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = $value.get_ava_single_string("name").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: name".to_string())
        })?;

        let spn = $value
            .get_ava_single("spn")
            .map(|v| v.to_proto_string_clone())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: spn".to_string())
            })?;

        let uuid = *$value.get_uuid();

        let displayname = $value.get_ava_single_string("displayname").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: displayname".to_string())
        })?;

        let gidnumber = $value.get_ava_single_uint32("gidnumber").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: gidnumber".to_string())
        })?;

        let shell = $value.get_ava_single_string("loginshell");

        let sshkeys = $value.get_ava_ssh_pubkeys("ssh_publickey");

        let cred = $value
            .get_ava_single_credential("unix_password")
            .map(|v| v.clone());

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
        })
    }};
}

impl UnixUserAccount {
    pub(crate) fn try_from_entry_rw(
        au: &mut AuditScope,
        value: Entry<EntryValid, EntryCommitted>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_rw(au, &value, qs)?;
        try_from_entry!(value, groups)
    }

    pub(crate) fn try_from_entry_ro(
        au: &mut AuditScope,
        value: Entry<EntryValid, EntryCommitted>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_ro(au, &value, qs)?;
        try_from_entry!(value, groups)
    }

    pub(crate) fn try_from_entry_reduced(
        au: &mut AuditScope,
        value: Entry<EntryReduced, EntryCommitted>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let groups = UnixGroup::try_from_account_entry_red_ro(au, &value, qs)?;
        try_from_entry!(value, groups)
    }

    pub(crate) fn to_unixusertoken(&self) -> Result<UnixUserToken, OperationError> {
        let groups: Result<Vec<_>, _> = self.groups.iter().map(|g| g.to_unixgrouptoken()).collect();
        let groups = groups?;

        Ok(UnixUserToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            displayname: self.name.clone(),
            gidnumber: self.gidnumber,
            uuid: self.uuid.to_hyphenated_ref().to_string(),
            shell: self.shell.clone(),
            groups: groups,
            sshkeys: self.sshkeys.clone(),
        })
    }

    pub fn is_anonymous(&self) -> bool {
        self.uuid == *UUID_ANONYMOUS
    }

    pub(crate) fn gen_password_mod(
        &self,
        cleartext: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let ncred = Credential::new_password_only(cleartext);
        let vcred = Value::new_credential("unix", ncred);
        Ok(ModifyList::new_purge_and_set("unix_password", vcred))
    }

    pub(crate) fn verify_unix_credential(
        &self,
        _au: &mut AuditScope,
        cleartext: &str,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        // TODO #59: Is the cred locked?
        // is the cred some or none?
        match &self.cred {
            Some(cred) => match &cred.password {
                Some(pw) => {
                    if pw.verify(cleartext) {
                        Some(self.to_unixusertoken()).transpose()
                    } else {
                        // Failed to auth
                        Ok(None)
                    }
                }
                // We have a cred but it's not a password, that's weird
                None => Err(OperationError::InvalidAccountState(
                    "non-password cred type?".to_string(),
                )),
            },
            // They don't have a unix cred, fail the auth.
            None => Ok(None),
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

        if !(($value.attribute_value_pres("class", &PVCLASS_ACCOUNT)
            && $value.attribute_value_pres("class", &PVCLASS_POSIXACCOUNT))
            || ($value.attribute_value_pres("class", &PVCLASS_GROUP)
                && $value.attribute_value_pres("class", &PVCLASS_POSIXGROUP)))
        {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account && posixaccount OR group && posixgroup".to_string(),
            ));
        }

        let name = $value.get_ava_single_string("name").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: name".to_string())
        })?;

        let spn = $value
            .get_ava_single("spn")
            .map(|v| v.to_proto_string_clone())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: spn".to_string())
            })?;

        let uuid = *$value.get_uuid();

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
    ($au:expr, $value:expr, $qs:expr) => {{
        // First synthesise the self-group from the account.
        // We have already checked these, but paranoia is better than
        // complacency.
        if !$value.attribute_value_pres("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !$value.attribute_value_pres("class", &PVCLASS_POSIXACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = $value.get_ava_single_string("name").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: name".to_string())
        })?;

        let spn = $value
            .get_ava_single("spn")
            .map(|v| v.to_proto_string_clone())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: spn".to_string())
            })?;

        let uuid = *$value.get_uuid();

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

        match $value.get_ava_reference_uuid("memberof") {
            Some(l) => {
                let f = filter!(f_and!([
                    f_eq("class", PartialValue::new_class("posixgroup")),
                    f_eq("class", PartialValue::new_class("group")),
                    f_or(
                        l.into_iter()
                            .map(|u| f_eq("uuid", PartialValue::new_uuidr(u)))
                            .collect()
                    )
                ]));
                let ges: Vec<_> = $qs.internal_search($au, f)?;
                let groups: Result<Vec<_>, _> = iter::once(Ok(upg))
                    .chain(ges.into_iter().map(UnixGroup::try_from_entry))
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
        au: &mut AuditScope,
        value: &Entry<EntryValid, EntryCommitted>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(au, value, qs)
    }

    pub fn try_from_account_entry_ro(
        au: &mut AuditScope,
        value: &Entry<EntryValid, EntryCommitted>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(au, value, qs)
    }

    pub fn try_from_account_entry_red_ro(
        au: &mut AuditScope,
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        try_from_account_group_e!(au, value, qs)
    }

    pub fn try_from_entry_reduced(
        value: Entry<EntryReduced, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_group_e!(value)
    }

    pub fn try_from_entry(
        value: Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        try_from_group_e!(value)
    }

    pub(crate) fn to_unixgrouptoken(&self) -> Result<UnixGroupToken, OperationError> {
        Ok(UnixGroupToken {
            name: self.name.clone(),
            spn: self.spn.clone(),
            uuid: self.uuid.to_hyphenated_ref().to_string(),
            gidnumber: self.gidnumber,
        })
    }
}

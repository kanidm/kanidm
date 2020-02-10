use uuid::Uuid;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntryValid};
use crate::server::{QueryServerReadTransaction, QueryServerTransaction};
use crate::value::PartialValue;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{UnixGroupToken, UnixUserToken};

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
}

lazy_static! {
    static ref PVCLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
    static ref PVCLASS_POSIXACCOUNT: PartialValue = PartialValue::new_class("posixaccount");
    static ref PVCLASS_GROUP: PartialValue = PartialValue::new_class("group");
    static ref PVCLASS_POSIXGROUP: PartialValue = PartialValue::new_class("posixgroup");
}

impl UnixUserAccount {
    pub(crate) fn try_from_entry_reduced(
        au: &mut AuditScope,
        value: Entry<EntryReduced, EntryCommitted>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !value.attribute_value_pres("class", &PVCLASS_POSIXACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = value.get_ava_single_string("name").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: name".to_string())
        })?;

        let spn = value
            .get_ava_single("spn")
            .map(|v| v.to_proto_string_clone())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: spn".to_string())
            })?;

        let uuid = *value.get_uuid();

        let displayname = value.get_ava_single_string("displayname").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: displayname".to_string())
        })?;

        let gidnumber = value.get_ava_single_uint32("gidnumber").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: gidnumber".to_string())
        })?;

        let shell = value.get_ava_single_string("loginshell");

        let sshkeys = value.get_ava_ssh_pubkeys("ssh_publickey");

        let groups = UnixGroup::try_from_account_entry_red_ro(au, &value, qs)?;

        Ok(UnixUserAccount {
            name,
            spn,
            uuid,
            displayname,
            gidnumber,
            shell,
            sshkeys,
            groups,
        })
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
}

#[derive(Debug, Clone)]
pub(crate) struct UnixGroup {
    pub name: String,
    pub spn: String,
    pub gidnumber: u32,
    pub uuid: Uuid,
}

impl UnixGroup {
    pub fn try_from_account_entry_red_ro(
        au: &mut AuditScope,
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Vec<Self>, OperationError> {
        match value.get_ava_reference_uuid("memberof") {
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
                let ges: Vec<_> = try_audit!(au, qs.internal_search(au, f));
                let groups: Result<Vec<_>, _> =
                    ges.into_iter().map(UnixGroup::try_from_entry).collect();
                groups
            }
            None => {
                // No memberof, no groups!
                Ok(Vec::new())
            }
        }
    }

    pub fn try_from_entry(
        value: Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", &PVCLASS_GROUP) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        if !value.attribute_value_pres("class", &PVCLASS_POSIXGROUP) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: posixaccount".to_string(),
            ));
        }

        let name = value.get_ava_single_string("name").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: name".to_string())
        })?;

        let spn = value
            .get_ava_single("spn")
            .map(|v| v.to_proto_string_clone())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: spn".to_string())
            })?;

        let uuid = *value.get_uuid();

        let gidnumber = value.get_ava_single_uint32("gidnumber").ok_or_else(|| {
            OperationError::InvalidAccountState("Missing attribute: gidnumber".to_string())
        })?;

        Ok(UnixGroup {
            name,
            spn,
            gidnumber,
            uuid,
        })
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

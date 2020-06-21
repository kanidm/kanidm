use crate::idm::group::Group;
use uuid::Uuid;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryReduced};
use crate::server::QueryServerReadTransaction;
use crate::value::PartialValue;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::RadiusAuthToken;

lazy_static! {
    static ref PVCLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
}

#[derive(Debug, Clone)]
pub(crate) struct RadiusAccount {
    pub name: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub groups: Vec<Group>,
    pub radius_secret: String,
}

impl RadiusAccount {
    pub(crate) fn try_from_entry_reduced(
        au: &mut AuditScope,
        value: Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        let radius_secret = value
            .get_ava_single_radiuscred("radius_secret")
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: radius_secret".to_string())
            })?
            .to_string();

        let name = value
            .get_ava_single_str("name")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: name".to_string())
            })?;

        let uuid = *value.get_uuid();

        let displayname = value
            .get_ava_single_str("displayname")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState("Missing attribute: displayname".to_string())
            })?;

        let groups = Group::try_from_account_entry_red_ro(au, &value, qs)?;

        Ok(RadiusAccount {
            name,
            uuid,
            displayname,
            groups,
            radius_secret,
        })
    }

    pub(crate) fn to_radiusauthtoken(&self) -> Result<RadiusAuthToken, OperationError> {
        // If we don't have access/permission, then just error instead.
        // This includes if we don't have the secret.
        Ok(RadiusAuthToken {
            name: self.name.clone(),
            displayname: self.displayname.clone(),
            uuid: self.uuid.to_hyphenated_ref().to_string(),
            secret: self.radius_secret.clone(),
            groups: self.groups.iter().map(|g| g.to_proto()).collect(),
        })
    }
}

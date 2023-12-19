use std::time::Duration;

use kanidm_proto::v1::{OperationError, RadiusAuthToken};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entry::{Entry, EntryCommitted, EntryReduced};
use crate::idm::group::Group;
use crate::prelude::*;

#[derive(Debug, Clone)]
pub(crate) struct RadiusAccount {
    pub name: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub groups: Vec<Group>,
    pub radius_secret: String,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
}

impl RadiusAccount {
    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account".to_string(),
            ));
        }

        let radius_secret = value
            .get_ava_single_secret(Attribute::RadiusSecret)
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::RadiusSecret
                ))
            })?
            .to_string();

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let uuid = value.get_uuid();

        let displayname = value
            .get_ava_single_utf8(Attribute::DisplayName)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::DisplayName
                ))
            })?;

        let groups = Group::try_from_account_entry_reduced(value, qs)?;

        let valid_from = value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let expire = value.get_ava_single_datetime(Attribute::AccountExpire);

        Ok(RadiusAccount {
            name,
            displayname,
            uuid,
            groups,
            radius_secret,
            valid_from,
            expire,
        })
    }

    fn is_within_valid_time(&self, ct: Duration) -> bool {
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

    pub(crate) fn to_radiusauthtoken(
        &self,
        ct: Duration,
    ) -> Result<RadiusAuthToken, OperationError> {
        if !self.is_within_valid_time(ct) {
            return Err(OperationError::InvalidAccountState(
                "Account Expired".to_string(),
            ));
        }

        // If we don't have access/permission, then just error instead.
        // This includes if we don't have the secret.
        Ok(RadiusAuthToken {
            name: self.name.clone(),
            displayname: self.displayname.clone(),
            uuid: self.uuid.as_hyphenated().to_string(),
            secret: self.radius_secret.clone(),
            groups: self.groups.iter().map(|g| g.to_proto()).collect(),
        })
    }
}

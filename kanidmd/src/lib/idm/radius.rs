use uuid::Uuid;
use crate::idm::group::Group;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryReduced};
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{RadiusAuthToken};
use crate::server::{QueryServerReadTransaction};


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
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let _groups = Group::try_from_account_entry_red_ro(au, &value, qs)?;
        unimplemented!();
    }

    pub(crate) fn to_radiusauthtoken(
        &self
    ) -> Result<RadiusAuthToken, OperationError> {
        // If we don't have access/permission, then just error instead.
        // This includes if we don't have the secret.
        unimplemented!();
    }
}


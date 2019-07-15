use crate::entry::{Entry, EntryCommitted, EntryValid};
use crate::error::OperationError;

use crate::proto::v1::UserAuthToken;

use crate::idm::claim::Claim;
use crate::idm::group::Group;

use std::convert::TryFrom;

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
    pub uuid: String,
    pub groups: Vec<Group>,
    // creds (various types)
    // groups?
    // claims?
    // account expiry?
}

impl TryFrom<Entry<EntryValid, EntryCommitted>> for Account {
    type Error = OperationError;

    fn try_from(value: Entry<EntryValid, EntryCommitted>) -> Result<Self, Self::Error> {
        // Check the classes
        if !value.attribute_value_pres("class", "account") {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account",
            ));
        }

        // Now extract our needed attributes
        let name = value
            .get_ava_single("name")
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: name",
            ))?
            .clone();

        let displayname = value
            .get_ava_single("displayname")
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: displayname",
            ))?
            .clone();

        // TODO: Resolve groups!!!!
        let groups = Vec::new();

        let uuid = value.get_uuid().clone();

        Ok(Account {
            uuid: uuid,
            name: name,
            displayname: displayname,
            groups: groups,
        })
    }
}

impl Account {
    // Could this actually take a claims list and application instead?
    pub(crate) fn to_userauthtoken(&self, claims: Vec<Claim>) -> Option<UserAuthToken> {
        // This could consume self?
        // The cred handler provided is what authenticated this user, so we can use it to
        // process what the proper claims should be.

        // Get the claims from the cred_h

        Some(UserAuthToken {
            name: self.name.clone(),
            displayname: self.name.clone(),
            uuid: self.uuid.clone(),
            application: None,
            groups: self.groups.iter().map(|g| g.into_proto()).collect(),
            claims: claims.iter().map(|c| c.into_proto()).collect(),
        })
    }
}

// Need to also add a "to UserAuthToken" ...

// Need tests for conversion and the cred validations

#[cfg(test)]
mod tests {
    use crate::constants::JSON_ANONYMOUS_V1;
    use crate::entry::{Entry, EntryNew, EntryValid};
    use crate::idm::account::Account;
    use crate::proto::v1::AuthAllowed;

    use std::convert::TryFrom;

    #[test]
    fn test_idm_account_from_anonymous() {
        let anon_e: Entry<EntryValid, EntryNew> =
            serde_json::from_str(JSON_ANONYMOUS_V1).expect("Json deserialise failure!");
        let anon_e = unsafe { anon_e.to_valid_committed() };

        let anon_account = Account::try_from(anon_e).expect("Must not fail");
        println!("{:?}", anon_account);
        // I think that's it? we may want to check anonymous mech ...
    }

    #[test]
    fn test_idm_account_from_real() {
        // For now, nothing, but later, we'll test different types of cred
        // passing.
    }
}

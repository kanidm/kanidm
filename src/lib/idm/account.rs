use crate::entry::{Entry, EntryCommitted, EntryValid};
use crate::error::OperationError;

use crate::proto::v1::UserAuthToken;

use crate::credential::Credential;
use crate::idm::claim::Claim;
use crate::idm::group::Group;
use crate::value::PartialValue;

use uuid::Uuid;

lazy_static! {
    static ref PVCLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
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
    // primary: Credential
    // app_creds: Vec<Credential>
    // account expiry? (as opposed to cred expiry)
}

impl Account {
    // TODO #71: We need a second try_from that doesn't do group resolve for test cases I think.
    pub(crate) fn try_from_entry(
        value: Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Check the classes
        if !value.attribute_value_pres("class", &PVCLASS_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: account",
            ));
        }

        // Now extract our needed attributes
        let name =
            value
                .get_ava_single_string("name")
                .ok_or(OperationError::InvalidAccountState(
                    "Missing attribute: name",
                ))?;

        let displayname = value.get_ava_single_string("displayname").ok_or(
            OperationError::InvalidAccountState("Missing attribute: displayname"),
        )?;

        let primary = value.get_ava_single_credential("primary_credential")
            .map(|v| v.clone());

        // TODO #71: Resolve groups!!!!
        let groups = Vec::new();

        let uuid = value.get_uuid().clone();

        Ok(Account {
            uuid: uuid,
            name: name,
            displayname: displayname,
            groups: groups,
            primary: primary,
        })
    }

    // Could this actually take a claims list and application instead?
    pub(crate) fn to_userauthtoken(&self, claims: Vec<Claim>) -> Option<UserAuthToken> {
        // This could consume self?
        // The cred handler provided is what authenticated this user, so we can use it to
        // process what the proper claims should be.

        // Get the claims from the cred_h

        Some(UserAuthToken {
            name: self.name.clone(),
            displayname: self.name.clone(),
            uuid: self.uuid.to_hyphenated_ref().to_string(),
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

    #[test]
    fn test_idm_account_from_anonymous() {
        let anon_e: Entry<EntryValid, EntryNew> =
            unsafe { Entry::unsafe_from_entry_str(JSON_ANONYMOUS_V1).to_valid_new() };
        let anon_e = unsafe { anon_e.to_valid_committed() };

        let anon_account = Account::try_from_entry(anon_e).expect("Must not fail");
        println!("{:?}", anon_account);
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

use crate::entry::{Entry, EntryValid, EntryCommitted};
use crate::error::OperationError;
use crate::constants::UUID_ANONYMOUS;

use crate::proto::v1::AuthAllowed;

use std::convert::TryFrom;
use uuid::Uuid;


#[derive(Debug, Clone)]
pub(crate) struct Account {
    // Later these could be &str if we cache entry here too ...
    // They can't because if we mod the entry, we'll lose the ref.
    //
    // We do need to decide if we'll cache the entry, or if we just "work out"
    // what the ops should be based on the values we cache here ... That's a future
    // william problem I think :)
    uuid: String,
    name: String,
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
            return Err(OperationError::InvalidAccountState("Missing class: account"))
        }

        // Now extract our needed attributes
        let name = value.get_ava_single("name")
            .ok_or(OperationError::InvalidAccountState("Missing attribute: name"))?
            .clone();

        let uuid = value.get_uuid().clone();

        Ok(Account {
            uuid: uuid,
            name: name,
        })
    }
}

impl Account {
    pub fn validate_cred(&mut self) -> () {
    }

    fn auth_mech_anonymous(&self) -> Option<AuthAllowed> {
        if self.uuid == UUID_ANONYMOUS {
            Some(AuthAllowed::Anonymous)
        } else {
            None
        }
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        let mut valid = Vec::new();

        match self.auth_mech_anonymous() {
            Some(a) => valid.push(a),
            None => {}
        }

        valid
    }
}

// Need to also add a "to UserAuthToken" ...

// Need tests for conversion and the cred validations

#[cfg(test)]
mod tests {
    use crate::constants::JSON_ANONYMOUS_V1;
    use crate::idm::account::Account;
    use crate::entry::{Entry, EntryValid, EntryNew};
    use crate::proto::v1::AuthAllowed;

    use std::convert::TryFrom;



    #[test]
    fn test_idm_account_from_anonymous() {
        let anon_e: Entry<EntryValid, EntryNew> = serde_json::from_str(JSON_ANONYMOUS_V1).expect("Json deserialise failure!");
        let anon_e = unsafe { anon_e.to_valid_committed() };

        let anon_account = Account::try_from(anon_e).expect("Must not fail");
        println!("{:?}", anon_account);
        // I think that's it? we may want to check anonymous mech ...
    }

    #[test]
    fn test_idm_account_anonymous_auth_mech() {
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);

        let auth_mechs = anon_account.valid_auth_mechs();

        assert!(true == auth_mechs.iter().fold(false, |acc, x| {
            match x {
                AuthAllowed::Anonymous => true,
                _ => acc,
            }
        }));

    }

    #[test]
    fn test_idm_account_from_real() {
        // For now, nothing, but later, we'll test different types of cred
        // passing.
    }
}

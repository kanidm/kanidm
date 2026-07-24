
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use std::time::Duration;

pub struct AccountSignupRequestEvent {
    // Who initiated this?
    pub ident: Identity,
}

impl IdmServerProxyWriteTransaction<'_> {
    pub fn account_signup_request(
        &mut self,
        asre: AccountSignupRequestEvent,
        ct: Duration,
    ) -> Result<(), OperationError> {


        
        
    }
}


#[cfg(test)]
mod tests {
    
}



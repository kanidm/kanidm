use crate::be::Backend;
use crate::constants::UUID_ANONYMOUS;
use crate::error::OperationError;
use crate::event::SearchEvent;
use crate::proto::v1::UserAuthToken;
use crate::schema::Schema;
use crate::server::{QueryServer, QueryServerTransaction};
use concread::cowcell::{CowCell, CowCellReadTxn, CowCellWriteTxn};

use std::collections::BTreeMap;
use std::sync::Arc;

pub struct IdmServer {
    // Need an auth-session table to save in progress authentications
    // sessions:
    sessions: CowCell<BTreeMap<String, ()>>,
    // Need a reference to the query server.
    qs: QueryServer,
}

pub struct IdmServerWriteTransaction<'a> {
    // Contains methods that require writes, but in the context of writing to
    // the idm in memory structures (maybe the query server too). This is
    // things like authentication
    sessions: CowCellWriteTxn<'a, BTreeMap<String, ()>>,
    qs: &'a QueryServer,
}

pub struct IdmServerReadTransaction<'a> {
    // This contains read-only methods, like getting users, groups
    // and other structured content.
    qs: &'a QueryServer,
}

impl IdmServer {
    pub fn new(be: Backend, schema: Arc<Schema>) -> IdmServer {
        IdmServer {
            sessions: CowCell::new(BTreeMap::new()),
            qs: QueryServer::new(be, schema),
        }
    }

    pub fn write(&self) -> IdmServerWriteTransaction {
        IdmServerWriteTransaction {
            sessions: self.sessions.write(),
            qs: &self.qs,
        }
    }

    pub fn read(&self) -> IdmServerReadTransaction {
        IdmServerReadTransaction { qs: &self.qs }
    }
}

impl<'a> IdmServerWriteTransaction<'a> {
    // TODO: This should be something else, not the proto token!
    pub fn auth(&self) -> Result<UserAuthToken, OperationError> {
        // Start a read
        //
        // Actually we may not need this - at the time we issue the auth-init
        // we could generate the uat, the nonce and cache hashes in memory,
        // then this can just be fully without a txn.
        //
        // We do need a txn so that we can process/search and claims
        // or related based on the quality of the provided auth steps
        //
        // We *DO NOT* need a write though, because I think that lock outs
        // and rate limits are *per server* and *in memory* only.
        let qs_read = self.qs.read();

        // Check anything needed? Get the current auth-session-id from request
        // because it associates to the nonce's etc which were all cached.

        // FIXME!!! This hack is to get anonymous, then we just use them
        // to generate the UAT.
        let filter_anon = filter!(f_eq("uuid", UUID_ANONYMOUS))
            .validate(qs_read.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;

        let se_anon = SearchEvent::new_internal(filter_anon);

        // Get the first / single entry we expect here ....
        // let entry = ...;
        unimplemented!();

        // If everything is good, finally issue the token. Oui oui!
        // Also send an async message to self to log the auth as provided.
        // Alternately, open a write, and commit the needed security metadata here
        // now rather than async (probably better for lock-outs etc)
        //
        // TODO: Async message the account owner about the login?

        //
        // The lockouts could also be an in-memory concept too?

        /*
        match anon_entry.to_userauthtoken() {
            Some(uat) => Ok(uat),
            None => Err(OperationError::InvalidState),
        }
        */

        // Else, non non non!
    }

    pub fn commit(self) -> Result<(), OperationError> {
        unimplemented!();
    }
}

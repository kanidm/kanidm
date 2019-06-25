

pub struct IdmServer {
    // Need an auth-session table to save in progress authentications
    // sessions: 

    // Need a reference to the query server.
}

pub struct IdmServerWriteTransaction {
    // Contains methods that require writes, but in the context of writing to
    // the idm in memory structures (maybe the query server too). This is
    // things like authentication
}

pub struct IdmServerReadTransaction {
    // This contains read-only methods, like getting users, groups
    // and other structured content.

}

impl IdmServer {
    pub fn new() -> IdmServer {
        IdmServer {
        }
    }

    pub fn read() -> IdmServerWriteTransaction {
        unimplemented!()
    }

    pub fn write() -> IdmServerReadTransaction {
        unimplemented!()
    }
}

impl IdmServerWriteTransaction {
    pub fn auth() -> () {
    }
}



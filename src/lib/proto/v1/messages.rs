use crate::error::OperationError;
use actix::prelude::*;
use uuid::Uuid;

use crate::proto::v1::{UserAuthToken, WhoamiRequest, WhoamiResponse, AuthRequest, AuthResponse};

// These are used when the request (IE Get) has no intrising request
// type. Additionally, they are used in some requests where we need
// to supplement extra server state (IE userauthtokens) to a request.
//
// Generally we don't need to have the responses here because they are
// part of the protocol.

pub struct WhoamiMessage {
    pub uat: Option<UserAuthToken>,
}

impl WhoamiMessage {
    pub fn new(uat: Option<UserAuthToken>) -> Self {
        WhoamiMessage { uat: uat }
    }
}

impl Message for WhoamiMessage {
    type Result = Result<WhoamiResponse, OperationError>;
}

#[derive(Debug)]
pub struct AuthMessage {
    pub sessionid: Option<Uuid>,
    pub req: AuthRequest,
}

impl AuthMessage {
    pub fn new(req: AuthRequest, sessionid: Option<Uuid>) -> Self {
        AuthMessage {
            sessionid: sessionid,
            req: req,
        }
    }
}

impl Message for AuthMessage {
    type Result = Result<AuthResponse, OperationError>;
}


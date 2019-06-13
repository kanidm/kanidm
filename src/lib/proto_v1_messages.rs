use crate::error::OperationError;
use actix::prelude::*;

use crate::proto_v1::{UserAuthToken, WhoamiRequest, WhoamiResponse};

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

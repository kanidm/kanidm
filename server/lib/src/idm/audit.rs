use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    AuthenticationDenied { spn: String },
}

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema, Eq, PartialEq)]
pub enum OutboundMessage {
    TestMessageV1 {
        display_name: String,
    },
    CredentialResetV1 {
        display_name: String,
        intent_id: String,
        #[serde(with = "time::serde::timestamp")]
        expiry_time: OffsetDateTime,
    },
}

impl OutboundMessage {
    pub fn display_type(&self) -> &'static str {
        match self {
            Self::TestMessageV1 { .. } => "test_message_v1",
            Self::CredentialResetV1 { .. } => "credential_reset_v1",
        }
    }
}

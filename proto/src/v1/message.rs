use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema, Eq, PartialEq)]
pub enum OutboundMessage {
    TestMessageV1 { display_name: String },
}

impl OutboundMessage {
    pub fn display_type(&self) -> &'static str {
        match self {
            Self::TestMessageV1 { .. } => "test_message_v1",
        }
    }
}

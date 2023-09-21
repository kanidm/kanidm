use crate::v1::ApiTokenPurpose;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
/// This is a description of a linked or connected application for a user. This is
/// used in the UI to render applications on the dashboard for a user to access.
pub enum AppLink {
    Oauth2 {
        name: String,
        display_name: String,
        redirect_url: Url,
        // Where the icon can be retrieved from.
        icon: Option<Url>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ScimSyncToken {
    // uuid of the token?
    pub token_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

// State machine states and transitions for the identity verification system feature!
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IdentifyUserRequest {
    Start,
    SubmitCode { other_totp: u32 },
    DisplayCode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IdentifyUserResponse {
    IdentityVerificationUnavailable,
    IdentityVerificationAvailable,
    ProvideCode { step: u32, totp: u32 },
    WaitForCode,
    Success,
    CodeFailure,
    InvalidUserId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum ImageType {
    Png = 0,
    Jpg = 1,
    Gif = 2,
    Svg = 3,
    Webp = 4,
}

impl From<&str> for ImageType {
    fn from(value: &str) -> Self {
        #[allow(clippy::panic)]
        match value {
            "png" => Self::Png,
            "jpg" => Self::Jpg,
            "gif" => Self::Gif,
            "svg" => Self::Svg,
            "webp" => Self::Webp,
            _ => panic!("Invalid image type!"),
        }
    }
}

impl ImageType {
    pub fn try_from_content_type(content_type: &str) -> Result<Self, String> {
        let content_type = content_type.to_lowercase();
        match content_type.as_str() {
            "image/jpeg" => Ok(ImageType::Jpg),
            "image/png" => Ok(ImageType::Png),
            "image/gif" => Ok(ImageType::Gif),
            "image/webp" => Ok(ImageType::Webp),
            _ => Err(format!("Invalid content type: {}", content_type)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, PartialOrd, Ord)]
pub struct ImageValue {
    pub filename: String,
    pub filetype: ImageType,
    pub contents: Vec<u8>,
}

impl TryFrom<&str> for ImageValue {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, String> {
        serde_json::from_str(s)
            .map_err(|e| format!("Failed to decode ImageValue from {} - {:?}", s, e))
    }
}

impl core::hash::Hash for ImageValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.filename.hash(state);
        self.filetype.hash(state);
        self.contents.hash(state);
    }
}

impl ImageValue {
    pub fn new(filename: String, filetype: ImageType, contents: Vec<u8>) -> Self {
        Self {
            filename,
            filetype,
            contents,
        }
    }
}

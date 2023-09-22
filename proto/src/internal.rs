use crate::constants::{
    CONTENT_TYPE_GIF, CONTENT_TYPE_JPG, CONTENT_TYPE_PNG, CONTENT_TYPE_SVG, CONTENT_TYPE_WEBP,
};
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
    Png,
    Jpg,
    Gif,
    Svg,
    Webp,
}

// impl From<&ImageType> for u8 {
//     fn from(input: &ImageType) -> u8 {
//         match input {
//             ImageType::Png => 0,
//             ImageType::Jpg => 1,
//             ImageType::Gif => 2,
//             ImageType::Svg => 3,
//             ImageType::Webp => 4,
//         }
//     }
// }

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
            CONTENT_TYPE_JPG => Ok(ImageType::Jpg),
            CONTENT_TYPE_PNG => Ok(ImageType::Png),
            CONTENT_TYPE_GIF => Ok(ImageType::Gif),
            CONTENT_TYPE_WEBP => Ok(ImageType::Webp),
            CONTENT_TYPE_SVG => Ok(ImageType::Svg),
            _ => Err(format!("Invalid content type: {}", content_type)),
        }
    }

    pub fn as_content_type_str(&self) -> &'static str {
        match &self {
            ImageType::Jpg => CONTENT_TYPE_JPG,
            ImageType::Png => CONTENT_TYPE_PNG,
            ImageType::Gif => CONTENT_TYPE_GIF,
            ImageType::Webp => CONTENT_TYPE_WEBP,
            ImageType::Svg => CONTENT_TYPE_SVG,
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

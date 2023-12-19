use crate::constants::{
    CONTENT_TYPE_GIF, CONTENT_TYPE_JPG, CONTENT_TYPE_PNG, CONTENT_TYPE_SVG, CONTENT_TYPE_WEBP,
};
use crate::v1::ApiTokenPurpose;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;
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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ToSchema)]
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

impl TryFrom<&str> for ImageType {
    type Error = &'static str;
    /// ```
    /// use kanidm_proto::internal::ImageType;
    /// assert_eq!(ImageType::try_from("png").unwrap(), ImageType::Png);
    /// assert!(ImageType::try_from("krabs").is_err());
    /// ```
    fn try_from(value: &str) -> Result<Self, &'static str> {
        #[allow(clippy::panic)]
        match value {
            "png" => Ok(Self::Png),
            "jpg" => Ok(Self::Jpg),
            "jpeg" => Ok(Self::Jpg), // ugh I hate this
            "gif" => Ok(Self::Gif),
            "svg" => Ok(Self::Svg),
            "webp" => Ok(Self::Webp),
            _ => Err("Invalid image type!"),
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, PartialOrd, Ord, Hash)]
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

impl ImageValue {
    pub fn new(filename: String, filetype: ImageType, contents: Vec<u8>) -> Self {
        Self {
            filename,
            filetype,
            contents,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Deserialize, Default, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
/// Filesystem type object, used for tuning database parameters.
pub enum FsType {
    Zfs = 65536,
    #[default]
    #[serde(other)]
    /// The default setting, if not set to "zfs"
    Generic = 4096,
}

impl FsType {
    pub fn checkpoint_pages(&self) -> u32 {
        match self {
            FsType::Generic => 2048,
            FsType::Zfs => 256,
        }
    }
}

impl From<String> for FsType {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

impl From<&str> for FsType {
    fn from(s: &str) -> Self {
        match s {
            "zfs" => FsType::Zfs,
            _ => FsType::Generic,
        }
    }
}

#[test]
fn test_fstype_deser() {
    assert_eq!(FsType::from("zfs"), FsType::Zfs);
    assert_eq!(FsType::from("generic"), FsType::Generic);
    assert_eq!(FsType::from(" "), FsType::Generic);
    assert_eq!(FsType::from("crab🦀"), FsType::Generic);
}

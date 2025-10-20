//! Kanidm internal elements
//!
//! Items defined in this module *may* change between releases without notice.

use crate::constants::{
    CONTENT_TYPE_GIF, CONTENT_TYPE_JPG, CONTENT_TYPE_PNG, CONTENT_TYPE_SVG, CONTENT_TYPE_WEBP,
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

use num_enum::TryFromPrimitive;

mod credupdate;
mod error;
mod raw;
mod token;

pub use self::credupdate::*;
pub use self::error::*;
pub use self::raw::*;
pub use self::token::*;

pub const COOKIE_AUTH_SESSION_ID: &str = "auth-session-id";
pub const COOKIE_BEARER_TOKEN: &str = "bearer";
pub const COOKIE_CU_SESSION_TOKEN: &str = "cu-session-token";
pub const COOKIE_USERNAME: &str = "username";
pub const COOKIE_OAUTH2_REQ: &str = "o2-authreq";

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
/// This is a description of a linked or connected application for a user. This is
/// used in the UI to render applications on the dashboard for a user to access.
pub enum AppLink {
    Oauth2 {
        name: String,
        display_name: String,
        redirect_url: Url,
        // Whether this oauth2 resource has an image.
        has_image: bool,
    },
}

#[derive(
    Debug, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, ToSchema,
)]
#[serde(rename_all = "lowercase")]
#[derive(TryFromPrimitive)]
#[repr(u16)]
pub enum UiHint {
    ExperimentalFeatures = 0,
    PosixAccount = 1,
    CredentialUpdate = 2,
    SynchronisedAccount = 3,
}

impl fmt::Display for UiHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl AsRef<str> for UiHint {
    fn as_ref(&self) -> &str {
        match self {
            UiHint::PosixAccount => "PosixAccount",
            UiHint::CredentialUpdate => "CredentialUpdate",
            UiHint::ExperimentalFeatures => "ExperimentalFeatures",
            UiHint::SynchronisedAccount => "SynchronisedAccount",
        }
    }
}

impl FromStr for UiHint {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CredentialUpdate" => Ok(UiHint::CredentialUpdate),
            "PosixAccount" => Ok(UiHint::PosixAccount),
            "ExperimentalFeatures" => Ok(UiHint::ExperimentalFeatures),
            "SynchronisedAccount" => Ok(UiHint::SynchronisedAccount),
            _ => Err(()),
        }
    }
}

// State machine states and transitions for the identity verification system feature!
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ToSchema)]
pub enum IdentifyUserRequest {
    Start,
    SubmitCode { other_totp: u32 },
    DisplayCode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, ToSchema)]
pub enum IdentifyUserResponse {
    IdentityVerificationUnavailable,
    IdentityVerificationAvailable,
    ProvideCode { step: u32, totp: u32 },
    WaitForCode,
    Success,
    CodeFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Ord, PartialOrd, ValueEnum)]
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
            _ => Err(format!("Invalid content type: {content_type}")),
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
        serde_json::from_str(s).map_err(|e| format!("Failed to decode ImageValue from {s} - {e:?}"))
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

impl TryFrom<&str> for FsType {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "zfs" => Ok(FsType::Zfs),
            "generic" => Ok(FsType::Generic),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, ToSchema)]
pub enum Oauth2ClaimMapJoin {
    #[serde(rename = "csv")]
    Csv,
    #[serde(rename = "ssv")]
    Ssv,
    #[serde(rename = "array")]
    Array,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainInfo {
    pub name: String,
    pub displayname: String,
    pub uuid: Uuid,
    pub level: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainUpgradeCheckReport {
    pub name: String,
    pub uuid: Uuid,
    pub current_level: u32,
    pub upgrade_level: u32,
    pub report_items: Vec<DomainUpgradeCheckItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DomainUpgradeCheckStatus {
    Pass6To7Gidnumber,
    Fail6To7Gidnumber,

    Pass7To8SecurityKeys,
    Fail7To8SecurityKeys,

    Pass7To8Oauth2StrictRedirectUri,
    Fail7To8Oauth2StrictRedirectUri,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainUpgradeCheckItem {
    pub from_level: u32,
    pub to_level: u32,
    pub status: DomainUpgradeCheckStatus,
    pub affected_entries: Vec<String>,
}

#[test]
fn test_fstype_deser() {
    assert_eq!(FsType::try_from("zfs"), Ok(FsType::Zfs));
    assert_eq!(FsType::try_from("generic"), Ok(FsType::Generic));
    assert_eq!(FsType::try_from(" "), Err(()));
    assert_eq!(FsType::try_from("crab🦀"), Err(()));
}

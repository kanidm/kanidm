use crate::ScimEntry;
use base64urlsafedata::Base64UrlSafeData;
use std::fmt;
use url::Url;
use uuid::Uuid;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Name {
    // The full name including all middle names and titles
    formatted: Option<String>,
    family_name: Option<String>,
    given_name: Option<String>,
    middle_name: Option<String>,
    honorific_prefix: Option<String>,
    honorific_suffix: Option<String>,
}

/*
// https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.5
//
// https://www.iana.org/assignments/language-subtag-registry/language-subtag-registry
// Same as locale?
#[derive(Serialize, Deserialize, Debug, Clone)]
enum Language {
    en,
}
*/

// https://datatracker.ietf.org/doc/html/rfc5646
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone)]
enum Locale {
    en,
    #[serde(rename = "en-AU")]
    en_AU,
    #[serde(rename = "en-US")]
    en_US,
    de,
    #[serde(rename = "en-DE")]
    de_DE,
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Locale::en => write!(f, "en"),
            Locale::en_AU => write!(f, "en-AU"),
            Locale::en_US => write!(f, "en-US"),
            Locale::de => write!(f, "de"),
            Locale::de_DE => write!(f, "de-DE"),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone)]
enum Timezone {
    #[serde(rename = "Australia/Brisbane")]
    australia_brisbane,
    #[serde(rename = "America/Los_Angeles")]
    america_los_angeles,
}

impl fmt::Display for Timezone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Timezone::australia_brisbane => write!(f, "Australia/Brisbane"),
            Timezone::america_los_angeles => write!(f, "America/Los_Angeles"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MultiValueAttr {
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub primary: Option<bool>,
    pub display: Option<String>,
    #[serde(rename = "$ref")]
    pub ref_: Option<Url>,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Photo {
    #[serde(rename = "type")]
    type_: Option<String>,
    primary: Option<bool>,
    display: Option<String>,
    #[serde(rename = "$ref")]
    ref_: Option<Url>,
    value: Url,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Binary {
    #[serde(rename = "type")]
    type_: Option<String>,
    primary: Option<bool>,
    display: Option<String>,
    #[serde(rename = "$ref")]
    ref_: Option<Url>,
    value: Base64UrlSafeData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Address {
    #[serde(rename = "type")]
    type_: Option<String>,
    primary: Option<bool>,
    formatted: Option<String>,
    street_address: Option<String>,
    locality: Option<String>,
    region: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
}

/*
#[derive(Serialize, Deserialize, Debug, Clone)]
enum Membership {
    Direct,
    Indirect,
}
*/

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Group {
    #[serde(rename = "type")]
    type_: Option<String>,
    #[serde(rename = "$ref")]
    ref_: Url,
    value: Uuid,
    display: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct User {
    #[serde(flatten)]
    entry: ScimEntry,
    // required, must be unique, string.
    user_name: String,
    // Components of the users name.
    name: Option<Name>,
    // required, must be unique, string.
    display_name: Option<String>,
    nick_name: Option<String>,
    profile_url: Option<Url>,
    title: Option<String>,
    user_type: Option<String>,
    preferred_language: Option<Locale>,
    locale: Option<Locale>,
    // https://datatracker.ietf.org/doc/html/rfc6557
    // How can we validate this? https://docs.rs/iana-time-zone/0.1.51/iana_time_zone/fn.get_timezone.html
    timezone: Option<Timezone>,
    active: bool,
    password: Option<String>,
    emails: Vec<MultiValueAttr>,
    phone_numbers: Vec<MultiValueAttr>,
    ims: Vec<MultiValueAttr>,
    photos: Vec<Photo>,
    addresses: Vec<Address>,
    groups: Vec<Group>,
    #[serde(default)]
    entitlements: Vec<MultiValueAttr>,
    #[serde(default)]
    roles: Vec<MultiValueAttr>,
    #[serde(default)]
    x509certificates: Vec<Binary>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RFC7643_USER;

    #[test]
    fn parse_user() {
        let _ = tracing_subscriber::fmt::try_init();

        let u: User = serde_json::from_str(RFC7643_USER).expect("Failed to parse RFC7643_USER");

        tracing::trace!(?u);

        let s = serde_json::to_string_pretty(&u).expect("Failed to serialise RFC7643_USER");
        eprintln!("{}", s);
    }
}

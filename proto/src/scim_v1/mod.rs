//! These represent Kanidm's view of SCIM resources that a client will serialise
//! for transmission, and the server will deserialise to process them. In reverse
//! Kanidm will send responses that a client can then process and use.
//!
//! A challenge of this is that it creates an asymmetry between the client and server
//! as SCIM contains very few strong types. Without awareness of what the client
//! or server intended it's not possible to directly deserialise into a rust
//! strong type on the receiver. To resolve this, this library divides the elements
//! into multiple parts.
//!
//! The [scim_proto] library, which is generic over all scim implementations.
//!
//! The client module, which describes how a client should transmit entries, and
//! how it should parse them when it receives them.
//!
//! The server module, which describes how a server should transmit entries and
//! how it should receive them.

use crate::attribute::{Attribute, SubAttribute};
use serde::{Deserialize, Serialize};
use serde_with::formats::CommaSeparator;
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr, StringWithSeparator};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::ops::Not;
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

pub use self::synch::*;
pub use scim_proto::prelude::*;
pub use serde_json::Value as JsonValue;

pub mod client;
pub mod server;
mod synch;

/// A generic ScimEntry. This retains attribute
/// values in a generic state awaiting processing by schema aware transforms
/// either by the server or the client.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ScimEntryGeneric {
    #[serde(flatten)]
    pub header: ScimEntryHeader,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScimSortOrder {
    #[default]
    Ascending,
    Descending,
}

/// SCIM Query Parameters used during the get of a single entry
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScimEntryGetQuery {
    #[serde_as(as = "Option<StringWithSeparator::<CommaSeparator, Attribute>>")]
    pub attributes: Option<Vec<Attribute>>,
    #[serde(default, skip_serializing_if = "<&bool>::not")]
    pub ext_access_check: bool,

    // Sorting per https://www.rfc-editor.org/rfc/rfc7644#section-3.4.2.3
    #[serde(default)]
    pub sort_by: Option<Attribute>,
    #[serde(default)]
    pub sort_order: Option<ScimSortOrder>,

    // Pagination https://www.rfc-editor.org/rfc/rfc7644#section-3.4.2.4
    pub start_index: Option<NonZeroU64>,
    pub count: Option<NonZeroU64>,

    // Strongly typed filter (rather than generic)
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub filter: Option<ScimFilter>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub enum ScimSchema {
    #[serde(rename = "urn:ietf:params:scim:schemas:kanidm:sync:1:account")]
    SyncAccountV1,
    #[serde(rename = "urn:ietf:params:scim:schemas:kanidm:sync:1:group")]
    SyncV1GroupV1,
    #[serde(rename = "urn:ietf:params:scim:schemas:kanidm:sync:1:person")]
    SyncV1PersonV1,
    #[serde(rename = "urn:ietf:params:scim:schemas:kanidm:sync:1:posixaccount")]
    SyncV1PosixAccountV1,
    #[serde(rename = "urn:ietf:params:scim:schemas:kanidm:sync:1:posixgroup")]
    SyncV1PosixGroupV1,
}

#[serde_as]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScimMail {
    #[serde(default)]
    pub primary: bool,
    pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimSshPublicKey {
    pub label: String,

    #[schema(value_type = String)]
    pub value: SshPublicKey,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimReference {
    pub uuid: Uuid,
    pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, ToSchema)]
pub enum ScimOauth2ClaimMapJoinChar {
    #[serde(rename = ",", alias = "csv")]
    CommaSeparatedValue,
    #[serde(rename = " ", alias = "ssv")]
    SpaceSeparatedValue,
    #[serde(rename = ";", alias = "json_array")]
    JsonArray,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimApplicationPassword {
    pub uuid: Uuid,
    pub label: String,
    pub secret: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimApplicationPasswordCreate {
    pub application_uuid: Uuid,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AttrPath {
    pub a: Attribute,
    pub s: Option<SubAttribute>,
}

impl fmt::Display for AttrPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(subattr) = self.s.as_ref() {
            write!(f, "{}.{}", self.a, subattr)
        } else {
            write!(f, "{}", self.a)
        }
    }
}

impl From<Attribute> for AttrPath {
    fn from(a: Attribute) -> Self {
        Self { a, s: None }
    }
}

impl From<(Attribute, SubAttribute)> for AttrPath {
    fn from((a, s): (Attribute, SubAttribute)) -> Self {
        Self { a, s: Some(s) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ScimFilter {
    Or(Box<ScimFilter>, Box<ScimFilter>),
    And(Box<ScimFilter>, Box<ScimFilter>),
    Not(Box<ScimFilter>),

    Present(AttrPath),
    Equal(AttrPath, JsonValue),
    NotEqual(AttrPath, JsonValue),
    Contains(AttrPath, JsonValue),
    StartsWith(AttrPath, JsonValue),
    EndsWith(AttrPath, JsonValue),
    Greater(AttrPath, JsonValue),
    Less(AttrPath, JsonValue),
    GreaterOrEqual(AttrPath, JsonValue),
    LessOrEqual(AttrPath, JsonValue),

    Complex(Attribute, Box<ScimComplexFilter>),
}

impl fmt::Display for ScimFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal(attrpath, value) => write!(f, "({attrpath} eq {value})"),
            Self::Contains(attrpath, value) => write!(f, "({attrpath} co {value})"),
            Self::Not(expr) => write!(f, "(not ({expr}))"),
            Self::Or(this, that) => write!(f, "({this} or {that})"),
            Self::And(this, that) => write!(f, "({this} and {that})"),
            Self::EndsWith(attrpath, value) => write!(f, "({attrpath} ew {value})"),
            Self::Greater(attrpath, value) => write!(f, "({attrpath} gt {value})"),
            Self::GreaterOrEqual(attrpath, value) => {
                write!(f, "({attrpath} ge {value})")
            }
            Self::Less(attrpath, value) => write!(f, "({attrpath} lt {value})"),
            Self::LessOrEqual(attrpath, value) => write!(f, "({attrpath} le {value})"),
            Self::NotEqual(attrpath, value) => write!(f, "({attrpath} ne {value})"),
            Self::Present(attrpath) => write!(f, "({attrpath} pr)"),
            Self::StartsWith(attrpath, value) => write!(f, "({attrpath} sw {value})"),
            Self::Complex(attrname, expr) => write!(f, "{attrname}[{expr}]"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ScimComplexFilter {
    Or(Box<ScimComplexFilter>, Box<ScimComplexFilter>),
    And(Box<ScimComplexFilter>, Box<ScimComplexFilter>),
    Not(Box<ScimComplexFilter>),

    Present(SubAttribute),
    Equal(SubAttribute, JsonValue),
    NotEqual(SubAttribute, JsonValue),
    Contains(SubAttribute, JsonValue),
    StartsWith(SubAttribute, JsonValue),
    EndsWith(SubAttribute, JsonValue),
    Greater(SubAttribute, JsonValue),
    Less(SubAttribute, JsonValue),
    GreaterOrEqual(SubAttribute, JsonValue),
    LessOrEqual(SubAttribute, JsonValue),
}

impl fmt::Display for ScimComplexFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equal(subattr, value) => write!(f, "({subattr} eq {value})"),
            Self::Contains(subattr, value) => write!(f, "({subattr} co {value})"),
            Self::Not(expr) => write!(f, "(not ({expr}))"),
            Self::Or(this, that) => write!(f, "({this} or {that})"),
            Self::And(this, that) => write!(f, "({this} and {that})"),
            Self::EndsWith(subattr, value) => write!(f, "({subattr} ew {value})"),
            Self::Greater(subattr, value) => write!(f, "({subattr} gt {value})"),
            Self::GreaterOrEqual(subattr, value) => {
                write!(f, "({subattr} ge {value})")
            }
            Self::Less(subattr, value) => write!(f, "({subattr} lt {value})"),
            Self::LessOrEqual(subattr, value) => write!(f, "({subattr} le {value})"),
            Self::NotEqual(subattr, value) => write!(f, "({subattr} ne {value})"),
            Self::Present(subattr) => write!(f, "({subattr} pr)"),
            Self::StartsWith(subattr, value) => write!(f, "({subattr} sw {value})"),
        }
    }
}

peg::parser! {
    grammar scimfilter() for str {

        pub rule parse() -> ScimFilter = precedence!{
            a:(@) separator()+ "or" separator()+ b:@ {
                ScimFilter::Or(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            a:(@) separator()+ "and" separator()+ b:@ {
                ScimFilter::And(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            "not" separator()+ "(" e:parse() ")" {
                ScimFilter::Not(Box::new(e))
            }
            --
            a:attrname()"[" e:parse_complex() "]" {
                ScimFilter::Complex(
                    a,
                    Box::new(e)
                )
            }
            --
            a:attrexp() { a }
            "(" e:parse() ")" { e }
        }

        pub rule parse_complex() -> ScimComplexFilter = precedence!{
            a:(@) separator()+ "or" separator()+ b:@ {
                ScimComplexFilter::Or(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            a:(@) separator()+ "and" separator()+ b:@ {
                ScimComplexFilter::And(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            "not" separator()+ "(" e:parse_complex() ")" {
                ScimComplexFilter::Not(Box::new(e))
            }
            --
            a:complex_attrexp() { a }
            "(" e:parse_complex() ")" { e }
        }

        pub(crate) rule attrexp() -> ScimFilter =
            pres()
            / eq()
            / ne()
            / co()
            / sw()
            / ew()
            / gt()
            / lt()
            / ge()
            / le()

        pub(crate) rule pres() -> ScimFilter =
            a:attrpath() separator()+ "pr" { ScimFilter::Present(a) }

        pub(crate) rule eq() -> ScimFilter =
            a:attrpath() separator()+ "eq" separator()+ v:value() { ScimFilter::Equal(a, v) }

        pub(crate) rule ne() -> ScimFilter =
            a:attrpath() separator()+ "ne" separator()+ v:value() { ScimFilter::NotEqual(a, v) }

        pub(crate) rule co() -> ScimFilter =
            a:attrpath() separator()+ "co" separator()+ v:value() { ScimFilter::Contains(a, v) }

        pub(crate) rule sw() -> ScimFilter =
            a:attrpath() separator()+ "sw" separator()+ v:value() { ScimFilter::StartsWith(a, v) }

        pub(crate) rule ew() -> ScimFilter =
            a:attrpath() separator()+ "ew" separator()+ v:value() { ScimFilter::EndsWith(a, v) }

        pub(crate) rule gt() -> ScimFilter =
            a:attrpath() separator()+ "gt" separator()+ v:value() { ScimFilter::Greater(a, v) }

        pub(crate) rule lt() -> ScimFilter =
            a:attrpath() separator()+ "lt" separator()+ v:value() { ScimFilter::Less(a, v) }

        pub(crate) rule ge() -> ScimFilter =
            a:attrpath() separator()+ "ge" separator()+ v:value() { ScimFilter::GreaterOrEqual(a, v) }

        pub(crate) rule le() -> ScimFilter =
            a:attrpath() separator()+ "le" separator()+ v:value() { ScimFilter::LessOrEqual(a, v) }

        pub(crate) rule complex_attrexp() -> ScimComplexFilter =
            c_pres()
            / c_eq()
            / c_ne()
            / c_co()
            / c_sw()
            / c_ew()
            / c_gt()
            / c_lt()
            / c_ge()
            / c_le()

        pub(crate) rule c_pres() -> ScimComplexFilter =
            a:subattr() separator()+ "pr" { ScimComplexFilter::Present(a) }

        pub(crate) rule c_eq() -> ScimComplexFilter =
            a:subattr() separator()+ "eq" separator()+ v:value() { ScimComplexFilter::Equal(a, v) }

        pub(crate) rule c_ne() -> ScimComplexFilter =
            a:subattr() separator()+ "ne" separator()+ v:value() { ScimComplexFilter::NotEqual(a, v) }

        pub(crate) rule c_co() -> ScimComplexFilter =
            a:subattr() separator()+ "co" separator()+ v:value() { ScimComplexFilter::Contains(a, v) }

        pub(crate) rule c_sw() -> ScimComplexFilter =
            a:subattr() separator()+ "sw" separator()+ v:value() { ScimComplexFilter::StartsWith(a, v) }

        pub(crate) rule c_ew() -> ScimComplexFilter =
            a:subattr() separator()+ "ew" separator()+ v:value() { ScimComplexFilter::EndsWith(a, v) }

        pub(crate) rule c_gt() -> ScimComplexFilter =
            a:subattr() separator()+ "gt" separator()+ v:value() { ScimComplexFilter::Greater(a, v) }

        pub(crate) rule c_lt() -> ScimComplexFilter =
            a:subattr() separator()+ "lt" separator()+ v:value() { ScimComplexFilter::Less(a, v) }

        pub(crate) rule c_ge() -> ScimComplexFilter =
            a:subattr() separator()+ "ge" separator()+ v:value() { ScimComplexFilter::GreaterOrEqual(a, v) }

        pub(crate) rule c_le() -> ScimComplexFilter =
            a:subattr() separator()+ "le" separator()+ v:value() { ScimComplexFilter::LessOrEqual(a, v) }

        rule separator() =
            ['\n' | ' ' | '\t' ]

        rule operator() =
            ['\n' | ' ' | '\t' | '(' | ')' | '[' | ']' ]

        rule value() -> JsonValue =
            quotedvalue() / unquotedvalue()

        rule quotedvalue() -> JsonValue =
            s:$(['"'] ((['\\'][_]) / (!['"'][_]))* ['"']) {? serde_json::from_str(s).map_err(|_| "invalid json value" ) }

        rule unquotedvalue() -> JsonValue =
            s:$((!operator()[_])*) {? serde_json::from_str(s).map_err(|_| "invalid json value" ) }

        pub(crate) rule attrpath() -> AttrPath =
            a:attrname() s:dot_subattr()? { AttrPath { a, s } }

        rule dot_subattr() -> SubAttribute =
            "." s:subattr() { s }

        rule subattr() -> SubAttribute =
            s:attrstring() { SubAttribute::from(s.as_str()) }

        pub(crate) rule attrname() -> Attribute =
            s:attrstring() { Attribute::from(s.as_str()) }

        pub(crate) rule attrstring() -> String =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' ]*) { s.to_string() }
    }
}

impl FromStr for AttrPath {
    type Err = peg::error::ParseError<peg::str::LineCol>;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        scimfilter::attrpath(input)
    }
}

impl FromStr for ScimFilter {
    type Err = peg::error::ParseError<peg::str::LineCol>;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        scimfilter::parse(input)
    }
}

impl FromStr for ScimComplexFilter {
    type Err = peg::error::ParseError<peg::str::LineCol>;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        scimfilter::parse_complex(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scim_rfc_to_generic() {
        // Assert that we can transition from the rfc generic entries to the
        // kanidm types.
    }

    #[test]
    fn scim_kani_to_generic() {
        // Assert that a kanidm strong entry can convert to generic.
    }

    #[test]
    fn scim_kani_to_rfc() {
        // Assert that a kanidm strong entry can convert to rfc.
    }

    #[test]
    fn scim_sync_kani_to_rfc() {
        use super::*;

        // Group
        let group_uuid = uuid::uuid!("2d0a9e7c-cc08-4ca2-8d7f-114f9abcfc8a");

        let group = ScimSyncGroup::builder(
            group_uuid,
            "cn=testgroup".to_string(),
            "testgroup".to_string(),
        )
        .set_description(Some("test desc".to_string()))
        .set_gidnumber(Some(12345))
        .set_members(vec!["member_a".to_string(), "member_a".to_string()].into_iter())
        .build();

        let entry: Result<ScimEntry, _> = group.try_into();

        assert!(entry.is_ok());

        // User
        let user_uuid = uuid::uuid!("cb3de098-33fd-4565-9d80-4f7ed6a664e9");

        let user_sshkey = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBENubZikrb8hu+HeVRdZ0pp/VAk2qv4JDbuJhvD0yNdWDL2e3cBbERiDeNPkWx58Q4rVnxkbV1fa8E2waRtT91wAAAAEc3NoOg== testuser@fidokey";

        let person = ScimSyncPerson::builder(
            user_uuid,
            "cn=testuser".to_string(),
            "testuser".to_string(),
            "Test User".to_string(),
        )
        .set_password_import(Some("new_password".to_string()))
        .set_unix_password_import(Some("new_password".to_string()))
        .set_totp_import(vec![ScimTotp {
            external_id: "Totp".to_string(),
            secret: "abcd".to_string(),
            algo: "SHA3".to_string(),
            step: 60,
            digits: 8,
        }])
        .set_mail(vec![MultiValueAttr {
            primary: Some(true),
            value: "testuser@example.com".to_string(),
            ..Default::default()
        }])
        .set_ssh_publickey(vec![ScimSshPubKey {
            label: "Key McKeyface".to_string(),
            value: user_sshkey.to_string(),
        }])
        .set_login_shell(Some("/bin/false".to_string()))
        .set_account_valid_from(Some("2023-11-28T04:57:55Z".to_string()))
        .set_account_expire(Some("2023-11-28T04:57:55Z".to_string()))
        .set_gidnumber(Some(54321))
        .build();

        let entry: Result<ScimEntry, _> = person.try_into();

        assert!(entry.is_ok());
    }

    #[test]
    fn scim_entry_get_query() {
        use super::*;

        let q = ScimEntryGetQuery {
            attributes: None,
            ..Default::default()
        };

        let txt = serde_urlencoded::to_string(&q).unwrap();

        assert_eq!(txt, "");

        let q = ScimEntryGetQuery {
            attributes: Some(vec![Attribute::Name]),
            ext_access_check: false,
            ..Default::default()
        };

        let txt = serde_urlencoded::to_string(&q).unwrap();
        assert_eq!(txt, "attributes=name");

        let q = ScimEntryGetQuery {
            attributes: Some(vec![Attribute::Name, Attribute::Spn]),
            ext_access_check: true,
            ..Default::default()
        };

        let txt = serde_urlencoded::to_string(&q).unwrap();
        assert_eq!(txt, "attributes=name%2Cspn&extAccessCheck=true");
    }

    #[test]
    fn test_scimfilter_attrname() {
        assert_eq!(scimfilter::attrstring("abcd-_"), Ok("abcd-_".to_string()));
        assert_eq!(scimfilter::attrstring("aB-_CD"), Ok("aB-_CD".to_string()));
        assert_eq!(scimfilter::attrstring("a1-_23"), Ok("a1-_23".to_string()));
        assert!(scimfilter::attrstring("-bcd").is_err());
        assert!(scimfilter::attrstring("_bcd").is_err());
        assert!(scimfilter::attrstring("0bcd").is_err());
    }

    #[test]
    fn test_scimfilter_attrpath() {
        assert_eq!(
            scimfilter::attrpath("mail"),
            Ok(AttrPath {
                a: Attribute::from("mail"),
                s: None
            })
        );

        assert_eq!(
            scimfilter::attrpath("mail.primary"),
            Ok(AttrPath {
                a: Attribute::from("mail"),
                s: Some(SubAttribute::from("primary"))
            })
        );

        assert!(scimfilter::attrname("mail.0").is_err());
        assert!(scimfilter::attrname("mail._").is_err());
        assert!(scimfilter::attrname("mail,0").is_err());
        assert!(scimfilter::attrname(".primary").is_err());
    }

    #[test]
    fn test_scimfilter_pres() {
        assert!(
            scimfilter::parse("mail pr")
                == Ok(ScimFilter::Present(AttrPath {
                    a: Attribute::from("mail"),
                    s: None
                }))
        );
    }

    #[test]
    fn test_scimfilter_eq() {
        assert!(
            scimfilter::parse("mail eq \"dcba\"")
                == Ok(ScimFilter::Equal(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_ne() {
        assert!(
            scimfilter::parse("mail ne \"dcba\"")
                == Ok(ScimFilter::NotEqual(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_co() {
        assert!(
            scimfilter::parse("mail co \"dcba\"")
                == Ok(ScimFilter::Contains(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_sw() {
        assert!(
            scimfilter::parse("mail sw \"dcba\"")
                == Ok(ScimFilter::StartsWith(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_ew() {
        assert!(
            scimfilter::parse("mail ew \"dcba\"")
                == Ok(ScimFilter::EndsWith(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_gt() {
        assert!(
            scimfilter::parse("mail gt \"dcba\"")
                == Ok(ScimFilter::Greater(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_lt() {
        assert!(
            scimfilter::parse("mail lt \"dcba\"")
                == Ok(ScimFilter::Less(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_ge() {
        assert!(
            scimfilter::parse("mail ge \"dcba\"")
                == Ok(ScimFilter::GreaterOrEqual(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_le() {
        assert!(
            scimfilter::parse("mail le \"dcba\"")
                == Ok(ScimFilter::LessOrEqual(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                ))
        );
    }

    #[test]
    fn test_scimfilter_group() {
        let f = scimfilter::parse("(mail eq \"dcba\")");
        eprintln!("{f:?}");
        assert!(
            f == Ok(ScimFilter::Equal(
                AttrPath {
                    a: Attribute::from("mail"),
                    s: None
                },
                JsonValue::String("dcba".to_string())
            ))
        );
    }

    #[test]
    fn test_scimfilter_not() {
        let f = scimfilter::parse("not (mail eq \"dcba\")");
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::Not(Box::new(ScimFilter::Equal(
                AttrPath {
                    a: Attribute::from("mail"),
                    s: None
                },
                JsonValue::String("dcba".to_string())
            ))))
        );
    }

    #[test]
    fn test_scimfilter_and() {
        let f = scimfilter::parse("mail eq \"dcba\" and name ne \"1234\"");
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::And(
                Box::new(ScimFilter::Equal(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                )),
                Box::new(ScimFilter::NotEqual(
                    AttrPath {
                        a: Attribute::from("name"),
                        s: None
                    },
                    JsonValue::String("1234".to_string())
                ))
            ))
        );
    }

    #[test]
    fn test_scimfilter_or() {
        let f = scimfilter::parse("mail eq \"dcba\" or name ne \"1234\"");
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::Or(
                Box::new(ScimFilter::Equal(
                    AttrPath {
                        a: Attribute::from("mail"),
                        s: None
                    },
                    JsonValue::String("dcba".to_string())
                )),
                Box::new(ScimFilter::NotEqual(
                    AttrPath {
                        a: Attribute::from("name"),
                        s: None
                    },
                    JsonValue::String("1234".to_string())
                ))
            ))
        );
    }

    #[test]
    fn test_scimfilter_complex() {
        let f = scimfilter::parse("mail[type eq \"work\"]");
        eprintln!("-- {f:?}");
        assert!(f.is_ok());

        let f = scimfilter::parse("mail[type eq \"work\" and value co \"@example.com\"] or testattr[type eq \"xmpp\" and value co \"@foo.com\"]");
        eprintln!("{f:?}");

        assert_eq!(
            f,
            Ok(ScimFilter::Or(
                Box::new(ScimFilter::Complex(
                    Attribute::from("mail"),
                    Box::new(ScimComplexFilter::And(
                        Box::new(ScimComplexFilter::Equal(
                            SubAttribute::from("type"),
                            JsonValue::String("work".to_string())
                        )),
                        Box::new(ScimComplexFilter::Contains(
                            SubAttribute::from("value"),
                            JsonValue::String("@example.com".to_string())
                        ))
                    ))
                )),
                Box::new(ScimFilter::Complex(
                    Attribute::from("testattr"),
                    Box::new(ScimComplexFilter::And(
                        Box::new(ScimComplexFilter::Equal(
                            SubAttribute::from("type"),
                            JsonValue::String("xmpp".to_string())
                        )),
                        Box::new(ScimComplexFilter::Contains(
                            SubAttribute::from("value"),
                            JsonValue::String("@foo.com".to_string())
                        ))
                    ))
                ))
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_1() {
        let f =
            scimfilter::parse("testattr_a pr or testattr_b pr and testattr_c pr or testattr_d pr");
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::Or(
                Box::new(ScimFilter::Or(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_a"),
                        s: None
                    })),
                    Box::new(ScimFilter::And(
                        Box::new(ScimFilter::Present(AttrPath {
                            a: Attribute::from("testattr_b"),
                            s: None
                        })),
                        Box::new(ScimFilter::Present(AttrPath {
                            a: Attribute::from("testattr_c"),
                            s: None
                        })),
                    )),
                )),
                Box::new(ScimFilter::Present(AttrPath {
                    a: Attribute::from("testattr_d"),
                    s: None
                }))
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_2() {
        let f =
            scimfilter::parse("testattr_a pr and testattr_b pr or testattr_c pr and testattr_d pr");
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::Or(
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_a"),
                        s: None
                    })),
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_b"),
                        s: None
                    })),
                )),
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_c"),
                        s: None
                    })),
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_d"),
                        s: None
                    })),
                )),
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_3() {
        let f = scimfilter::parse(
            "testattr_a pr and (testattr_b pr or testattr_c pr) and testattr_d pr",
        );
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::And(
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_a"),
                        s: None
                    })),
                    Box::new(ScimFilter::Or(
                        Box::new(ScimFilter::Present(AttrPath {
                            a: Attribute::from("testattr_b"),
                            s: None
                        })),
                        Box::new(ScimFilter::Present(AttrPath {
                            a: Attribute::from("testattr_c"),
                            s: None
                        })),
                    )),
                )),
                Box::new(ScimFilter::Present(AttrPath {
                    a: Attribute::from("testattr_d"),
                    s: None
                })),
            ))
        );
    }

    #[test]
    fn test_scimfilter_precedence_4() {
        let f = scimfilter::parse(
            "testattr_a pr and not (testattr_b pr or testattr_c pr) and testattr_d pr",
        );
        eprintln!("{f:?}");

        assert!(
            f == Ok(ScimFilter::And(
                Box::new(ScimFilter::And(
                    Box::new(ScimFilter::Present(AttrPath {
                        a: Attribute::from("testattr_a"),
                        s: None
                    })),
                    Box::new(ScimFilter::Not(Box::new(ScimFilter::Or(
                        Box::new(ScimFilter::Present(AttrPath {
                            a: Attribute::from("testattr_b"),
                            s: None
                        })),
                        Box::new(ScimFilter::Present(AttrPath {
                            a: Attribute::from("testattr_c"),
                            s: None
                        })),
                    )))),
                )),
                Box::new(ScimFilter::Present(AttrPath {
                    a: Attribute::from("testattr_d"),
                    s: None
                })),
            ))
        );
    }

    #[test]
    fn test_scimfilter_quoted_values() {
        assert_eq!(
            scimfilter::parse(r#"description eq "text ( ) [ ] 'single' \"escaped\" \\\\consecutive\\\\ \/slash\b\f\n\r\t\u0041 and or not eq ne co sw ew gt lt ge le pr true false""#),
            Ok(ScimFilter::Equal(
                AttrPath { a: Attribute::from("description"), s: None },
                JsonValue::String("text ( ) [ ] 'single' \"escaped\" \\\\consecutive\\\\ /slash\u{08}\u{0C}\n\r\tA and or not eq ne co sw ew gt lt ge le pr true false".to_string())
            ))
        );
    }

    #[test]
    fn test_scimfilter_quoted_values_incomplete_escape() {
        let result = scimfilter::parse(r#"name eq "test\""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_scimfilter_quoted_values_empty() {
        assert_eq!(
            scimfilter::parse(r#"name eq """#),
            Ok(ScimFilter::Equal(
                AttrPath {
                    a: Attribute::from("name"),
                    s: None
                },
                JsonValue::String("".to_string())
            ))
        );
    }
}

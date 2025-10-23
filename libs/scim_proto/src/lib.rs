#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

pub mod constants;
pub mod filter;
pub mod group;
pub mod user;

pub mod prelude {
    pub use crate::constants::*;
    pub use crate::user::MultiValueAttr;
    pub use crate::{ScimAttr, ScimComplexAttr, ScimEntry, ScimEntryHeader, ScimMeta, ScimValue};
}

#[derive(Deserialize, Serialize, Debug, Clone, ToSchema)]
#[serde(untagged)]
pub enum ScimAttr {
    Bool(bool),
    Integer(i64),
    Decimal(f64),
    String(String),
    // These can't be implicitly decoded because we may not know the intent, but we can *encode* them.
    // That's why "String" is above this because it catches anything during deserialization before
    // this point.
    #[serde(with = "time::serde::rfc3339")]
    DateTime(OffsetDateTime),
    #[schema(value_type = String)]
    Binary(Base64UrlSafeData),
    Reference(Url),
}

impl ScimAttr {
    pub fn parse_as_datetime(&self) -> Option<Self> {
        let s = match self {
            ScimAttr::String(s) => s,
            _ => return None,
        };

        OffsetDateTime::parse(s, &Rfc3339)
            .map(ScimAttr::DateTime)
            .ok()
    }
}

impl From<String> for ScimAttr {
    fn from(s: String) -> Self {
        ScimAttr::String(s)
    }
}

impl From<bool> for ScimAttr {
    fn from(b: bool) -> Self {
        ScimAttr::Bool(b)
    }
}

impl From<u32> for ScimAttr {
    fn from(i: u32) -> Self {
        ScimAttr::Integer(i as i64)
    }
}

impl From<Vec<u8>> for ScimAttr {
    fn from(data: Vec<u8>) -> Self {
        ScimAttr::Binary(data.into())
    }
}

impl From<OffsetDateTime> for ScimAttr {
    fn from(odt: OffsetDateTime) -> Self {
        ScimAttr::DateTime(odt)
    }
}

impl From<ScimAttr> for ScimValue {
    fn from(sa: ScimAttr) -> Self {
        ScimValue::Simple(sa)
    }
}

impl Eq for ScimAttr {}

impl PartialEq for ScimAttr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ScimAttr::String(l), ScimAttr::String(r)) => l == r,
            (ScimAttr::Bool(l), ScimAttr::Bool(r)) => l == r,
            (ScimAttr::Decimal(l), ScimAttr::Decimal(r)) => l == r,
            (ScimAttr::Integer(l), ScimAttr::Integer(r)) => l == r,
            (ScimAttr::DateTime(l), ScimAttr::DateTime(r)) => l == r,
            (ScimAttr::Binary(l), ScimAttr::Binary(r)) => l == r,
            (ScimAttr::Reference(l), ScimAttr::Reference(r)) => l == r,
            _ => false,
        }
    }
}

pub type ScimComplexAttr = BTreeMap<String, ScimAttr>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(untagged)]
pub enum ScimValue {
    Simple(ScimAttr),
    Complex(ScimComplexAttr),
    MultiSimple(Vec<ScimAttr>),
    MultiComplex(Vec<ScimComplexAttr>),
}

impl ScimValue {
    pub fn len(&self) -> usize {
        match self {
            ScimValue::Simple(_) | ScimValue::Complex(_) => 1,
            ScimValue::MultiSimple(a) => a.len(),
            ScimValue::MultiComplex(a) => a.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimMeta {
    pub resource_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub location: Url,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimEntryHeader {
    pub schemas: Vec<String>,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimEntry {
    pub schemas: Vec<String>,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
    #[serde(flatten)]
    pub attrs: BTreeMap<String, ScimValue>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RFC7643_USER;

    #[test]
    fn parse_scim_entry() {
        let _ = tracing_subscriber::fmt::try_init();

        let u: ScimEntry =
            serde_json::from_str(RFC7643_USER).expect("Failed to parse RFC7643_USER");

        tracing::trace!(?u);

        let s = serde_json::to_string_pretty(&u).expect("Failed to serialise RFC7643_USER");
        eprintln!("{s}");
    }

    // =========================================================
    // asymmetric serde tests

    use serde::de::{self, Deserialize, Deserializer, Visitor};
    use std::fmt;
    use uuid::Uuid;

    // -> For values, we need to be able to capture and handle "what if it's X" type? But
    // we can't know the "intent" until we hit schema, so we have to preserve the string
    // types as well. In this type, we make this *asymmetric*. When we parse we use
    // this type which has the "maybes" but when we serialise, we use concrete types
    // instead.

    #[derive(Debug)]
    #[allow(dead_code)]
    enum TestB {
        Integer(i64),
        Decimal(f64),
        MaybeUuid(Uuid, String),
        String(String),
    }

    struct TestBVisitor;

    impl Visitor<'_> for TestBVisitor {
        type Value = TestB;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("cheese")
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(TestB::Decimal(v))
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(TestB::Integer(v as i64))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(TestB::Integer(v))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(if let Ok(u) = Uuid::parse_str(v) {
                TestB::MaybeUuid(u, v.to_string())
            } else {
                TestB::String(v.to_string())
            })
        }
    }

    impl<'de> Deserialize<'de> for TestB {
        fn deserialize<D>(deserializer: D) -> Result<TestB, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(TestBVisitor)
        }
    }

    #[test]
    fn parse_enum_b() {
        let x: TestB = serde_json::from_str("10").unwrap();
        eprintln!("{x:?}");

        let x: TestB = serde_json::from_str("10.5").unwrap();
        eprintln!("{x:?}");

        let x: TestB = serde_json::from_str(r#""550e8400-e29b-41d4-a716-446655440000""#).unwrap();
        eprintln!("{x:?}");

        let x: TestB = serde_json::from_str(r#""Value""#).unwrap();
        eprintln!("{x:?}");
    }

    // In reverse when we serialise, we can simply use untagged on an enum.
    // Potentially this lets us have more "scim" types for dedicated serialisations
    // over the generic ones.

    #[derive(Serialize, Debug, Deserialize, Clone)]
    #[serde(rename_all = "lowercase", from = "&str", into = "String")]
    enum TestC {
        A,
        B,
        Unknown(String),
    }

    impl From<TestC> for String {
        fn from(v: TestC) -> String {
            match v {
                TestC::A => "A".to_string(),
                TestC::B => "B".to_string(),
                TestC::Unknown(v) => v,
            }
        }
    }

    impl From<&str> for TestC {
        fn from(v: &str) -> TestC {
            match v {
                "A" => TestC::A,
                "B" => TestC::B,
                _ => TestC::Unknown(v.to_string()),
            }
        }
    }

    #[test]
    fn parse_enum_c() {
        let x = serde_json::to_string(&TestC::A).unwrap();
        eprintln!("{x:?}");

        let x = serde_json::to_string(&TestC::B).unwrap();
        eprintln!("{x:?}");

        let x = serde_json::to_string(&TestC::Unknown("X".to_string())).unwrap();
        eprintln!("{x:?}");
    }
}

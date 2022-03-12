//! Inside an entry, the key-value pairs are stored in these [`Value`] types. The components of
//! the [`Value`] module allow storage and transformation of various types of input into strongly
//! typed values, allows their comparison, filtering and more. It also has the code for serialising
//! these into a form for the backend that can be persistent into the [`Backend`](crate::be::Backend).

use crate::be::dbvalue::DbValueV1;
use crate::credential::Credential;
use crate::repl::cid::Cid;
use kanidm_proto::v1::Filter as ProtoFilter;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use sshkeys::PublicKey as SshPublicKey;

use regex::Regex;

lazy_static! {
    pub static ref SPN_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("(?P<name>[^@]+)@(?P<realm>[^@]+)").expect("Invalid SPN regex found")
    };
    pub static ref INAME_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("^((\\.|_).*|.*(\\s|:|;|@|,|/|\\\\|=).*|\\d+|root|nobody|nogroup|wheel|sshd|shadow|systemd.*)$").expect("Invalid Iname regex found")
        //            ^      ^                          ^   ^
        //            |      |                          |   \- must not be a reserved name.
        //            |      |                          \- must not be only integers
        //            |      \- must not contain whitespace, @, :, ;, ',', /, \, =
        //            \- must not start with _ or .
        // Them's be the rules.
    };
    pub static ref NSUNIQUEID_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}$").expect("Invalid Nsunique regex found")
    };
    pub static ref OAUTHSCOPE_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("^[0-9a-zA-Z_]+$").expect("Invalid oauthscope regex found")
        // Must not contain whitespace.
    };
}

#[derive(Debug, Clone, PartialOrd, Ord, Eq, PartialEq)]
// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
pub struct Address {
    pub formatted: String,
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    // Must be validated.
    pub country: String,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Hash)]
pub enum IndexType {
    Equality,
    Presence,
    SubString,
}

impl TryFrom<&str> for IndexType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let n_value = value.to_uppercase();
        match n_value.as_str() {
            "EQUALITY" => Ok(IndexType::Equality),
            "PRESENCE" => Ok(IndexType::Presence),
            "SUBSTRING" => Ok(IndexType::SubString),
            // UUID map?
            // UUID rev map?
            _ => Err(()),
        }
    }
}

impl TryFrom<usize> for IndexType {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IndexType::Equality),
            1 => Ok(IndexType::Presence),
            2 => Ok(IndexType::SubString),
            _ => Err(()),
        }
    }
}

impl IndexType {
    pub fn as_idx_str(&self) -> &str {
        match self {
            IndexType::Equality => "eq",
            IndexType::Presence => "pres",
            IndexType::SubString => "sub",
        }
    }

    pub fn to_usize(&self) -> usize {
        match self {
            IndexType::Equality => 0,
            IndexType::Presence => 1,
            IndexType::SubString => 2,
        }
    }
}

impl fmt::Display for IndexType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                IndexType::Equality => "EQUALITY",
                IndexType::Presence => "PRESENCE",
                IndexType::SubString => "SUBSTRING",
            }
        )
    }
}

#[allow(non_camel_case_types)]
#[derive(Hash, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum SyntaxType {
    UTF8STRING,
    Utf8StringInsensitive,
    Utf8StringIname,
    Uuid,
    Boolean,
    SYNTAX_ID,
    INDEX_ID,
    REFERENCE_UUID,
    JSON_FILTER,
    Credential,
    SecretUtf8String,
    SshKey,
    SecurityPrincipalName,
    UINT32,
    Cid,
    NsUniqueId,
    DateTime,
    EmailAddress,
    Url,
    OauthScope,
    OauthScopeMap,
    PrivateBinary,
}

impl TryFrom<&str> for SyntaxType {
    type Error = ();

    fn try_from(value: &str) -> Result<SyntaxType, Self::Error> {
        let n_value = value.to_uppercase();
        match n_value.as_str() {
            "UTF8STRING" => Ok(SyntaxType::UTF8STRING),
            "UTF8STRING_INSENSITIVE" => Ok(SyntaxType::Utf8StringInsensitive),
            "UTF8STRING_INAME" => Ok(SyntaxType::Utf8StringIname),
            "UUID" => Ok(SyntaxType::Uuid),
            "BOOLEAN" => Ok(SyntaxType::Boolean),
            "SYNTAX_ID" => Ok(SyntaxType::SYNTAX_ID),
            "INDEX_ID" => Ok(SyntaxType::INDEX_ID),
            "REFERENCE_UUID" => Ok(SyntaxType::REFERENCE_UUID),
            "JSON_FILTER" => Ok(SyntaxType::JSON_FILTER),
            "CREDENTIAL" => Ok(SyntaxType::Credential),
            // Compatability for older syntax name.
            "RADIUS_UTF8STRING" | "SECRET_UTF8STRING" => Ok(SyntaxType::SecretUtf8String),
            "SSHKEY" => Ok(SyntaxType::SshKey),
            "SECURITY_PRINCIPAL_NAME" => Ok(SyntaxType::SecurityPrincipalName),
            "UINT32" => Ok(SyntaxType::UINT32),
            "CID" => Ok(SyntaxType::Cid),
            "NSUNIQUEID" => Ok(SyntaxType::NsUniqueId),
            "DATETIME" => Ok(SyntaxType::DateTime),
            "EMAIL_ADDRESS" => Ok(SyntaxType::EmailAddress),
            "URL" => Ok(SyntaxType::Url),
            "OAUTH_SCOPE" => Ok(SyntaxType::OauthScope),
            "OAUTH_SCOPE_MAP" => Ok(SyntaxType::OauthScopeMap),
            "PRIVATE_BINARY" => Ok(SyntaxType::PrivateBinary),
            _ => Err(()),
        }
    }
}

impl TryFrom<usize> for SyntaxType {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SyntaxType::UTF8STRING),
            1 => Ok(SyntaxType::Utf8StringInsensitive),
            2 => Ok(SyntaxType::Uuid),
            3 => Ok(SyntaxType::Boolean),
            4 => Ok(SyntaxType::SYNTAX_ID),
            5 => Ok(SyntaxType::INDEX_ID),
            6 => Ok(SyntaxType::REFERENCE_UUID),
            7 => Ok(SyntaxType::JSON_FILTER),
            8 => Ok(SyntaxType::Credential),
            9 => Ok(SyntaxType::SecretUtf8String),
            10 => Ok(SyntaxType::SshKey),
            11 => Ok(SyntaxType::SecurityPrincipalName),
            12 => Ok(SyntaxType::UINT32),
            13 => Ok(SyntaxType::Cid),
            14 => Ok(SyntaxType::Utf8StringIname),
            15 => Ok(SyntaxType::NsUniqueId),
            16 => Ok(SyntaxType::DateTime),
            17 => Ok(SyntaxType::EmailAddress),
            18 => Ok(SyntaxType::Url),
            19 => Ok(SyntaxType::OauthScope),
            20 => Ok(SyntaxType::OauthScopeMap),
            21 => Ok(SyntaxType::PrivateBinary),
            _ => Err(()),
        }
    }
}

impl SyntaxType {
    pub fn to_usize(&self) -> usize {
        match self {
            SyntaxType::UTF8STRING => 0,
            SyntaxType::Utf8StringInsensitive => 1,
            SyntaxType::Uuid => 2,
            SyntaxType::Boolean => 3,
            SyntaxType::SYNTAX_ID => 4,
            SyntaxType::INDEX_ID => 5,
            SyntaxType::REFERENCE_UUID => 6,
            SyntaxType::JSON_FILTER => 7,
            SyntaxType::Credential => 8,
            SyntaxType::SecretUtf8String => 9,
            SyntaxType::SshKey => 10,
            SyntaxType::SecurityPrincipalName => 11,
            SyntaxType::UINT32 => 12,
            SyntaxType::Cid => 13,
            SyntaxType::Utf8StringIname => 14,
            SyntaxType::NsUniqueId => 15,
            SyntaxType::DateTime => 16,
            SyntaxType::EmailAddress => 17,
            SyntaxType::Url => 18,
            SyntaxType::OauthScope => 19,
            SyntaxType::OauthScopeMap => 20,
            SyntaxType::PrivateBinary => 21,
        }
    }
}

impl fmt::Display for SyntaxType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            SyntaxType::UTF8STRING => "UTF8STRING",
            SyntaxType::Utf8StringInsensitive => "UTF8STRING_INSENSITIVE",
            SyntaxType::Utf8StringIname => "UTF8STRING_INAME",
            SyntaxType::Uuid => "UUID",
            SyntaxType::Boolean => "BOOLEAN",
            SyntaxType::SYNTAX_ID => "SYNTAX_ID",
            SyntaxType::INDEX_ID => "INDEX_ID",
            SyntaxType::REFERENCE_UUID => "REFERENCE_UUID",
            SyntaxType::JSON_FILTER => "JSON_FILTER",
            SyntaxType::Credential => "CREDENTIAL",
            SyntaxType::SecretUtf8String => "SECRET_UTF8STRING",
            SyntaxType::SshKey => "SSHKEY",
            SyntaxType::SecurityPrincipalName => "SECURITY_PRINCIPAL_NAME",
            SyntaxType::UINT32 => "UINT32",
            SyntaxType::Cid => "CID",
            SyntaxType::NsUniqueId => "NSUNIQUEID",
            SyntaxType::DateTime => "DATETIME",
            SyntaxType::EmailAddress => "EMAIL_ADDRESS",
            SyntaxType::Url => "URL",
            SyntaxType::OauthScope => "OAUTH_SCOPE",
            SyntaxType::OauthScopeMap => "OAUTH_SCOPE_MAP",
            SyntaxType::PrivateBinary => "PRIVATE_BINARY",
        })
    }
}

/// A partial value is a key or key subset that can be used to match for equality or substring
/// against a complete Value within a set in an Entry.
///
/// A partialValue is typically used when you need to match against a value, but without
/// requiring all of it's data or expression. This is common in Filters or other direct
/// lookups and requests.
#[derive(Hash, Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Deserialize, Serialize)]
pub enum PartialValue {
    Utf8(String),
    Iutf8(String),
    Iname(String),
    Uuid(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    // Does this make sense?
    // TODO: We'll probably add tagging to this type for the partial matching
    JsonFilt(ProtoFilter),
    // Tag, matches to a DataValue.
    Cred(String),
    SshKey(String),
    SecretValue,
    Spn(String, String),
    Uint32(u32),
    Cid(Cid),
    Nsuniqueid(String),
    DateTime(OffsetDateTime),
    EmailAddress(String),
    PhoneNumber(String),
    Address(String),
    // Can add other selectors later.
    Url(Url),
    OauthScope(String),
    OauthScopeMap(Uuid),
    PrivateBinary,
    PublicBinary(String),
    // Enumeration(String),
    // Float64(f64),
    RestrictedString(String),
}

impl From<SyntaxType> for PartialValue {
    fn from(s: SyntaxType) -> Self {
        PartialValue::Syntax(s)
    }
}

impl From<IndexType> for PartialValue {
    fn from(i: IndexType) -> Self {
        PartialValue::Index(i)
    }
}

impl From<bool> for PartialValue {
    fn from(b: bool) -> Self {
        PartialValue::Bool(b)
    }
}

impl From<&bool> for PartialValue {
    fn from(b: &bool) -> Self {
        PartialValue::Bool(*b)
    }
}

impl From<ProtoFilter> for PartialValue {
    fn from(i: ProtoFilter) -> Self {
        PartialValue::JsonFilt(i)
    }
}

impl From<u32> for PartialValue {
    fn from(i: u32) -> Self {
        PartialValue::Uint32(i)
    }
}

impl From<OffsetDateTime> for PartialValue {
    fn from(i: OffsetDateTime) -> Self {
        PartialValue::DateTime(i)
    }
}

impl From<Url> for PartialValue {
    fn from(i: Url) -> Self {
        PartialValue::Url(i)
    }
}

impl PartialValue {
    pub fn new_utf8(s: String) -> Self {
        PartialValue::Utf8(s)
    }

    pub fn new_utf8s(s: &str) -> Self {
        PartialValue::Utf8(s.to_string())
    }

    pub fn is_utf8(&self) -> bool {
        matches!(self, PartialValue::Utf8(_))
    }

    pub fn new_iutf8(s: &str) -> Self {
        PartialValue::Iutf8(s.to_lowercase())
    }

    pub fn new_iname(s: &str) -> Self {
        PartialValue::Iname(s.to_lowercase())
    }

    #[inline]
    pub fn new_class(s: &str) -> Self {
        PartialValue::new_iutf8(s)
    }

    pub fn is_iutf8(&self) -> bool {
        matches!(self, PartialValue::Iutf8(_))
    }

    pub fn is_iname(&self) -> bool {
        matches!(self, PartialValue::Iname(_))
    }

    pub fn new_bool(b: bool) -> Self {
        PartialValue::Bool(b)
    }

    pub fn new_bools(s: &str) -> Option<Self> {
        bool::from_str(s).map(PartialValue::Bool).ok()
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, PartialValue::Bool(_))
    }

    pub fn new_uuid(u: Uuid) -> Self {
        PartialValue::Uuid(u)
    }

    pub fn new_uuidr(u: &Uuid) -> Self {
        PartialValue::Uuid(*u)
    }

    pub fn new_uuids(us: &str) -> Option<Self> {
        Uuid::parse_str(us).map(PartialValue::Uuid).ok()
    }

    pub fn is_uuid(&self) -> bool {
        matches!(self, PartialValue::Uuid(_))
    }

    pub fn new_refer(u: Uuid) -> Self {
        PartialValue::Refer(u)
    }

    pub fn new_refer_r(u: &Uuid) -> Self {
        PartialValue::Refer(*u)
    }

    pub fn new_refer_s(us: &str) -> Option<Self> {
        match Uuid::parse_str(us) {
            Ok(u) => Some(PartialValue::Refer(u)),
            Err(_) => None,
        }
    }

    pub fn is_refer(&self) -> bool {
        matches!(self, PartialValue::Refer(_))
    }

    pub fn new_indexs(s: &str) -> Option<Self> {
        IndexType::try_from(s).map(PartialValue::Index).ok()
    }

    pub fn is_index(&self) -> bool {
        matches!(self, PartialValue::Index(_))
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        SyntaxType::try_from(s).map(PartialValue::Syntax).ok()
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self, PartialValue::Syntax(_))
    }

    pub fn new_json_filter_s(s: &str) -> Option<Self> {
        serde_json::from_str(s).map(PartialValue::JsonFilt).ok()
    }

    pub fn is_json_filter(&self) -> bool {
        matches!(self, PartialValue::JsonFilt(_))
    }

    pub fn new_credential_tag(s: &str) -> Self {
        PartialValue::Cred(s.to_lowercase())
    }

    pub fn is_credential(&self) -> bool {
        matches!(self, PartialValue::Cred(_))
    }

    pub fn new_secret_str() -> Self {
        PartialValue::SecretValue
    }

    pub fn is_secret_string(&self) -> bool {
        matches!(self, PartialValue::SecretValue)
    }

    pub fn new_sshkey_tag(s: String) -> Self {
        PartialValue::SshKey(s)
    }

    pub fn new_sshkey_tag_s(s: &str) -> Self {
        PartialValue::SshKey(s.to_string())
    }

    pub fn is_sshkey(&self) -> bool {
        matches!(self, PartialValue::SshKey(_))
    }

    pub fn new_spn_s(s: &str) -> Option<Self> {
        SPN_RE.captures(s).and_then(|caps| {
            let name = match caps.name("name") {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            let realm = match caps.name("realm") {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            Some(PartialValue::Spn(name, realm))
        })
    }

    pub fn new_spn_nrs(n: &str, r: &str) -> Self {
        PartialValue::Spn(n.to_string(), r.to_string())
    }

    pub fn is_spn(&self) -> bool {
        matches!(self, PartialValue::Spn(_, _))
    }

    pub fn new_uint32(u: u32) -> Self {
        PartialValue::Uint32(u)
    }

    pub fn new_uint32_str(u: &str) -> Option<Self> {
        u.parse::<u32>().ok().map(PartialValue::Uint32)
    }

    pub fn is_uint32(&self) -> bool {
        matches!(self, PartialValue::Uint32(_))
    }

    pub fn new_cid(c: Cid) -> Self {
        PartialValue::Cid(c)
    }

    pub fn new_cid_s(_c: &str) -> Option<Self> {
        None
    }

    pub fn is_cid(&self) -> bool {
        matches!(self, PartialValue::Cid(_))
    }

    pub fn new_nsuniqueid_s(s: &str) -> Self {
        PartialValue::Nsuniqueid(s.to_lowercase())
    }

    pub fn is_nsuniqueid(&self) -> bool {
        matches!(self, PartialValue::Nsuniqueid(_))
    }

    pub fn new_datetime_epoch(ts: Duration) -> Self {
        PartialValue::DateTime(OffsetDateTime::unix_epoch() + ts)
    }

    pub fn new_datetime_s(s: &str) -> Option<Self> {
        OffsetDateTime::parse(s, time::Format::Rfc3339)
            .ok()
            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
            .map(PartialValue::DateTime)
    }

    pub fn is_datetime(&self) -> bool {
        matches!(self, PartialValue::DateTime(_))
    }

    pub fn new_email_address_s(s: &str) -> Self {
        PartialValue::EmailAddress(s.to_string())
    }

    pub fn is_email_address(&self) -> bool {
        matches!(self, PartialValue::EmailAddress(_))
    }

    pub fn new_phonenumber_s(s: &str) -> Self {
        PartialValue::PhoneNumber(s.to_string())
    }

    pub fn new_address(s: &str) -> Self {
        PartialValue::Address(s.to_string())
    }

    pub fn new_url_s(s: &str) -> Option<Self> {
        Url::parse(s).ok().map(PartialValue::Url)
    }

    pub fn is_url(&self) -> bool {
        matches!(self, PartialValue::Url(_))
    }

    pub fn new_oauthscope(s: &str) -> Self {
        PartialValue::OauthScope(s.to_string())
    }

    pub fn is_oauthscope(&self) -> bool {
        matches!(self, PartialValue::OauthScope(_))
    }

    pub fn new_oauthscopemap(u: Uuid) -> Self {
        PartialValue::OauthScopeMap(u)
    }

    pub fn new_oauthscopemap_s(us: &str) -> Option<Self> {
        match Uuid::parse_str(us) {
            Ok(u) => Some(PartialValue::OauthScopeMap(u)),
            Err(_) => None,
        }
    }

    pub fn is_oauthscopemap(&self) -> bool {
        matches!(self, PartialValue::OauthScopeMap(_))
    }

    pub fn is_privatebinary(&self) -> bool {
        matches!(self, PartialValue::PrivateBinary)
    }

    pub fn new_publicbinary_tag_s(s: &str) -> Self {
        PartialValue::PublicBinary(s.to_string())
    }

    pub fn new_restrictedstring_s(s: &str) -> Self {
        PartialValue::RestrictedString(s.to_string())
    }

    pub fn to_str(&self) -> Option<&str> {
        match self {
            PartialValue::Utf8(s) => Some(s.as_str()),
            PartialValue::Iutf8(s) => Some(s.as_str()),
            PartialValue::Iname(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_url(&self) -> Option<&Url> {
        match self {
            PartialValue::Url(u) => Some(u),
            _ => None,
        }
    }

    pub fn get_idx_eq_key(&self) -> String {
        match &self {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            | PartialValue::Nsuniqueid(s)
            | PartialValue::EmailAddress(s)
            | PartialValue::RestrictedString(s) => s.clone(),
            PartialValue::Refer(u) | PartialValue::Uuid(u) => u.to_hyphenated_ref().to_string(),
            PartialValue::Bool(b) => b.to_string(),
            PartialValue::Syntax(syn) => syn.to_string(),
            PartialValue::Index(it) => it.to_string(),
            PartialValue::JsonFilt(s) =>
            {
                #[allow(clippy::expect_used)]
                serde_json::to_string(s).expect("A json filter value was corrupted during run-time")
            }
            PartialValue::Cred(tag)
            | PartialValue::PublicBinary(tag)
            | PartialValue::SshKey(tag) => tag.to_string(),
            // This will never match as we never index radius creds! See generate_idx_eq_keys
            PartialValue::SecretValue | PartialValue::PrivateBinary => "_".to_string(),
            PartialValue::Spn(name, realm) => format!("{}@{}", name, realm),
            PartialValue::Uint32(u) => u.to_string(),
            // This will never work, we don't allow equality searching on Cid's
            PartialValue::Cid(_) => "_".to_string(),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            }
            PartialValue::Url(u) => u.to_string(),
            PartialValue::OauthScope(u) => u.to_string(),
            PartialValue::OauthScopeMap(u) => u.to_hyphenated_ref().to_string(),
            PartialValue::Address(a) => a.to_string(),
            PartialValue::PhoneNumber(a) => a.to_string(),
        }
    }

    pub fn get_idx_sub_key(&self) -> String {
        unimplemented!();
    }
}

/// A value is a complete unit of data for an attribute. It is made up of a PartialValue, which is
/// used for selection, filtering, searching, matching etc. It also contains supplemental data
/// which may be stored inside of the Value, such as credential secrets, blobs etc.
///
/// This type is used when you need the "full data" of an attribute. Typically this is in a create
/// or modification operation where you are applying a set of complete values into an entry.
#[derive(Clone, Debug)]
pub enum Value {
    Utf8(String),
    Iutf8(String),
    Iname(String),
    Uuid(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    JsonFilt(ProtoFilter),
    Cred(String, Credential),
    SshKey(String, String),
    SecretValue(String),
    Spn(String, String),
    Uint32(u32),
    Cid(Cid),
    Nsuniqueid(String),
    DateTime(OffsetDateTime),
    EmailAddress(String, bool),
    PhoneNumber(String, bool),
    Address(Address),
    Url(Url),
    OauthScope(String),
    OauthScopeMap(Uuid, BTreeSet<String>),
    PrivateBinary(Vec<u8>),
    PublicBinary(String, Vec<u8>),
    // Enumeration(String),
    // Float64(f64),
    RestrictedString(String),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Utf8(a), Value::Utf8(b))
            | (Value::Iutf8(a), Value::Iutf8(b))
            | (Value::Iname(a), Value::Iname(b))
            | (Value::Cred(a, _), Value::Cred(b, _))
            | (Value::SshKey(a, _), Value::SshKey(b, _))
            | (Value::Spn(a, _), Value::Spn(b, _))
            | (Value::Nsuniqueid(a), Value::Nsuniqueid(b))
            | (Value::EmailAddress(a, _), Value::EmailAddress(b, _))
            | (Value::PhoneNumber(a, _), Value::PhoneNumber(b, _))
            | (Value::OauthScope(a), Value::OauthScope(b))
            | (Value::PublicBinary(a, _), Value::PublicBinary(b, _))
            | (Value::RestrictedString(a), Value::RestrictedString(b)) => a.eq(b),
            // Uuid, Refer
            (Value::Uuid(a), Value::Uuid(b)) | (Value::Refer(a), Value::Refer(b)) => a.eq(b),
            // Bool
            (Value::Bool(a), Value::Bool(b)) => a.eq(b),
            // Syntax
            (Value::Syntax(a), Value::Syntax(b)) => a.eq(b),
            // Index
            (Value::Index(a), Value::Index(b)) => a.eq(b),
            // JsonFilt
            (Value::JsonFilt(a), Value::JsonFilt(b)) => a.eq(b),
            // Uint32
            (Value::Uint32(a), Value::Uint32(b)) => a.eq(b),
            // Cid
            (Value::Cid(a), Value::Cid(b)) => a.eq(b),
            // DateTime
            (Value::DateTime(a), Value::DateTime(b)) => a.eq(b),
            // Url
            (Value::Url(a), Value::Url(b)) => a.eq(b),
            // OauthScopeMap
            (Value::OauthScopeMap(a, c), Value::OauthScopeMap(b, d)) => a.eq(b) && c.eq(d),

            // Address
            // PrivateBinary
            // SecretValue
            (Value::Address(_), Value::Address(_))
            | (Value::PrivateBinary(_), Value::PrivateBinary(_))
            | (Value::SecretValue(_), Value::SecretValue(_)) => false,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&bool> for Value {
    fn from(b: &bool) -> Self {
        Value::Bool(*b)
    }
}

impl From<SyntaxType> for Value {
    fn from(s: SyntaxType) -> Self {
        Value::Syntax(s)
    }
}

impl From<IndexType> for Value {
    fn from(i: IndexType) -> Self {
        Value::Index(i)
    }
}

impl From<ProtoFilter> for Value {
    fn from(i: ProtoFilter) -> Self {
        Value::JsonFilt(i)
    }
}

impl From<OffsetDateTime> for Value {
    fn from(i: OffsetDateTime) -> Self {
        Value::DateTime(i)
    }
}

impl From<u32> for Value {
    fn from(i: u32) -> Self {
        Value::Uint32(i)
    }
}

impl From<Url> for Value {
    fn from(i: Url) -> Self {
        Value::Url(i)
    }
}

// Because these are potentially ambiguous, we limit them to tests where we can contain
// any....mistakes.
#[cfg(test)]
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        // Fuzzy match for uuid's
        match Uuid::parse_str(s) {
            Ok(u) => Value::Uuid(u),
            Err(_) => Value::Utf8(s.to_string()),
        }
    }
}

#[cfg(test)]
impl From<&Uuid> for Value {
    fn from(u: &Uuid) -> Self {
        Value::Uuid(u.clone())
    }
}

#[cfg(test)]
impl From<Uuid> for Value {
    fn from(u: Uuid) -> Self {
        Value::Uuid(u)
    }
}

impl Value {
    // I get the feeling this will have a lot of matching ... sigh.
    pub fn new_utf8(s: String) -> Self {
        Value::Utf8(s)
    }

    pub fn new_utf8s(s: &str) -> Self {
        Value::Utf8(s.to_string())
    }

    pub fn is_utf8(&self) -> bool {
        matches!(self, Value::Utf8(_))
    }

    pub fn new_iutf8(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn is_iutf8(&self) -> bool {
        matches!(self, Value::Iutf8(_))
    }

    pub fn new_class(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn new_attr(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        matches!(self, Value::Iutf8(_))
    }

    pub fn new_iname(s: &str) -> Self {
        Value::Iname(s.to_lowercase())
    }

    pub fn is_iname(&self) -> bool {
        matches!(self, Value::Iname(_))
    }

    pub fn new_uuid(u: Uuid) -> Self {
        Value::Uuid(u)
    }

    pub fn new_uuids(s: &str) -> Option<Self> {
        Uuid::parse_str(s).map(Value::Uuid).ok()
    }

    pub fn new_uuidr(u: &Uuid) -> Self {
        Value::Uuid(*u)
    }

    // Is this correct? Should ref be seperate?
    pub fn is_uuid(&self) -> bool {
        matches!(self, Value::Uuid(_))
    }

    pub fn new_bool(b: bool) -> Self {
        Value::Bool(b)
    }

    pub fn new_bools(s: &str) -> Option<Self> {
        bool::from_str(s).map(Value::Bool).ok()
    }

    #[inline]
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        SyntaxType::try_from(s).map(Value::Syntax).ok()
    }

    pub fn new_syntax(s: SyntaxType) -> Self {
        Value::Syntax(s)
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self, Value::Syntax(_))
    }

    pub fn new_indexs(s: &str) -> Option<Self> {
        IndexType::try_from(s).map(Value::Index).ok()
    }

    pub fn new_index(i: IndexType) -> Self {
        Value::Index(i)
    }

    pub fn is_index(&self) -> bool {
        matches!(self, Value::Index(_))
    }

    pub fn new_refer(u: Uuid) -> Self {
        Value::Refer(u)
    }

    pub fn new_refer_r(u: &Uuid) -> Self {
        Value::Refer(*u)
    }

    pub fn new_refer_s(us: &str) -> Option<Self> {
        Uuid::parse_str(us).map(Value::Refer).ok()
    }

    pub fn is_refer(&self) -> bool {
        matches!(self, Value::Refer(_))
    }

    pub fn new_json_filter_s(s: &str) -> Option<Self> {
        serde_json::from_str(s).map(Value::JsonFilt).ok()
    }

    pub fn new_json_filter(f: ProtoFilter) -> Self {
        Value::JsonFilt(f)
    }

    pub fn is_json_filter(&self) -> bool {
        matches!(self, Value::JsonFilt(_))
    }

    pub fn as_json_filter(&self) -> Option<&ProtoFilter> {
        match &self {
            Value::JsonFilt(f) => Some(f),
            _ => None,
        }
    }

    pub fn new_credential(tag: &str, cred: Credential) -> Self {
        Value::Cred(tag.to_string(), cred)
    }

    pub fn is_credential(&self) -> bool {
        matches!(&self, Value::Cred(_, _))
    }

    pub fn to_credential(&self) -> Option<&Credential> {
        match &self {
            Value::Cred(_, cred) => Some(cred),
            _ => None,
        }
    }

    pub fn new_secret_str(cleartext: &str) -> Self {
        Value::SecretValue(cleartext.to_string())
    }

    pub fn is_secret_string(&self) -> bool {
        matches!(&self, Value::SecretValue(_))
    }

    pub fn get_secret_str(&self) -> Option<&str> {
        match &self {
            Value::SecretValue(c) => Some(c.as_str()),
            _ => None,
        }
    }

    pub fn new_sshkey_str(tag: &str, key: &str) -> Self {
        Value::SshKey(tag.to_string(), key.to_string())
    }

    pub fn new_sshkey(tag: String, key: String) -> Self {
        Value::SshKey(tag, key)
    }

    pub fn is_sshkey(&self) -> bool {
        matches!(&self, Value::SshKey(_, _))
    }

    pub fn get_sshkey(&self) -> Option<&str> {
        match &self {
            Value::SshKey(_, key) => Some(key.as_str()),
            _ => None,
        }
    }

    pub fn new_spn_parse(s: &str) -> Option<Self> {
        SPN_RE.captures(s).and_then(|caps| {
            let name = match caps.name("name") {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            let realm = match caps.name("realm") {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            Some(Value::Spn(name, realm))
        })
    }

    pub fn new_spn_str(n: &str, r: &str) -> Self {
        Value::Spn(n.to_string(), r.to_string())
    }

    pub fn is_spn(&self) -> bool {
        matches!(&self, Value::Spn(_, _))
    }

    pub fn new_uint32(u: u32) -> Self {
        Value::Uint32(u)
    }

    pub fn new_uint32_str(u: &str) -> Option<Self> {
        u.parse::<u32>().ok().map(Value::Uint32)
    }

    pub fn is_uint32(&self) -> bool {
        matches!(&self, Value::Uint32(_))
    }

    pub fn new_cid(c: Cid) -> Self {
        Value::Cid(c)
    }

    pub fn is_cid(&self) -> bool {
        matches!(&self, Value::Cid(_))
    }

    pub fn new_nsuniqueid_s(s: &str) -> Option<Self> {
        if NSUNIQUEID_RE.is_match(s) {
            Some(Value::Nsuniqueid(s.to_lowercase()))
        } else {
            None
        }
    }

    pub fn is_nsuniqueid(&self) -> bool {
        matches!(&self, Value::Nsuniqueid(_))
    }

    pub fn new_datetime_epoch(ts: Duration) -> Self {
        Value::DateTime(OffsetDateTime::unix_epoch() + ts)
    }

    pub fn new_datetime_s(s: &str) -> Option<Self> {
        OffsetDateTime::parse(s, time::Format::Rfc3339)
            .ok()
            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
            .map(Value::DateTime)
    }

    pub fn new_datetime(dt: OffsetDateTime) -> Self {
        Value::DateTime(dt)
    }

    pub fn to_datetime(&self) -> Option<OffsetDateTime> {
        match &self {
            Value::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                Some(*odt)
            }
            _ => None,
        }
    }

    pub fn is_datetime(&self) -> bool {
        matches!(&self, Value::DateTime(_))
    }

    pub fn new_email_address_s(s: &str) -> Option<Self> {
        if validator::validate_email(s) {
            Some(Value::EmailAddress(s.to_string(), false))
        } else {
            None
        }
    }

    pub fn new_email_address_primary_s(s: &str) -> Option<Self> {
        if validator::validate_email(s) {
            Some(Value::EmailAddress(s.to_string(), true))
        } else {
            None
        }
    }

    pub fn is_email_address(&self) -> bool {
        matches!(&self, Value::EmailAddress(_, _))
    }

    pub fn new_phonenumber_s(s: &str) -> Self {
        Value::PhoneNumber(s.to_string(), false)
    }

    pub fn new_address(a: Address) -> Self {
        Value::Address(a)
    }

    pub fn new_url_s(s: &str) -> Option<Self> {
        Url::parse(s).ok().map(Value::Url)
    }

    pub fn new_url(u: Url) -> Self {
        Value::Url(u)
    }

    pub fn is_url(&self) -> bool {
        matches!(&self, Value::Url(_))
    }

    pub fn new_oauthscope(s: &str) -> Option<Self> {
        if OAUTHSCOPE_RE.is_match(s) {
            Some(Value::OauthScope(s.to_string()))
        } else {
            None
        }
    }

    pub fn is_oauthscope(&self) -> bool {
        matches!(&self, Value::OauthScope(_))
    }

    pub fn new_oauthscopemap(u: Uuid, m: BTreeSet<String>) -> Option<Self> {
        if m.iter().all(|s| OAUTHSCOPE_RE.is_match(s)) {
            Some(Value::OauthScopeMap(u, m))
        } else {
            None
        }
    }

    pub fn is_oauthscopemap(&self) -> bool {
        matches!(&self, Value::OauthScopeMap(_, _))
    }

    #[cfg(test)]
    pub fn new_privatebinary_base64(der: &str) -> Self {
        let der = base64::decode(der).unwrap();
        Value::PrivateBinary(der)
    }

    pub fn new_privatebinary(der: &[u8]) -> Self {
        Value::PrivateBinary(der.to_owned())
    }

    pub fn to_privatebinary(&self) -> Option<&Vec<u8>> {
        match &self {
            Value::PrivateBinary(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_privatebinary(&self) -> bool {
        matches!(&self, Value::PrivateBinary(_))
    }

    pub fn new_publicbinary(tag: String, der: Vec<u8>) -> Self {
        Value::PublicBinary(tag, der)
    }

    pub fn new_restrictedstring(s: String) -> Self {
        Value::RestrictedString(s)
    }

    #[allow(clippy::unreachable)]
    pub(crate) fn to_supplementary_db_valuev1(&self) -> DbValueV1 {
        // This has to clone due to how the backend works.
        match &self {
            Value::Iname(s) => DbValueV1::Iname(s.clone()),
            Value::Utf8(s) => DbValueV1::Utf8(s.clone()),
            Value::Iutf8(s) => DbValueV1::Iutf8(s.clone()),
            Value::Uuid(u) => DbValueV1::Uuid(*u),
            Value::Spn(n, r) => DbValueV1::Spn(n.clone(), r.clone()),
            Value::Nsuniqueid(s) => DbValueV1::NsUniqueId(s.clone()),
            v => unreachable!("-> {:?}", v),
        }
    }

    pub fn to_str(&self) -> Option<&str> {
        match &self {
            Value::Utf8(s) => Some(s.as_str()),
            Value::Iutf8(s) => Some(s.as_str()),
            Value::Iname(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_url(&self) -> Option<&Url> {
        match &self {
            Value::Url(u) => Some(u),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&String> {
        match &self {
            Value::Utf8(s) => Some(s),
            Value::Iutf8(s) => Some(s),
            Value::Iname(s) => Some(s),
            _ => None,
        }
    }

    // We need a seperate to-ref_uuid to distinguish from normal uuids
    // in refint plugin.
    pub fn to_ref_uuid(&self) -> Option<&Uuid> {
        match &self {
            Value::Refer(u) => Some(u),
            Value::OauthScopeMap(u, _) => Some(u),
            _ => None,
        }
    }

    pub fn to_uuid(&self) -> Option<&Uuid> {
        match &self {
            Value::Uuid(u) => Some(u),
            _ => None,
        }
    }

    pub fn to_indextype(&self) -> Option<&IndexType> {
        match &self {
            Value::Index(i) => Some(i),
            _ => None,
        }
    }

    pub fn to_syntaxtype(&self) -> Option<&SyntaxType> {
        match &self {
            Value::Syntax(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_bool(&self) -> Option<bool> {
        match self {
            // *v is to invoke a copy, but this is cheap af
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn to_uint32(&self) -> Option<u32> {
        match &self {
            Value::Uint32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn to_partialvalue(&self) -> PartialValue {
        // Match on self to become a partialvalue.
        // self.pv.clone()
        unimplemented!();
    }

    pub fn to_utf8(self) -> Option<String> {
        match self {
            Value::Utf8(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_iutf8(self) -> Option<String> {
        match self {
            Value::Iutf8(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_iname(self) -> Option<String> {
        match self {
            Value::Iname(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_jsonfilt(self) -> Option<ProtoFilter> {
        match self {
            Value::JsonFilt(f) => Some(f),
            _ => None,
        }
    }

    pub fn to_cred(self) -> Option<(String, Credential)> {
        match self {
            Value::Cred(tag, c) => Some((tag, c)),
            _ => None,
        }
    }

    pub fn to_sshkey(self) -> Option<(String, String)> {
        match self {
            Value::SshKey(tag, k) => Some((tag, k)),
            _ => None,
        }
    }

    pub fn to_spn(self) -> Option<(String, String)> {
        match self {
            Value::Spn(n, d) => Some((n, d)),
            _ => None,
        }
    }

    pub fn to_cid(self) -> Option<Cid> {
        match self {
            Value::Cid(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_nsuniqueid(self) -> Option<String> {
        match self {
            Value::Nsuniqueid(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_emailaddress(self) -> Option<String> {
        match self {
            Value::EmailAddress(s, _) => Some(s),
            _ => None,
        }
    }

    pub fn to_oauthscope(self) -> Option<String> {
        match self {
            Value::OauthScope(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_oauthscopemap(self) -> Option<(Uuid, BTreeSet<String>)> {
        match self {
            Value::OauthScopeMap(u, m) => Some((u, m)),
            _ => None,
        }
    }

    pub fn to_restrictedstring(self) -> Option<String> {
        match self {
            Value::RestrictedString(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_phonenumber(self) -> Option<String> {
        match self {
            Value::PhoneNumber(p, _b) => Some(p),
            _ => None,
        }
    }

    pub fn to_publicbinary(self) -> Option<(String, Vec<u8>)> {
        match self {
            Value::PublicBinary(t, d) => Some((t, d)),
            _ => None,
        }
    }

    pub fn to_address(self) -> Option<Address> {
        match self {
            Value::Address(a) => Some(a),
            _ => None,
        }
    }

    pub fn migrate_iutf8_iname(self) -> Option<Self> {
        match self {
            Value::Iutf8(v) => Some(Value::Iname(v)),
            _ => None,
        }
    }

    // !!!! This function is beind phased out !!!
    #[allow(clippy::unreachable)]
    pub(crate) fn to_proto_string_clone(&self) -> String {
        match &self {
            Value::Iname(s) => s.clone(),
            Value::Uuid(u) => u.to_hyphenated_ref().to_string(),
            // We display the tag and fingerprint.
            Value::SshKey(tag, key) =>
            // Check it's really an sshkey in the
            // supplemental data.
            {
                match SshPublicKey::from_string(key) {
                    Ok(spk) => {
                        let fp = spk.fingerprint();
                        format!("{}: {}", tag, fp.hash)
                    }
                    Err(_) => format!("{}: corrupted ssh public key", tag),
                }
            }
            Value::Spn(n, r) => format!("{}@{}", n, r),
            _ => unreachable!(),
        }
    }

    // !!! relocate to value set !!!
    pub(crate) fn validate(&self) -> bool {
        // Validate that extra-data constraints on the type exist and are
        // valid. IE json filter is really a filter, or cred types have supplemental
        // data.
        match &self {
            Value::Iname(s) => {
                match Uuid::parse_str(s) {
                    // It is a uuid, disallow.
                    Ok(_) => false,
                    // Not a uuid, check it against the re.
                    Err(_) => !INAME_RE.is_match(s),
                }
            }
            /*
            Value::Cred(_) => match &self.data {
                Some(v) => matches!(v.as_ref(), DataValue::Cred(_)),
                None => false,
            },
            */
            Value::SshKey(_, key) => SshPublicKey::from_string(key).is_ok(),
            Value::Nsuniqueid(s) => NSUNIQUEID_RE.is_match(s),
            Value::DateTime(odt) => odt.offset() == time::UtcOffset::UTC,
            Value::EmailAddress(mail, _) => validator::validate_email(mail.as_str()),
            // PartialValue::Url validated through parsing.
            Value::OauthScope(s) => OAUTHSCOPE_RE.is_match(s),
            Value::OauthScopeMap(_, m) => m.iter().all(|s| OAUTHSCOPE_RE.is_match(s)),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::value::*;

    #[test]
    fn test_value_index_tryfrom() {
        let r1 = IndexType::try_from("EQUALITY");
        assert_eq!(r1, Ok(IndexType::Equality));

        let r2 = IndexType::try_from("PRESENCE");
        assert_eq!(r2, Ok(IndexType::Presence));

        let r3 = IndexType::try_from("SUBSTRING");
        assert_eq!(r3, Ok(IndexType::SubString));

        let r4 = IndexType::try_from("thaoeusaneuh");
        assert_eq!(r4, Err(()));
    }

    #[test]
    fn test_value_syntax_tryfrom() {
        let r1 = SyntaxType::try_from("UTF8STRING");
        assert_eq!(r1, Ok(SyntaxType::UTF8STRING));

        let r2 = SyntaxType::try_from("UTF8STRING_INSENSITIVE");
        assert_eq!(r2, Ok(SyntaxType::Utf8StringInsensitive));

        let r3 = SyntaxType::try_from("BOOLEAN");
        assert_eq!(r3, Ok(SyntaxType::Boolean));

        let r4 = SyntaxType::try_from("SYNTAX_ID");
        assert_eq!(r4, Ok(SyntaxType::SYNTAX_ID));

        let r5 = SyntaxType::try_from("INDEX_ID");
        assert_eq!(r5, Ok(SyntaxType::INDEX_ID));

        let r6 = SyntaxType::try_from("zzzzantheou");
        assert_eq!(r6, Err(()));
    }

    #[test]
    fn test_value_sshkey_validation_display() {
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@a",
        "methyst");
        let ed25519 = concat!(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP",
            " william@amethyst"
        );
        let rsa = concat!("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTcXpclurQpyOHZBM/cDY9EvInSYkYSGe51by/wJP0Njgi",
        "GZUJ3HTaPqoGWux0PKd7KJki+onLYt4IwDV1RhV/GtMML2U9v94+pA8RIK4khCxvpUxlM7Kt/svjOzzzqiZfKdV37/",
        "OUXmM7bwVGOvm3EerDOwmO/QdzNGfkca12aWLoz97YrleXnCoAzr3IN7j3rwmfJGDyuUtGTdmyS/QWhK9FPr8Ic3eM",
        "QK1JSAQqVfGhA8lLbJHmnQ/b/KMl2lzzp7SXej0wPUfvI/IP3NGb8irLzq8+JssAzXGJ+HMql+mNHiSuPaktbFzZ6y",
        "ikMR6Rx/psU07nAkxKZDEYpNVv william@amethyst");

        let sk1 = Value::new_sshkey_str("tag", ecdsa);
        assert!(sk1.validate());
        // to proto them
        let psk1 = sk1.to_proto_string_clone();
        assert_eq!(psk1, "tag: oMh0SibdRGV2APapEdVojzSySx9PuhcklWny5LP0Mg4");

        let sk2 = Value::new_sshkey_str("tag", ed25519);
        assert!(sk2.validate());
        let psk2 = sk2.to_proto_string_clone();
        assert_eq!(psk2, "tag: UR7mRCLLXmZNsun+F2lWO3hG3PORk/0JyjxPQxDUcdc");

        let sk3 = Value::new_sshkey_str("tag", rsa);
        assert!(sk3.validate());
        let psk3 = sk3.to_proto_string_clone();
        assert_eq!(psk3, "tag: sWugDdWeE4LkmKer8hz7ERf+6VttYPIqD0ULXR3EUcU");

        let sk4 = Value::new_sshkey_str("tag", "ntaouhtnhtnuehtnuhotnuhtneouhtneouh");
        assert!(!sk4.validate());

        let sk5 = Value::new_sshkey_str(
            "tag",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo",
        );
        assert!(!sk5.validate());
    }

    /*
    #[test]
    fn test_value_spn() {
        // Create an spn vale
        let spnv = Value::new_spn_str("claire", "example.net.au");
        // create an spn pv
        let spnp = PartialValue::new_spn_nrs("claire", "example.net.au");
        // check it's indexing output
        let vidx_key = spnv.generate_idx_eq_keys().pop().unwrap();
        let idx_key = spnp.get_idx_eq_key();
        assert!(idx_key == vidx_key);
        // check it can parse from name@realm
        let spn_parse = PartialValue::new_spn_s("claire@example.net.au").unwrap();
        assert!(spn_parse == spnp);
        // check it can produce name@realm as str from the pv.
        assert!("claire@example.net.au" == spnv.to_proto_string_clone());
    }
    */

    /*
    #[test]
    fn test_value_uint32() {
        assert!(Value::new_uint32_str("test").is_none());
        assert!(Value::new_uint32_str("18446744073709551615").is_none());

        let u32v = Value::new_uint32_str("4000").unwrap();
        let u32pv = PartialValue::new_uint32_str("4000").unwrap();

        let idx_key = u32pv.get_idx_eq_key();
        let vidx_key = u32v.generate_idx_eq_keys().pop().unwrap();

        assert!(idx_key == vidx_key);
    }
    */

    #[test]
    fn test_value_cid() {
        assert!(PartialValue::new_cid_s("_").is_none());
    }

    #[test]
    fn test_value_iname() {
        /*
         * name MUST NOT:
         * - be a pure int (confusion to gid/uid/linux)
         * - a uuid (confuses our name mapper)
         * - contain an @ (confuses SPN)
         * - can not start with _ (... api end points have _ as a magic char)
         * - can not have spaces (confuses too many systems :()
         * - can not have = or , (confuses ldap)
         * - can not have ., /, \ (path injection attacks)
         */
        let inv1 = Value::new_iname("1234");
        let inv2 = Value::new_iname("bc23f637-4439-4c07-b95d-eaed0d9e4b8b");
        let inv3 = Value::new_iname("hello@test.com");
        let inv4 = Value::new_iname("_bad");
        let inv5 = Value::new_iname("no spaces I'm sorry :(");
        let inv6 = Value::new_iname("bad=equals");
        let inv7 = Value::new_iname("bad,comma");

        let val1 = Value::new_iname("William");
        let val2 = Value::new_iname("this_is_okay");
        let val3 = Value::new_iname("123_456");
        let val4 = Value::new_iname("🍿");

        assert!(!inv1.validate());
        assert!(!inv2.validate());
        assert!(!inv3.validate());
        assert!(!inv4.validate());
        assert!(!inv5.validate());
        assert!(!inv6.validate());
        assert!(!inv7.validate());

        assert!(val1.validate());
        assert!(val2.validate());
        assert!(val3.validate());
        assert!(val4.validate());
    }

    #[test]
    fn test_value_nsuniqueid() {
        // nsunique
        // d765e707-48e111e6-8c9ebed8-f7926cc3
        // uuid
        // d765e707-48e1-11e6-8c9e-bed8f7926cc3
        let val1 = Value::new_nsuniqueid_s("d765e707-48e111e6-8c9ebed8-f7926cc3");
        let val2 = Value::new_nsuniqueid_s("D765E707-48E111E6-8C9EBED8-F7926CC3");
        let inv1 = Value::new_nsuniqueid_s("d765e707-48e1-11e6-8c9e-bed8f7926cc3");
        let inv2 = Value::new_nsuniqueid_s("xxxx");

        assert!(inv1.is_none());
        assert!(inv2.is_none());
        assert!(val1.unwrap().validate());
        assert!(val2.unwrap().validate());
    }

    #[test]
    fn test_value_datetime() {
        // Datetimes must always convert to UTC, and must always be rfc3339
        let val1 = Value::new_datetime_s("2020-09-25T11:22:02+10:00").expect("Must be valid");
        assert!(val1.validate());
        let val2 = Value::new_datetime_s("2020-09-25T01:22:02+00:00").expect("Must be valid");
        assert!(val2.validate());
        assert!(Value::new_datetime_s("2020-09-25T01:22:02").is_none());
        assert!(Value::new_datetime_s("2020-09-25").is_none());
        assert!(Value::new_datetime_s("2020-09-25T01:22:02+10").is_none());
        assert!(Value::new_datetime_s("2020-09-25 01:22:02+00:00").is_none());

        // Manually craft
        let inv1 =
            Value::DateTime(OffsetDateTime::now_utc().to_offset(time::UtcOffset::east_hours(10)));
        assert!(!inv1.validate());

        let val3 = Value::DateTime(OffsetDateTime::now_utc());
        assert!(val3.validate());
    }

    #[test]
    fn test_value_email_address() {
        // https://html.spec.whatwg.org/multipage/forms.html#valid-e-mail-address
        let val1 = Value::new_email_address_s("william@blackhats.net.au");
        let val2 = Value::new_email_address_s("alice@idm.example.com");
        let val3 = Value::new_email_address_s("test+mailbox@foo.com");
        let inv1 = Value::new_email_address_s("william");
        let inv2 = Value::new_email_address_s("test~uuid");

        assert!(inv1.is_none());
        assert!(inv2.is_none());
        assert!(val1.unwrap().validate());
        assert!(val2.unwrap().validate());
        assert!(val3.unwrap().validate());
    }

    #[test]
    fn test_value_url() {
        // https://html.spec.whatwg.org/multipage/forms.html#valid-e-mail-address
        let val1 = Value::new_url_s("https://localhost:8000/search?q=text#hello");
        let val2 = Value::new_url_s("https://github.com/kanidm/kanidm");
        let val3 = Value::new_url_s("ldap://foo.com");
        let inv1 = Value::new_url_s("127.0.");
        let inv2 = Value::new_url_s("🤔");

        assert!(inv1.is_none());
        assert!(inv2.is_none());
        assert!(val1.is_some());
        assert!(val2.is_some());
        assert!(val3.is_some());
    }

    /*
    #[test]
    fn test_schema_syntax_json_filter() {
        let sa = SchemaAttribute {
            name: String::from("acp_receiver"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_RECEIVER)
                .expect("unable to parse const uuid"),
            description: String::from(
                "Who the ACP applies to, constraining or allowing operations.",
            ),
            multivalue: false,
            index: vec![IndexType::Equality, IndexType::SubString],
            syntax: SyntaxType::JSON_FILTER,
        };

        // Outright wrong
        let r1 = sa.validate_json_filter(&String::from("Whargarble lol not a filter"));
        assert!(r1.is_err());
        // Json error
        let r2 = sa.validate_json_filter(&String::from(
            "{\"And\":[{\"Eq\":[\"a\",\"a\"]},\"Self\",]}",
        ));
        assert!(r2.is_err());
        // Invalid keyword
        let r3 = sa.validate_json_filter(&String::from(
            "{\"And\":[{\"Nalf\":[\"a\",\"a\"]},\"Self\"]}",
        ));
        assert!(r3.is_err());
        // valid
        let r4 = sa.validate_json_filter(&String::from("{\"Or\":[{\"Eq\":[\"a\",\"a\"]}]}"));
        assert!(r4.is_ok());
        // valid with self keyword
        let r5 =
            sa.validate_json_filter(&String::from("{\"And\":[{\"Eq\":[\"a\",\"a\"]},\"Self\"]}"));
        assert!(r5.is_ok());
    }

    #[test]
    fn test_schema_normalise_uuid() {
        let sa = SchemaAttribute {
            name: String::from("uuid"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UUID).expect("unable to parse const uuid"),
            description: String::from("The universal unique id of the object"),
            multivalue: false,
            index: vec![IndexType::Equality],
            syntax: SyntaxType::UUID,
        };
        let u1 = String::from("936DA01F9ABD4d9d80C702AF85C822A8");

        let un1 = sa.normalise_value(&u1);
        assert_eq!(un1, "936da01f-9abd-4d9d-80c7-02af85c822a8");
    }
    */
}

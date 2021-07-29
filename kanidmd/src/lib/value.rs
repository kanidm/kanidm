//! Inside an entry, the key-value pairs are stored in these [`Value`] types. The components of
//! the [`Value`] module allow storage and transformation of various types of input into strongly
//! typed values, allows their comparison, filtering and more. It also has the code for serialising
//! these into a form for the backend that can be persistent into the [`Backend`](crate::be::Backend).

use crate::be::dbvalue::{
    DbCidV1, DbValueCredV1, DbValueEmailAddressV1, DbValueTaggedStringV1, DbValueV1,
};
use crate::credential::Credential;
use crate::repl::cid::Cid;
use kanidm_proto::v1::Filter as ProtoFilter;

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use sshkeys::PublicKey as SshPublicKey;
use std::cmp::Ordering;

use regex::Regex;

lazy_static! {
    static ref SPN_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("(?P<name>[^@]+)@(?P<realm>[^@]+)").expect("Invalid SPN regex found")
    };
    static ref INAME_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("^((\\.|_).*|.*(\\s|:|;|@|,|/|\\\\|=).*|\\d+|root|nobody|nogroup|wheel|sshd|shadow|systemd.*)$").expect("Invalid Iname regex found")
        //            ^      ^                          ^   ^
        //            |      |                          |   \- must not be a reserved name.
        //            |      |                          \- must not be only integers
        //            |      \- must not contain whitespace, @, :, ;, ',', /, \, =
        //            \- must not start with _ or .
        // Them's be the rules.
    };
    static ref NSUNIQUEID_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}$").expect("Invalid Nsunique regex found")
    };
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
        })
    }
}

#[derive(Clone)]
pub enum DataValue {
    Cred(Credential),
    SshKey(String),
    SecretValue(String),
}

impl std::fmt::Debug for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DataValue::Cred(_) => write!(f, "DataValue::Cred(_)"),
            DataValue::SshKey(_) => write!(f, "DataValue::SshKey(_)"),
            DataValue::SecretValue(_) => write!(f, "DataValue::SecretValue(_)"),
        }
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
    Url(Url),
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

    /*
    #[inline]
    pub fn new_attr(s: &str) -> Self {
        PartialValue::new_iutf8s(s)
    }
    */

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
        match bool::from_str(s) {
            Ok(b) => Some(PartialValue::Bool(b)),
            Err(_) => None,
        }
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
        match Uuid::parse_str(us) {
            Ok(u) => Some(PartialValue::Uuid(u)),
            Err(_) => None,
        }
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
        let i = match IndexType::try_from(s) {
            Ok(i) => i,
            Err(_) => return None,
        };
        Some(PartialValue::Index(i))
    }

    pub fn is_index(&self) -> bool {
        matches!(self, PartialValue::Index(_))
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        let i = match SyntaxType::try_from(s) {
            Ok(i) => i,
            Err(_) => return None,
        };
        Some(PartialValue::Syntax(i))
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self, PartialValue::Syntax(_))
    }

    pub fn new_json_filter(s: &str) -> Option<Self> {
        let pf: ProtoFilter = match serde_json::from_str(s) {
            Ok(pf) => pf,
            Err(_) => return None,
        };
        Some(PartialValue::JsonFilt(pf))
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
        u32::from_str_radix(u, 10).ok().map(PartialValue::Uint32)
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

    pub fn new_url_s(s: &str) -> Option<Self> {
        Url::parse(s).ok().map(PartialValue::Url)
    }

    pub fn is_url(&self) -> bool {
        matches!(self, PartialValue::Url(_))
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
            PartialValue::Url(u) => Some(&u),
            _ => None,
        }
    }

    pub fn substring(&self, s: &PartialValue) -> bool {
        match (self, s) {
            (PartialValue::Utf8(s1), PartialValue::Utf8(s2)) => s1.contains(s2),
            (PartialValue::Iutf8(s1), PartialValue::Iutf8(s2)) => s1.contains(s2),
            (PartialValue::Iname(s1), PartialValue::Iname(s2)) => s1.contains(s2),
            _ => false,
        }
    }

    pub fn lessthan(&self, s: &PartialValue) -> bool {
        match (self, s) {
            (PartialValue::Cid(c1), PartialValue::Cid(c2)) => c1 < c2,
            (PartialValue::Uint32(u1), PartialValue::Uint32(u2)) => u1 < u2,
            _ => false,
        }
    }

    pub fn get_idx_eq_key(&self) -> String {
        match &self {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            | PartialValue::Nsuniqueid(s)
            | PartialValue::EmailAddress(s) => s.clone(),
            PartialValue::Refer(u) | PartialValue::Uuid(u) => u.to_hyphenated_ref().to_string(),
            PartialValue::Bool(b) => b.to_string(),
            PartialValue::Syntax(syn) => syn.to_string(),
            PartialValue::Index(it) => it.to_string(),
            PartialValue::JsonFilt(s) =>
            {
                #[allow(clippy::expect_used)]
                serde_json::to_string(s).expect("A json filter value was corrupted during run-time")
            }
            PartialValue::Cred(tag) => tag.to_string(),
            // This will never match as we never index radius creds! See generate_idx_eq_keys
            PartialValue::SecretValue => "_".to_string(),
            PartialValue::SshKey(tag) => tag.to_string(),
            PartialValue::Spn(name, realm) => format!("{}@{}", name, realm),
            PartialValue::Uint32(u) => u.to_string(),
            // This will never work, we don't allow equality searching on Cid's
            PartialValue::Cid(_) => "_".to_string(),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            }
            PartialValue::Url(u) => u.to_string(),
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
pub struct Value {
    pub(crate) pv: PartialValue,
    // Later we'll add extra data fields for different v types. They'll have to switch on
    // pv somehow, so probably need optional or union?
    pub(crate) data: Option<Box<DataValue>>,
}

// TODO: Impl display

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.pv.eq(&other.pv)
    }
}

impl Eq for Value {}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.pv.cmp(&other.pv))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pv.cmp(&other.pv)
    }
}

// Need new_<type> -> Result<_, _>
// Need from_db_value
// Need to_db_value
// Need to_string for most types.

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value {
            pv: PartialValue::Bool(b),
            data: None,
        }
    }
}

impl From<&bool> for Value {
    fn from(b: &bool) -> Self {
        Value {
            pv: PartialValue::Bool(*b),
            data: None,
        }
    }
}

impl From<SyntaxType> for Value {
    fn from(s: SyntaxType) -> Self {
        Value {
            pv: PartialValue::Syntax(s),
            data: None,
        }
    }
}

impl From<IndexType> for Value {
    fn from(i: IndexType) -> Self {
        Value {
            pv: PartialValue::Index(i),
            data: None,
        }
    }
}

// Because these are potentially ambiguous, we limit them to tests where we can contain
// any....mistakes.
#[cfg(test)]
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        // Fuzzy match for uuid's
        match Uuid::parse_str(s) {
            Ok(u) => Value {
                pv: PartialValue::Uuid(u),
                data: None,
            },
            Err(_) => Value {
                pv: PartialValue::Utf8(s.to_string()),
                data: None,
            },
        }
    }
}

#[cfg(test)]
impl From<&Uuid> for Value {
    fn from(u: &Uuid) -> Self {
        Value {
            pv: PartialValue::Uuid(u.clone()),
            data: None,
        }
    }
}

#[cfg(test)]
impl From<Uuid> for Value {
    fn from(u: Uuid) -> Self {
        Value {
            pv: PartialValue::Uuid(u),
            data: None,
        }
    }
}

impl Value {
    // I get the feeling this will have a lot of matching ... sigh.
    pub fn new_utf8(s: String) -> Self {
        Value {
            pv: PartialValue::new_utf8(s),
            data: None,
        }
    }

    pub fn new_utf8s(s: &str) -> Self {
        Value {
            pv: PartialValue::new_utf8s(s),
            data: None,
        }
    }

    pub fn is_utf8(&self) -> bool {
        matches!(self.pv, PartialValue::Utf8(_))
    }

    pub fn new_iutf8(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iutf8(s),
            data: None,
        }
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        matches!(self.pv, PartialValue::Iutf8(_))
    }

    pub fn new_iname(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iname(s),
            data: None,
        }
    }

    pub fn is_iname(&self) -> bool {
        matches!(self.pv, PartialValue::Iname(_))
    }

    pub fn new_uuid(u: Uuid) -> Self {
        Value {
            pv: PartialValue::new_uuid(u),
            data: None,
        }
    }

    pub fn new_uuids(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_uuids(s)?,
            data: None,
        })
    }

    pub fn new_uuidr(u: &Uuid) -> Self {
        Value {
            pv: PartialValue::new_uuidr(u),
            data: None,
        }
    }

    // Is this correct? Should ref be seperate?
    pub fn is_uuid(&self) -> bool {
        matches!(self.pv, PartialValue::Uuid(_))
    }

    pub fn new_class(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iutf8(s),
            data: None,
        }
    }

    pub fn new_attr(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iutf8(s),
            data: None,
        }
    }

    pub fn new_bool(b: bool) -> Self {
        Value {
            pv: PartialValue::new_bool(b),
            data: None,
        }
    }

    pub fn new_bools(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_bools(s)?,
            data: None,
        })
    }

    #[inline]
    pub fn is_bool(&self) -> bool {
        matches!(self.pv, PartialValue::Bool(_))
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_syntaxs(s)?,
            data: None,
        })
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self.pv, PartialValue::Syntax(_))
    }

    pub fn new_indexs(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_indexs(s)?,
            data: None,
        })
    }

    pub fn is_index(&self) -> bool {
        matches!(self.pv, PartialValue::Index(_))
    }

    pub fn new_refer(u: Uuid) -> Self {
        Value {
            pv: PartialValue::new_refer(u),
            data: None,
        }
    }

    pub fn new_refer_r(u: &Uuid) -> Self {
        Value {
            pv: PartialValue::new_refer_r(u),
            data: None,
        }
    }

    pub fn new_refer_s(us: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_refer_s(us)?,
            data: None,
        })
    }

    pub fn is_refer(&self) -> bool {
        matches!(self.pv, PartialValue::Refer(_))
    }

    pub fn new_json_filter(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_json_filter(s)?,
            data: None,
        })
    }

    pub fn is_json_filter(&self) -> bool {
        matches!(self.pv, PartialValue::JsonFilt(_))
    }

    pub fn as_json_filter(&self) -> Option<&ProtoFilter> {
        match &self.pv {
            PartialValue::JsonFilt(f) => Some(f),
            _ => None,
        }
    }

    pub fn new_credential(tag: &str, cred: Credential) -> Self {
        Value {
            pv: PartialValue::new_credential_tag(tag),
            data: Some(Box::new(DataValue::Cred(cred))),
        }
    }

    pub fn is_credential(&self) -> bool {
        matches!(&self.pv, PartialValue::Cred(_))
    }

    pub fn to_credential(&self) -> Option<&Credential> {
        match &self.pv {
            PartialValue::Cred(_) => match &self.data {
                Some(dv) => match dv.as_ref() {
                    DataValue::Cred(c) => Some(&c),
                    _ => None,
                },
                None => None,
            },
            _ => None,
        }
    }

    pub fn new_secret_str(cleartext: &str) -> Self {
        Value {
            pv: PartialValue::new_secret_str(),
            data: Some(Box::new(DataValue::SecretValue(cleartext.to_string()))),
        }
    }

    pub fn is_secret_string(&self) -> bool {
        matches!(&self.pv, PartialValue::SecretValue)
    }

    pub fn get_secret_str(&self) -> Option<&str> {
        match &self.pv {
            PartialValue::SecretValue => match &self.data {
                Some(dv) => match dv.as_ref() {
                    DataValue::SecretValue(c) => Some(c.as_str()),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    pub fn new_sshkey_str(tag: &str, key: &str) -> Self {
        Value {
            pv: PartialValue::new_sshkey_tag_s(tag),
            data: Some(Box::new(DataValue::SshKey(key.to_string()))),
        }
    }

    pub fn new_sshkey(tag: String, key: String) -> Self {
        Value {
            pv: PartialValue::new_sshkey_tag(tag),
            data: Some(Box::new(DataValue::SshKey(key))),
        }
    }

    pub fn is_sshkey(&self) -> bool {
        matches!(&self.pv, PartialValue::SshKey(_))
    }

    pub fn get_sshkey(&self) -> Option<&str> {
        match &self.pv {
            PartialValue::SshKey(_) => match &self.data {
                Some(v) => match v.as_ref() {
                    DataValue::SshKey(sc) => Some(sc.as_str()),
                    _ => None,
                },
                None => None,
            },
            _ => None,
        }
    }

    pub fn new_spn_parse(v: &str) -> Option<Self> {
        PartialValue::new_spn_s(v).map(|spn| Value {
            pv: spn,
            data: None,
        })
    }

    pub fn new_spn_str(n: &str, r: &str) -> Self {
        Value {
            pv: PartialValue::new_spn_nrs(n, r),
            data: None,
        }
    }

    pub fn is_spn(&self) -> bool {
        matches!(&self.pv, PartialValue::Spn(_, _))
    }

    pub fn new_uint32(u: u32) -> Self {
        Value {
            pv: PartialValue::new_uint32(u),
            data: None,
        }
    }

    pub fn new_uint32_str(u: &str) -> Option<Self> {
        PartialValue::new_uint32_str(u).map(|ui| Value { pv: ui, data: None })
    }

    pub fn is_uint32(&self) -> bool {
        matches!(&self.pv, PartialValue::Uint32(_))
    }

    pub fn new_cid(c: Cid) -> Self {
        Value {
            pv: PartialValue::new_cid(c),
            data: None,
        }
    }

    pub fn is_cid(&self) -> bool {
        matches!(&self.pv, PartialValue::Cid(_))
    }

    pub fn new_nsuniqueid_s(s: &str) -> Self {
        Value {
            pv: PartialValue::new_nsuniqueid_s(s),
            data: None,
        }
    }

    pub fn is_nsuniqueid(&self) -> bool {
        self.pv.is_nsuniqueid()
    }

    pub fn new_datetime_epoch(ts: Duration) -> Self {
        Value {
            pv: PartialValue::new_datetime_epoch(ts),
            data: None,
        }
    }

    pub fn new_datetime_s(s: &str) -> Option<Self> {
        PartialValue::new_datetime_s(s).map(|pv| Value { pv, data: None })
    }

    pub fn to_datetime(&self) -> Option<OffsetDateTime> {
        match &self.pv {
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                Some(*odt)
            }
            _ => None,
        }
    }

    pub fn is_datetime(&self) -> bool {
        self.pv.is_datetime()
    }

    pub fn new_email_address_s(s: &str) -> Self {
        Value {
            pv: PartialValue::new_email_address_s(s),
            data: None,
        }
    }

    pub fn is_email_address(&self) -> bool {
        self.pv.is_email_address()
    }

    pub fn new_url_s(s: &str) -> Option<Self> {
        PartialValue::new_url_s(s).map(|pv| Value { pv, data: None })
    }

    pub fn is_url(&self) -> bool {
        self.pv.is_url()
    }

    pub fn lessthan(&self, s: &PartialValue) -> bool {
        self.pv.lessthan(s)
    }

    pub fn substring(&self, s: &PartialValue) -> bool {
        self.pv.substring(s)
    }

    // Converters between DBRepr -> MemRepr. It's likely many of these
    // will be just wrappers to our from str types.

    // Keep this updated with DbValueV1 in be::dbvalue.
    pub(crate) fn from_db_valuev1(v: DbValueV1) -> Result<Self, ()> {
        match v {
            DbValueV1::Utf8(s) => Ok(Value {
                pv: PartialValue::Utf8(s),
                data: None,
            }),
            DbValueV1::Iutf8(s) => {
                Ok(Value {
                    // TODO: Should we be lowercasing here? The dbv should be normalised
                    // already, but is there a risk of corruption/tampering if we don't touch this?
                    pv: PartialValue::Iutf8(s.to_lowercase()),
                    data: None,
                })
            }
            DbValueV1::Iname(s) => Ok(Value {
                pv: PartialValue::Iname(s.to_lowercase()),
                data: None,
            }),
            DbValueV1::Uuid(u) => Ok(Value {
                pv: PartialValue::Uuid(u),
                data: None,
            }),
            DbValueV1::Bool(b) => Ok(Value {
                pv: PartialValue::Bool(b),
                data: None,
            }),
            DbValueV1::SyntaxType(us) => Ok(Value {
                pv: PartialValue::Syntax(SyntaxType::try_from(us)?),
                data: None,
            }),
            DbValueV1::IndexType(us) => Ok(Value {
                pv: PartialValue::Index(IndexType::try_from(us)?),
                data: None,
            }),
            DbValueV1::Reference(u) => Ok(Value {
                pv: PartialValue::Refer(u),
                data: None,
            }),
            DbValueV1::JsonFilter(s) => Ok(Value {
                pv: match PartialValue::new_json_filter(s.as_str()) {
                    Some(pv) => pv,
                    None => return Err(()),
                },
                data: None,
            }),
            DbValueV1::Credential(dvc) => {
                // Deserialise the db cred here.
                Ok(Value {
                    pv: PartialValue::Cred(dvc.tag.to_lowercase()),
                    data: Some(Box::new(DataValue::Cred(Credential::try_from(dvc.data)?))),
                })
            }
            DbValueV1::SecretValue(d) => Ok(Value {
                pv: PartialValue::SecretValue,
                data: Some(Box::new(DataValue::SecretValue(d))),
            }),
            DbValueV1::SshKey(ts) => Ok(Value {
                pv: PartialValue::SshKey(ts.tag),
                data: Some(Box::new(DataValue::SshKey(ts.data))),
            }),
            DbValueV1::Spn(n, r) => Ok(Value {
                pv: PartialValue::Spn(n, r),
                data: None,
            }),
            DbValueV1::Uint32(u) => Ok(Value {
                pv: PartialValue::Uint32(u),
                data: None,
            }),
            DbValueV1::Cid(dc) => Ok(Value {
                pv: PartialValue::Cid(Cid {
                    ts: dc.timestamp,
                    d_uuid: dc.domain_id,
                    s_uuid: dc.server_id,
                }),
                data: None,
            }),
            DbValueV1::NsUniqueId(s) => Ok(Value {
                pv: PartialValue::Nsuniqueid(s),
                data: None,
            }),
            DbValueV1::DateTime(s) => PartialValue::new_datetime_s(&s)
                .ok_or(())
                .map(|pv| Value { pv, data: None }),
            DbValueV1::EmailAddress(DbValueEmailAddressV1 { d: email_addr }) => Ok(Value {
                pv: PartialValue::EmailAddress(email_addr),
                data: None,
            }),
            DbValueV1::Url(u) => Ok(Value {
                pv: PartialValue::Url(u),
                data: None,
            }),
        }
    }

    #[allow(clippy::unreachable)]
    #[allow(clippy::expect_used)]
    pub(crate) fn to_db_valuev1(&self) -> DbValueV1 {
        // This has to clone due to how the backend works.
        match &self.pv {
            PartialValue::Utf8(s) => DbValueV1::Utf8(s.clone()),
            PartialValue::Iutf8(s) => DbValueV1::Iutf8(s.clone()),
            PartialValue::Iname(s) => DbValueV1::Iname(s.clone()),
            PartialValue::Uuid(u) => DbValueV1::Uuid(*u),
            PartialValue::Bool(b) => DbValueV1::Bool(*b),
            PartialValue::Syntax(syn) => DbValueV1::SyntaxType(syn.to_usize()),
            PartialValue::Index(it) => DbValueV1::IndexType(it.to_usize()),
            PartialValue::Refer(u) => DbValueV1::Reference(*u),
            PartialValue::JsonFilt(s) => DbValueV1::JsonFilter(
                serde_json::to_string(s)
                    .expect("A json filter value was corrupted during run-time"),
            ),
            PartialValue::Cred(tag) => {
                // Get the credential out and make sure it matches the type we expect.
                let c = match &self.data {
                    Some(v) => match v.as_ref() {
                        DataValue::Cred(c) => c,
                        _ => unreachable!(),
                    },
                    None => unreachable!(),
                };

                // Save the tag AND the dataValue here!
                DbValueV1::Credential(DbValueCredV1 {
                    tag: tag.clone(),
                    data: c.to_db_valuev1(),
                })
            }
            PartialValue::SecretValue => {
                let ru = match &self.data {
                    Some(v) => match v.as_ref() {
                        DataValue::SecretValue(rc) => rc.clone(),
                        _ => unreachable!(),
                    },
                    None => unreachable!(),
                };
                DbValueV1::SecretValue(ru)
            }
            PartialValue::SshKey(t) => {
                let sk = match &self.data {
                    Some(v) => match v.as_ref() {
                        DataValue::SshKey(sc) => sc.clone(),
                        _ => unreachable!(),
                    },
                    None => unreachable!(),
                };
                DbValueV1::SshKey(DbValueTaggedStringV1 {
                    tag: t.clone(),
                    data: sk,
                })
            }
            PartialValue::Spn(n, r) => DbValueV1::Spn(n.clone(), r.clone()),
            PartialValue::Uint32(u) => DbValueV1::Uint32(*u),
            PartialValue::Cid(c) => DbValueV1::Cid(DbCidV1 {
                domain_id: c.d_uuid,
                server_id: c.s_uuid,
                timestamp: c.ts,
            }),
            PartialValue::Nsuniqueid(s) => DbValueV1::NsUniqueId(s.clone()),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                DbValueV1::DateTime(odt.format(time::Format::Rfc3339))
            }
            PartialValue::EmailAddress(mail) => {
                DbValueV1::EmailAddress(DbValueEmailAddressV1 { d: mail.clone() })
            }
            PartialValue::Url(u) => DbValueV1::Url(u.clone()),
        }
    }

    pub fn to_str(&self) -> Option<&str> {
        match &self.pv {
            PartialValue::Utf8(s) => Some(s.as_str()),
            PartialValue::Iutf8(s) => Some(s.as_str()),
            PartialValue::Iname(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_url(&self) -> Option<&Url> {
        match &self.pv {
            PartialValue::Url(u) => Some(&u),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&String> {
        match &self.pv {
            PartialValue::Utf8(s) => Some(s),
            PartialValue::Iutf8(s) => Some(s),
            PartialValue::Iname(s) => Some(s),
            _ => None,
        }
    }

    // We need a seperate to-ref_uuid to distinguish from normal uuids
    // in refint plugin.
    pub fn to_ref_uuid(&self) -> Option<&Uuid> {
        match &self.pv {
            PartialValue::Refer(u) => Some(&u),
            _ => None,
        }
    }

    pub fn to_uuid(&self) -> Option<&Uuid> {
        match &self.pv {
            PartialValue::Uuid(u) => Some(&u),
            _ => None,
        }
    }

    pub fn to_indextype(&self) -> Option<&IndexType> {
        match &self.pv {
            PartialValue::Index(i) => Some(&i),
            _ => None,
        }
    }

    pub fn to_syntaxtype(&self) -> Option<&SyntaxType> {
        match &self.pv {
            PartialValue::Syntax(s) => Some(&s),
            _ => None,
        }
    }

    pub fn to_bool(&self) -> Option<bool> {
        match self.pv {
            // *v is to invoke a copy, but this is cheap af
            PartialValue::Bool(v) => Some(v),
            _ => None,
        }
    }

    pub fn to_uint32(&self) -> Option<u32> {
        match &self.pv {
            PartialValue::Uint32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn to_partialvalue(&self) -> PartialValue {
        // Match on self to become a partialvalue.
        self.pv.clone()
    }

    pub fn migrate_iutf8_iname(self) -> Option<Self> {
        match self.pv {
            PartialValue::Iutf8(v) => Some(Value {
                pv: PartialValue::Iname(v),
                data: None,
            }),
            _ => None,
        }
    }

    pub(crate) fn to_proto_string_clone(&self) -> String {
        match &self.pv {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            | PartialValue::Nsuniqueid(s)
            | PartialValue::EmailAddress(s) => s.clone(),
            PartialValue::Uuid(u) => u.to_hyphenated_ref().to_string(),
            PartialValue::Bool(b) => b.to_string(),
            PartialValue::Syntax(syn) => syn.to_string(),
            PartialValue::Index(it) => it.to_string(),
            // In resolve value, we bypass this, but we keep it here for complete
            // impl sake.
            PartialValue::Refer(u) => u.to_hyphenated_ref().to_string(),
            PartialValue::JsonFilt(s) =>
            {
                #[allow(clippy::expect_used)]
                serde_json::to_string(s).expect("A json filter value was corrupted during run-time")
            }
            PartialValue::Cred(tag) => {
                // You can't actually read the credential values because we only display the
                // tag to the proto side. The credentials private data is stored seperately.
                tag.to_string()
            }
            // We display the tag and fingerprint.
            PartialValue::SshKey(tag) => match &self.data {
                Some(v) => match v.as_ref() {
                    DataValue::SshKey(sk) => {
                        // Check it's really an sshkey in the
                        // supplemental data.
                        match SshPublicKey::from_string(sk) {
                            Ok(spk) => {
                                let fp = spk.fingerprint();
                                format!("{}: {}", tag, fp.hash)
                            }
                            Err(_) => format!("{}: corrupted ssh public key", tag),
                        }
                    }
                    _ => format!("{}: corrupted value tag", tag),
                },
                None => format!("{}: corrupted value", tag),
            },
            // We don't disclose the secret value unless by special
            // interfaces.
            PartialValue::SecretValue => "secret".to_string(),
            PartialValue::Spn(n, r) => format!("{}@{}", n, r),
            PartialValue::Uint32(u) => u.to_string(),
            PartialValue::Cid(c) => format!("{:?}_{}_{}", c.ts, c.d_uuid, c.s_uuid),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            }
            PartialValue::Url(u) => u.to_string(),
        }
    }

    pub fn validate(&self) -> bool {
        // Validate that extra-data constraints on the type exist and are
        // valid. IE json filter is really a filter, or cred types have supplemental
        // data.
        match &self.pv {
            PartialValue::Iname(s) => {
                match Uuid::parse_str(s) {
                    // It is a uuid, disallow.
                    Ok(_) => false,
                    // Not a uuid, check it against the re.
                    Err(_) => !INAME_RE.is_match(s),
                }
            }
            PartialValue::Cred(_) => match &self.data {
                Some(v) => matches!(v.as_ref(), DataValue::Cred(_)),
                None => false,
            },
            PartialValue::SshKey(_) => match &self.data {
                Some(v) => match v.as_ref() {
                    // Check it's really an sshkey in the supplemental
                    // data.
                    DataValue::SshKey(sk) => SshPublicKey::from_string(sk).is_ok(),
                    _ => false,
                },
                None => false,
            },
            PartialValue::SecretValue => match &self.data {
                Some(v) => matches!(v.as_ref(), DataValue::SecretValue(_)),
                None => false,
            },
            PartialValue::Nsuniqueid(s) => NSUNIQUEID_RE.is_match(s),
            PartialValue::DateTime(odt) => odt.offset() == time::UtcOffset::UTC,
            PartialValue::EmailAddress(mail) => validator::validate_email(mail.as_str()),
            // PartialValue::Url validated through parsing.
            _ => true,
        }
    }

    pub fn generate_idx_eq_keys(&self) -> Vec<String> {
        #[allow(clippy::expect_used)]
        match &self.pv {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            | PartialValue::Nsuniqueid(s)
            | PartialValue::EmailAddress(s) => vec![s.clone()],
            PartialValue::Refer(u) | PartialValue::Uuid(u) => {
                vec![u.to_hyphenated_ref().to_string()]
            }
            PartialValue::Bool(b) => vec![b.to_string()],
            PartialValue::Syntax(syn) => vec![syn.to_string()],
            PartialValue::Index(it) => vec![it.to_string()],
            PartialValue::JsonFilt(s) => vec![serde_json::to_string(s)
                .expect("A json filter value was corrupted during run-time")],
            PartialValue::Cred(tag) => vec![tag.to_string()],
            PartialValue::SshKey(tag) => {
                // Should this also extract the key data?
                vec![tag.to_string()]
            }
            PartialValue::SecretValue => vec![],
            PartialValue::Spn(n, r) => vec![format!("{}@{}", n, r)],
            PartialValue::Uint32(u) => vec![u.to_string()],
            PartialValue::Cid(_) => vec![],
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                vec![odt.format(time::Format::Rfc3339)]
            }
            PartialValue::Url(u) => vec![u.to_string()],
        }
    }
}

impl Borrow<PartialValue> for Value {
    fn borrow(&self) -> &PartialValue {
        &self.pv
    }
}

// Allows sets of value refs to be compared to PV's
impl Borrow<PartialValue> for &Value {
    fn borrow(&self) -> &PartialValue {
        &self.pv
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

        assert!(!inv1.validate());
        assert!(!inv2.validate());
        assert!(val1.validate());
        assert!(val2.validate());
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
        let inv1 = Value {
            pv: PartialValue::DateTime(
                OffsetDateTime::now_utc().to_offset(time::UtcOffset::east_hours(10)),
            ),
            data: None,
        };
        assert!(!inv1.validate());

        let val3 = Value {
            pv: PartialValue::DateTime(OffsetDateTime::now_utc()),
            data: None,
        };
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

        assert!(!inv1.validate());
        assert!(!inv2.validate());
        assert!(val1.validate());
        assert!(val2.validate());
        assert!(val3.validate());
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

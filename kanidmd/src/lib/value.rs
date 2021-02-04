use crate::be::dbvalue::{DbCidV1, DbValueCredV1, DbValueTaggedStringV1, DbValueV1};
use crate::credential::Credential;
use crate::repl::cid::Cid;
use kanidm_proto::v1::Filter as ProtoFilter;

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;
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
        Regex::new("^((\\.|_).*|.*(\\s|@|,|/|\\\\|=).*|\\d+|root|nobody|nogroup|wheel|sshd|shadow|systemd.*)$").expect("Invalid Iname regex found")
        //            ^      ^                          ^   ^
        //            |      |                          |   \- must not be a reserved name.
        //            |      |                          \- must not be only integers
        //            |      \- must not contain whitespace, @, ',', /, \, =
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
    EQUALITY,
    PRESENCE,
    SUBSTRING,
}

impl TryFrom<&str> for IndexType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let n_value = value.to_uppercase();
        match n_value.as_str() {
            "EQUALITY" => Ok(IndexType::EQUALITY),
            "PRESENCE" => Ok(IndexType::PRESENCE),
            "SUBSTRING" => Ok(IndexType::SUBSTRING),
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
            0 => Ok(IndexType::EQUALITY),
            1 => Ok(IndexType::PRESENCE),
            2 => Ok(IndexType::SUBSTRING),
            _ => Err(()),
        }
    }
}

impl IndexType {
    pub fn as_idx_str(&self) -> &str {
        match self {
            IndexType::EQUALITY => "eq",
            IndexType::PRESENCE => "pres",
            IndexType::SUBSTRING => "sub",
        }
    }

    pub fn to_usize(&self) -> usize {
        match self {
            IndexType::EQUALITY => 0,
            IndexType::PRESENCE => 1,
            IndexType::SUBSTRING => 2,
        }
    }
}

impl fmt::Display for IndexType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                IndexType::EQUALITY => "EQUALITY",
                IndexType::PRESENCE => "PRESENCE",
                IndexType::SUBSTRING => "SUBSTRING",
            }
        )
    }
}

#[allow(non_camel_case_types)]
#[derive(Hash, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum SyntaxType {
    // We need an insensitive string type too ...
    // We also need to "self host" a syntax type, and index type
    UTF8STRING,
    UTF8STRING_INSENSITIVE,
    UTF8STRING_INAME,
    UUID,
    BOOLEAN,
    SYNTAX_ID,
    INDEX_ID,
    REFERENCE_UUID,
    JSON_FILTER,
    CREDENTIAL,
    RADIUS_UTF8STRING,
    SSHKEY,
    SERVICE_PRINCIPLE_NAME,
    UINT32,
    CID,
    NSUNIQUEID,
    DATETIME,
}

impl TryFrom<&str> for SyntaxType {
    type Error = ();

    fn try_from(value: &str) -> Result<SyntaxType, Self::Error> {
        let n_value = value.to_uppercase();
        match n_value.as_str() {
            "UTF8STRING" => Ok(SyntaxType::UTF8STRING),
            "UTF8STRING_INSENSITIVE" => Ok(SyntaxType::UTF8STRING_INSENSITIVE),
            "UTF8STRING_INAME" => Ok(SyntaxType::UTF8STRING_INAME),
            "UUID" => Ok(SyntaxType::UUID),
            "BOOLEAN" => Ok(SyntaxType::BOOLEAN),
            "SYNTAX_ID" => Ok(SyntaxType::SYNTAX_ID),
            "INDEX_ID" => Ok(SyntaxType::INDEX_ID),
            "REFERENCE_UUID" => Ok(SyntaxType::REFERENCE_UUID),
            "JSON_FILTER" => Ok(SyntaxType::JSON_FILTER),
            "CREDENTIAL" => Ok(SyntaxType::CREDENTIAL),
            "RADIUS_UTF8STRING" => Ok(SyntaxType::RADIUS_UTF8STRING),
            "SSHKEY" => Ok(SyntaxType::SSHKEY),
            "SERVICE_PRINCIPLE_NAME" => Ok(SyntaxType::SERVICE_PRINCIPLE_NAME),
            "UINT32" => Ok(SyntaxType::UINT32),
            "CID" => Ok(SyntaxType::CID),
            "NSUNIQUEID" => Ok(SyntaxType::NSUNIQUEID),
            "DATETIME" => Ok(SyntaxType::DATETIME),
            _ => Err(()),
        }
    }
}

impl TryFrom<usize> for SyntaxType {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SyntaxType::UTF8STRING),
            1 => Ok(SyntaxType::UTF8STRING_INSENSITIVE),
            2 => Ok(SyntaxType::UUID),
            3 => Ok(SyntaxType::BOOLEAN),
            4 => Ok(SyntaxType::SYNTAX_ID),
            5 => Ok(SyntaxType::INDEX_ID),
            6 => Ok(SyntaxType::REFERENCE_UUID),
            7 => Ok(SyntaxType::JSON_FILTER),
            8 => Ok(SyntaxType::CREDENTIAL),
            9 => Ok(SyntaxType::RADIUS_UTF8STRING),
            10 => Ok(SyntaxType::SSHKEY),
            11 => Ok(SyntaxType::SERVICE_PRINCIPLE_NAME),
            12 => Ok(SyntaxType::UINT32),
            13 => Ok(SyntaxType::CID),
            14 => Ok(SyntaxType::UTF8STRING_INAME),
            15 => Ok(SyntaxType::NSUNIQUEID),
            16 => Ok(SyntaxType::DATETIME),
            _ => Err(()),
        }
    }
}

impl SyntaxType {
    pub fn to_usize(&self) -> usize {
        match self {
            SyntaxType::UTF8STRING => 0,
            SyntaxType::UTF8STRING_INSENSITIVE => 1,
            SyntaxType::UUID => 2,
            SyntaxType::BOOLEAN => 3,
            SyntaxType::SYNTAX_ID => 4,
            SyntaxType::INDEX_ID => 5,
            SyntaxType::REFERENCE_UUID => 6,
            SyntaxType::JSON_FILTER => 7,
            SyntaxType::CREDENTIAL => 8,
            SyntaxType::RADIUS_UTF8STRING => 9,
            SyntaxType::SSHKEY => 10,
            SyntaxType::SERVICE_PRINCIPLE_NAME => 11,
            SyntaxType::UINT32 => 12,
            SyntaxType::CID => 13,
            SyntaxType::UTF8STRING_INAME => 14,
            SyntaxType::NSUNIQUEID => 15,
            SyntaxType::DATETIME => 16,
        }
    }
}

impl fmt::Display for SyntaxType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SyntaxType::UTF8STRING => "UTF8STRING",
                SyntaxType::UTF8STRING_INSENSITIVE => "UTF8STRING_INSENSITIVE",
                SyntaxType::UTF8STRING_INAME => "UTF8STRING_INAME",
                SyntaxType::UUID => "UUID",
                SyntaxType::BOOLEAN => "BOOLEAN",
                SyntaxType::SYNTAX_ID => "SYNTAX_ID",
                SyntaxType::INDEX_ID => "INDEX_ID",
                SyntaxType::REFERENCE_UUID => "REFERENCE_UUID",
                SyntaxType::JSON_FILTER => "JSON_FILTER",
                SyntaxType::CREDENTIAL => "CREDENTIAL",
                SyntaxType::RADIUS_UTF8STRING => "RADIUS_UTF8STRING",
                SyntaxType::SSHKEY => "SSHKEY",
                SyntaxType::SERVICE_PRINCIPLE_NAME => "SERVICE_PRINCIPLE_NAME",
                SyntaxType::UINT32 => "UINT32",
                SyntaxType::CID => "CID",
                SyntaxType::NSUNIQUEID => "NSUNIQUEID",
                SyntaxType::DATETIME => "DATETIME",
            }
        )
    }
}

#[derive(Clone)]
pub enum DataValue {
    Cred(Credential),
    SshKey(String),
    RadiusCred(String),
}

impl std::fmt::Debug for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DataValue::Cred(_) => write!(f, "DataValue::Cred(_)"),
            DataValue::SshKey(_) => write!(f, "DataValue::SshKey(_)"),
            DataValue::RadiusCred(_) => write!(f, "DataValue::RadiusCred(_)"),
        }
    }
}

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
    RadiusCred,
    Spn(String, String),
    Uint32(u32),
    Cid(Cid),
    Nsuniqueid(String),
    DateTime(OffsetDateTime),
}

impl PartialValue {
    pub fn new_utf8(s: String) -> Self {
        PartialValue::Utf8(s)
    }

    pub fn new_utf8s(s: &str) -> Self {
        PartialValue::Utf8(s.to_string())
    }

    pub fn is_utf8(&self) -> bool {
        match self {
            PartialValue::Utf8(_) => true,
            _ => false,
        }
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
        match self {
            PartialValue::Iutf8(_) => true,
            _ => false,
        }
    }

    pub fn is_iname(&self) -> bool {
        match self {
            PartialValue::Iname(_) => true,
            _ => false,
        }
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
        match self {
            PartialValue::Bool(_) => true,
            _ => false,
        }
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
        match self {
            PartialValue::Uuid(_) => true,
            _ => false,
        }
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
        match self {
            PartialValue::Refer(_) => true,
            _ => false,
        }
    }

    pub fn new_indexs(s: &str) -> Option<Self> {
        let i = match IndexType::try_from(s) {
            Ok(i) => i,
            Err(_) => return None,
        };
        Some(PartialValue::Index(i))
    }

    pub fn is_index(&self) -> bool {
        match self {
            PartialValue::Index(_) => true,
            _ => false,
        }
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        let i = match SyntaxType::try_from(s) {
            Ok(i) => i,
            Err(_) => return None,
        };
        Some(PartialValue::Syntax(i))
    }

    pub fn is_syntax(&self) -> bool {
        match self {
            PartialValue::Syntax(_) => true,
            _ => false,
        }
    }

    pub fn new_json_filter(s: &str) -> Option<Self> {
        let pf: ProtoFilter = match serde_json::from_str(s) {
            Ok(pf) => pf,
            Err(_) => return None,
        };
        Some(PartialValue::JsonFilt(pf))
    }

    pub fn is_json_filter(&self) -> bool {
        match self {
            PartialValue::JsonFilt(_) => true,
            _ => false,
        }
    }

    pub fn new_credential_tag(s: &str) -> Self {
        PartialValue::Cred(s.to_lowercase())
    }

    pub fn is_credential(&self) -> bool {
        match self {
            PartialValue::Cred(_) => true,
            _ => false,
        }
    }

    pub fn new_radius_string() -> Self {
        PartialValue::RadiusCred
    }

    pub fn is_radius_string(&self) -> bool {
        match self {
            PartialValue::RadiusCred => true,
            _ => false,
        }
    }

    pub fn new_sshkey_tag(s: String) -> Self {
        PartialValue::SshKey(s)
    }

    pub fn new_sshkey_tag_s(s: &str) -> Self {
        PartialValue::SshKey(s.to_string())
    }

    pub fn is_sshkey(&self) -> bool {
        match self {
            PartialValue::SshKey(_) => true,
            _ => false,
        }
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
        match self {
            PartialValue::Spn(_, _) => true,
            _ => false,
        }
    }

    pub fn new_uint32(u: u32) -> Self {
        PartialValue::Uint32(u)
    }

    pub fn new_uint32_str(u: &str) -> Option<Self> {
        u32::from_str_radix(u, 10).ok().map(PartialValue::Uint32)
    }

    pub fn is_uint32(&self) -> bool {
        match self {
            PartialValue::Uint32(_) => true,
            _ => false,
        }
    }

    pub fn new_cid(c: Cid) -> Self {
        PartialValue::Cid(c)
    }

    pub fn new_cid_s(_c: &str) -> Option<Self> {
        None
    }

    pub fn is_cid(&self) -> bool {
        match self {
            PartialValue::Cid(_) => true,
            _ => false,
        }
    }

    pub fn new_nsuniqueid_s(s: &str) -> Self {
        PartialValue::Nsuniqueid(s.to_lowercase())
    }

    pub fn is_nsuniqueid(&self) -> bool {
        match self {
            PartialValue::Nsuniqueid(_) => true,
            _ => false,
        }
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
        match self {
            PartialValue::DateTime(_) => true,
            _ => false,
        }
    }

    pub fn to_str(&self) -> Option<&str> {
        match self {
            PartialValue::Utf8(s) => Some(s.as_str()),
            PartialValue::Iutf8(s) => Some(s.as_str()),
            PartialValue::Iname(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn contains(&self, s: &PartialValue) -> bool {
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
            | PartialValue::Nsuniqueid(s) => s.clone(),
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
            PartialValue::RadiusCred => "_".to_string(),
            PartialValue::SshKey(tag) => tag.to_string(),
            PartialValue::Spn(name, realm) => format!("{}@{}", name, realm),
            PartialValue::Uint32(u) => u.to_string(),
            // This will never work, we don't allow equality searching on Cid's
            PartialValue::Cid(_) => "_".to_string(),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            }
        }
    }

    pub fn get_idx_sub_key(&self) -> String {
        unimplemented!();
    }
}

#[derive(Clone, Debug)]
pub struct Value {
    pv: PartialValue,
    // Later we'll add extra data fields for different v types. They'll have to switch on
    // pv somehow, so probably need optional or union?
    data: Option<Box<DataValue>>,
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
        match self.pv {
            PartialValue::Utf8(_) => true,
            _ => false,
        }
    }

    pub fn new_iutf8(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iutf8(s),
            data: None,
        }
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        match self.pv {
            PartialValue::Iutf8(_) => true,
            _ => false,
        }
    }

    pub fn new_iname(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iname(s),
            data: None,
        }
    }

    pub fn is_iname(&self) -> bool {
        match self.pv {
            PartialValue::Iname(_) => true,
            _ => false,
        }
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
        match self.pv {
            PartialValue::Uuid(_) => true,
            _ => false,
        }
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
        match self.pv {
            PartialValue::Bool(_) => true,
            _ => false,
        }
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_syntaxs(s)?,
            data: None,
        })
    }

    pub fn is_syntax(&self) -> bool {
        match self.pv {
            PartialValue::Syntax(_) => true,
            _ => false,
        }
    }

    pub fn new_indexs(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_indexs(s)?,
            data: None,
        })
    }

    pub fn is_index(&self) -> bool {
        match self.pv {
            PartialValue::Index(_) => true,
            _ => false,
        }
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
        match self.pv {
            PartialValue::Refer(_) => true,
            _ => false,
        }
    }

    pub fn new_json_filter(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_json_filter(s)?,
            data: None,
        })
    }

    pub fn is_json_filter(&self) -> bool {
        match self.pv {
            PartialValue::JsonFilt(_) => true,
            _ => false,
        }
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
        match &self.pv {
            PartialValue::Cred(_) => true,
            _ => false,
        }
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

    pub fn new_radius_str(cleartext: &str) -> Self {
        Value {
            pv: PartialValue::new_radius_string(),
            data: Some(Box::new(DataValue::RadiusCred(cleartext.to_string()))),
        }
    }

    pub fn is_radius_string(&self) -> bool {
        match &self.pv {
            PartialValue::RadiusCred => true,
            _ => false,
        }
    }

    pub fn get_radius_secret(&self) -> Option<&str> {
        match &self.pv {
            PartialValue::RadiusCred => match &self.data {
                Some(dv) => match dv.as_ref() {
                    DataValue::RadiusCred(c) => Some(c.as_str()),
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
        match &self.pv {
            PartialValue::SshKey(_) => true,
            _ => false,
        }
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
        match &self.pv {
            PartialValue::Spn(_, _) => true,
            _ => false,
        }
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
        match &self.pv {
            PartialValue::Uint32(_) => true,
            _ => false,
        }
    }

    pub fn new_cid(c: Cid) -> Self {
        Value {
            pv: PartialValue::new_cid(c),
            data: None,
        }
    }

    pub fn is_cid(&self) -> bool {
        match &self.pv {
            PartialValue::Cid(_) => true,
            _ => false,
        }
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

    pub fn contains(&self, s: &PartialValue) -> bool {
        self.pv.contains(s)
    }

    pub fn lessthan(&self, s: &PartialValue) -> bool {
        self.pv.lessthan(s)
    }

    // Converters between DBRepr -> MemRepr. It's likely many of these
    // will be just wrappers to our from str types.

    // Keep this updated with DbValueV1 in be::dbvalue.
    pub(crate) fn from_db_valuev1(v: DbValueV1) -> Result<Self, ()> {
        match v {
            DbValueV1::U8(s) => Ok(Value {
                pv: PartialValue::Utf8(s),
                data: None,
            }),
            DbValueV1::I8(s) => {
                Ok(Value {
                    // TODO: Should we be lowercasing here? The dbv should be normalised
                    // already, but is there a risk of corruption/tampering if we don't touch this?
                    pv: PartialValue::Iutf8(s.to_lowercase()),
                    data: None,
                })
            }
            DbValueV1::N8(s) => Ok(Value {
                pv: PartialValue::Iname(s.to_lowercase()),
                data: None,
            }),
            DbValueV1::UU(u) => Ok(Value {
                pv: PartialValue::Uuid(u),
                data: None,
            }),
            DbValueV1::BO(b) => Ok(Value {
                pv: PartialValue::Bool(b),
                data: None,
            }),
            DbValueV1::SY(us) => Ok(Value {
                pv: PartialValue::Syntax(SyntaxType::try_from(us)?),
                data: None,
            }),
            DbValueV1::IN(us) => Ok(Value {
                pv: PartialValue::Index(IndexType::try_from(us)?),
                data: None,
            }),
            DbValueV1::RF(u) => Ok(Value {
                pv: PartialValue::Refer(u),
                data: None,
            }),
            DbValueV1::JF(s) => Ok(Value {
                pv: match PartialValue::new_json_filter(s.as_str()) {
                    Some(pv) => pv,
                    None => return Err(()),
                },
                data: None,
            }),
            DbValueV1::CR(dvc) => {
                // Deserialise the db cred here.
                Ok(Value {
                    pv: PartialValue::Cred(dvc.t.to_lowercase()),
                    data: Some(Box::new(DataValue::Cred(Credential::try_from(dvc.d)?))),
                })
            }
            DbValueV1::RU(d) => Ok(Value {
                pv: PartialValue::RadiusCred,
                data: Some(Box::new(DataValue::RadiusCred(d))),
            }),
            DbValueV1::SK(ts) => Ok(Value {
                pv: PartialValue::SshKey(ts.t),
                data: Some(Box::new(DataValue::SshKey(ts.d))),
            }),
            DbValueV1::SP(n, r) => Ok(Value {
                pv: PartialValue::Spn(n, r),
                data: None,
            }),
            DbValueV1::UI(u) => Ok(Value {
                pv: PartialValue::Uint32(u),
                data: None,
            }),
            DbValueV1::CI(dc) => Ok(Value {
                pv: PartialValue::Cid(Cid {
                    ts: dc.t,
                    d_uuid: dc.d,
                    s_uuid: dc.s,
                }),
                data: None,
            }),
            DbValueV1::NU(s) => Ok(Value {
                pv: PartialValue::Nsuniqueid(s),
                data: None,
            }),
            DbValueV1::DT(s) => PartialValue::new_datetime_s(&s)
                .ok_or(())
                .map(|pv| Value { pv, data: None }),
        }
    }

    #[allow(clippy::unreachable)]
    #[allow(clippy::expect_used)]
    pub(crate) fn to_db_valuev1(&self) -> DbValueV1 {
        // This has to clone due to how the backend works.
        match &self.pv {
            PartialValue::Utf8(s) => DbValueV1::U8(s.clone()),
            PartialValue::Iutf8(s) => DbValueV1::I8(s.clone()),
            PartialValue::Iname(s) => DbValueV1::N8(s.clone()),
            PartialValue::Uuid(u) => DbValueV1::UU(*u),
            PartialValue::Bool(b) => DbValueV1::BO(*b),
            PartialValue::Syntax(syn) => DbValueV1::SY(syn.to_usize()),
            PartialValue::Index(it) => DbValueV1::IN(it.to_usize()),
            PartialValue::Refer(u) => DbValueV1::RF(*u),
            PartialValue::JsonFilt(s) => DbValueV1::JF(
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
                DbValueV1::CR(DbValueCredV1 {
                    t: tag.clone(),
                    d: c.to_db_valuev1(),
                })
            }
            PartialValue::RadiusCred => {
                let ru = match &self.data {
                    Some(v) => match v.as_ref() {
                        DataValue::RadiusCred(rc) => rc.clone(),
                        _ => unreachable!(),
                    },
                    None => unreachable!(),
                };
                DbValueV1::RU(ru)
            }
            PartialValue::SshKey(t) => {
                let sk = match &self.data {
                    Some(v) => match v.as_ref() {
                        DataValue::SshKey(sc) => sc.clone(),
                        _ => unreachable!(),
                    },
                    None => unreachable!(),
                };
                DbValueV1::SK(DbValueTaggedStringV1 {
                    t: t.clone(),
                    d: sk,
                })
            }
            PartialValue::Spn(n, r) => DbValueV1::SP(n.clone(), r.clone()),
            PartialValue::Uint32(u) => DbValueV1::UI(*u),
            PartialValue::Cid(c) => DbValueV1::CI(DbCidV1 {
                d: c.d_uuid,
                s: c.s_uuid,
                t: c.ts,
            }),
            PartialValue::Nsuniqueid(s) => DbValueV1::NU(s.clone()),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                DbValueV1::DT(odt.format(time::Format::Rfc3339))
            }
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
            | PartialValue::Nsuniqueid(s) => s.clone(),
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
            // We don't disclose the radius credential unless by special
            // interfaces.
            PartialValue::RadiusCred => "radius".to_string(),
            PartialValue::Spn(n, r) => format!("{}@{}", n, r),
            PartialValue::Uint32(u) => u.to_string(),
            PartialValue::Cid(c) => format!("{:?}_{}_{}", c.ts, c.d_uuid, c.s_uuid),
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            }
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
                Some(v) => match v.as_ref() {
                    DataValue::Cred(_) => true,
                    _ => false,
                },
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
            PartialValue::RadiusCred => match &self.data {
                Some(v) => match v.as_ref() {
                    DataValue::RadiusCred(_) => true,
                    _ => false,
                },
                None => false,
            },
            PartialValue::Nsuniqueid(s) => NSUNIQUEID_RE.is_match(s),
            PartialValue::DateTime(odt) => odt.offset() == time::UtcOffset::UTC,
            _ => true,
        }
    }

    pub fn generate_idx_eq_keys(&self) -> Vec<String> {
        #[allow(clippy::expect_used)]
        match &self.pv {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            | PartialValue::Nsuniqueid(s) => vec![s.clone()],
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
            PartialValue::RadiusCred => vec![],
            PartialValue::Spn(n, r) => vec![format!("{}@{}", n, r)],
            PartialValue::Uint32(u) => vec![u.to_string()],
            PartialValue::Cid(_) => vec![],
            PartialValue::DateTime(odt) => {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                vec![odt.format(time::Format::Rfc3339)]
            }
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
        assert_eq!(r1, Ok(IndexType::EQUALITY));

        let r2 = IndexType::try_from("PRESENCE");
        assert_eq!(r2, Ok(IndexType::PRESENCE));

        let r3 = IndexType::try_from("SUBSTRING");
        assert_eq!(r3, Ok(IndexType::SUBSTRING));

        let r4 = IndexType::try_from("thaoeusaneuh");
        assert_eq!(r4, Err(()));
    }

    #[test]
    fn test_value_syntax_tryfrom() {
        let r1 = SyntaxType::try_from("UTF8STRING");
        assert_eq!(r1, Ok(SyntaxType::UTF8STRING));

        let r2 = SyntaxType::try_from("UTF8STRING_INSENSITIVE");
        assert_eq!(r2, Ok(SyntaxType::UTF8STRING_INSENSITIVE));

        let r3 = SyntaxType::try_from("BOOLEAN");
        assert_eq!(r3, Ok(SyntaxType::BOOLEAN));

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
            index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
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
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UUID,
        };
        let u1 = String::from("936DA01F9ABD4d9d80C702AF85C822A8");

        let un1 = sa.normalise_value(&u1);
        assert_eq!(un1, "936da01f-9abd-4d9d-80c7-02af85c822a8");
    }
    */
}

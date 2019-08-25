use crate::be::dbvalue::DbValueV1;
use crate::proto::v1::Filter as ProtoFilter;

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::str::FromStr;
use uuid::Uuid;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum IndexType {
    EQUALITY,
    PRESENCE,
    SUBSTRING,
}

impl TryFrom<&str> for IndexType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value == "EQUALITY" {
            Ok(IndexType::EQUALITY)
        } else if value == "PRESENCE" {
            Ok(IndexType::PRESENCE)
        } else if value == "SUBSTRING" {
            Ok(IndexType::SUBSTRING)
        } else {
            Err(())
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
    pub fn to_string(&self) -> String {
        String::from(match self {
            IndexType::EQUALITY => "EQUALITY",
            IndexType::PRESENCE => "PRESENCE",
            IndexType::SUBSTRING => "SUBSTRING",
        })
    }

    pub fn to_usize(&self) -> usize {
        match self {
            IndexType::EQUALITY => 0,
            IndexType::PRESENCE => 1,
            IndexType::SUBSTRING => 2,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum SyntaxType {
    // We need an insensitive string type too ...
    // We also need to "self host" a syntax type, and index type
    UTF8STRING,
    UTF8STRING_INSENSITIVE,
    UUID,
    BOOLEAN,
    SYNTAX_ID,
    INDEX_ID,
    REFERENCE_UUID,
    JSON_FILTER,
}

impl TryFrom<&str> for SyntaxType {
    type Error = ();

    fn try_from(value: &str) -> Result<SyntaxType, Self::Error> {
        if value == "UTF8STRING" {
            Ok(SyntaxType::UTF8STRING)
        } else if value == "UTF8STRING_INSENSITIVE" {
            Ok(SyntaxType::UTF8STRING_INSENSITIVE)
        } else if value == "UUID" {
            Ok(SyntaxType::UUID)
        } else if value == "BOOLEAN" {
            Ok(SyntaxType::BOOLEAN)
        } else if value == "SYNTAX_ID" {
            Ok(SyntaxType::SYNTAX_ID)
        } else if value == "INDEX_ID" {
            Ok(SyntaxType::INDEX_ID)
        } else if value == "REFERENCE_UUID" {
            Ok(SyntaxType::REFERENCE_UUID)
        } else if value == "JSON_FILTER" {
            Ok(SyntaxType::JSON_FILTER)
        } else {
            Err(())
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
            _ => Err(()),
        }
    }
}

impl SyntaxType {
    pub fn to_string(&self) -> String {
        String::from(match self {
            SyntaxType::UTF8STRING => "UTF8STRING",
            SyntaxType::UTF8STRING_INSENSITIVE => "UTF8STRING_INSENSITIVE",
            SyntaxType::UUID => "UUID",
            SyntaxType::BOOLEAN => "BOOLEAN",
            SyntaxType::SYNTAX_ID => "SYNTAX_ID",
            SyntaxType::INDEX_ID => "INDEX_ID",
            SyntaxType::REFERENCE_UUID => "REFERENCE_UUID",
            SyntaxType::JSON_FILTER => "JSON_FILTER",
        })
    }

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
        }
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Deserialize, Serialize)]
pub enum PartialValue {
    Utf8(String),
    Iutf8(String),
    Uuid(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    // Does this make sense?
    // TODO: We'll probably add tagging to this type for the partial matching
    JsonFilt(ProtoFilter),
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

    pub fn new_iutf8s(s: &str) -> Self {
        PartialValue::Iutf8(s.to_lowercase())
    }

    #[inline]
    pub fn new_class(s: &str) -> Self {
        PartialValue::new_iutf8s(s)
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
        PartialValue::Uuid(u.clone())
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
        PartialValue::Refer(u.clone())
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

    pub fn to_str(&self) -> Option<&str> {
        match self {
            PartialValue::Utf8(s) => Some(s.as_str()),
            PartialValue::Iutf8(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_str_unwrap(&self) -> &str {
        self.to_str().expect("An invalid value was returned!!!")
    }

    pub fn contains(&self, _s: &PartialValue) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct Value {
    pv: PartialValue,
    // Later we'll add extra data fields for different v types. They'll have to switch on
    // pv somehow, so probably need optional or union?
}

// TODO: Impl display

// Need new_<type> -> Result<_, _>
// Need from_db_value
// Need to_db_value
// Need to_string for most types.

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value {
            pv: PartialValue::Bool(b),
        }
    }
}

impl From<&bool> for Value {
    fn from(b: &bool) -> Self {
        Value {
            pv: PartialValue::Bool(*b),
        }
    }
}

impl From<SyntaxType> for Value {
    fn from(s: SyntaxType) -> Self {
        Value {
            pv: PartialValue::Syntax(s),
        }
    }
}

impl From<IndexType> for Value {
    fn from(i: IndexType) -> Self {
        Value {
            pv: PartialValue::Index(i),
        }
    }
}

// Because these are potentially ambiguous, we limit them to tests where we can contain
// any....mistakes.
#[cfg(test)]
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        // Fuzzy match for uuid's
        // TODO: Will I regret this?
        match Uuid::parse_str(s) {
            Ok(u) => Value {
                pv: PartialValue::Uuid(u),
            },
            Err(_) => Value {
                pv: PartialValue::Utf8(s.to_string()),
            },
        }
    }
}

#[cfg(test)]
impl From<&Uuid> for Value {
    fn from(u: &Uuid) -> Self {
        Value {
            pv: PartialValue::Uuid(u.clone()),
        }
    }
}

#[cfg(test)]
impl From<Uuid> for Value {
    fn from(u: Uuid) -> Self {
        Value {
            pv: PartialValue::Uuid(u),
        }
    }
}

impl Value {
    // I get the feeling this will have a lot of matching ... sigh.
    pub fn new_utf8(s: String) -> Self {
        Value {
            pv: PartialValue::new_utf8(s),
        }
    }

    pub fn new_utf8s(s: &str) -> Self {
        Value {
            pv: PartialValue::new_utf8s(s),
        }
    }

    pub fn is_utf8(&self) -> bool {
        match self.pv {
            PartialValue::Utf8(_) => true,
            _ => false,
        }
    }

    pub fn new_iutf8(s: String) -> Self {
        Value {
            pv: PartialValue::new_iutf8s(s.as_str()),
        }
    }

    pub fn new_iutf8s(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iutf8s(s),
        }
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        match self.pv {
            PartialValue::Iutf8(_) => true,
            _ => false,
        }
    }

    pub fn new_uuid(u: Uuid) -> Self {
        Value {
            pv: PartialValue::new_uuid(u),
        }
    }

    pub fn new_uuids(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_uuids(s)?,
        })
    }

    pub fn new_uuidr(u: &Uuid) -> Self {
        Value {
            pv: PartialValue::new_uuidr(u),
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
            pv: PartialValue::new_iutf8s(s),
        }
    }

    pub fn new_attr(s: &str) -> Self {
        Value {
            pv: PartialValue::new_iutf8s(s),
        }
    }

    pub fn new_bool(b: bool) -> Self {
        Value {
            pv: PartialValue::new_bool(b),
        }
    }

    pub fn new_bools(s: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_bools(s)?,
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
        }
    }

    pub fn new_refer_r(u: &Uuid) -> Self {
        Value {
            pv: PartialValue::new_refer_r(u),
        }
    }

    pub fn new_refer_s(us: &str) -> Option<Self> {
        Some(Value {
            pv: PartialValue::new_refer_s(us)?,
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

    pub fn contains(&self, s: &PartialValue) -> bool {
        self.pv.contains(s)
    }

    // Converters between DBRepr -> MemRepr. It's likely many of these
    // will be just wrappers to our from str types.

    // Keep this updated with DbValueV1 in be::dbvalue.
    pub(crate) fn from_db_valuev1(v: DbValueV1) -> Result<Self, ()> {
        // TODO: Should this actually take ownership? Or do we clone?
        match v {
            DbValueV1::U8(s) => Ok(Value {
                pv: PartialValue::Utf8(s),
            }),
            DbValueV1::I8(s) => {
                Ok(Value {
                    // TODO: Should we be lowercasing here? The dbv should be normalised
                    // already, but is there a risk of corruption/tampering if we don't touch this?
                    pv: PartialValue::Iutf8(s.to_lowercase()),
                })
            }
            DbValueV1::UU(u) => Ok(Value {
                pv: PartialValue::Uuid(u),
            }),
            DbValueV1::BO(b) => Ok(Value {
                pv: PartialValue::Bool(b),
            }),
            DbValueV1::SY(us) => Ok(Value {
                pv: PartialValue::Syntax(SyntaxType::try_from(us)?),
            }),
            DbValueV1::IN(us) => Ok(Value {
                pv: PartialValue::Index(IndexType::try_from(us)?),
            }),
            DbValueV1::RF(u) => Ok(Value {
                pv: PartialValue::Refer(u),
            }),
            DbValueV1::JF(s) => Ok(Value {
                pv: match PartialValue::new_json_filter(s.as_str()) {
                    Some(pv) => pv,
                    None => return Err(()),
                },
            }),
        }
    }

    pub(crate) fn to_db_valuev1(&self) -> DbValueV1 {
        // TODO: Should this actually take ownership? Or do we clone?
        match &self.pv {
            PartialValue::Utf8(s) => DbValueV1::U8(s.clone()),
            PartialValue::Iutf8(s) => DbValueV1::I8(s.clone()),
            PartialValue::Uuid(u) => DbValueV1::UU(u.clone()),
            PartialValue::Bool(b) => DbValueV1::BO(b.clone()),
            PartialValue::Syntax(syn) => DbValueV1::SY(syn.to_usize()),
            PartialValue::Index(it) => DbValueV1::IN(it.to_usize()),
            PartialValue::Refer(u) => DbValueV1::RF(u.clone()),
            PartialValue::JsonFilt(s) => DbValueV1::JF(
                serde_json::to_string(s)
                    .expect("A json filter value was corrupted during run-time"),
            ),
        }
    }

    /// Convert to a proto/public value that can be read and consumed.
    pub(crate) fn to_proto_string_clone(&self) -> String {
        unimplemented!();
    }

    pub fn to_str(&self) -> Option<&str> {
        match &self.pv {
            PartialValue::Utf8(s) => Some(s.as_str()),
            PartialValue::Iutf8(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_str_unwrap(&self) -> &str {
        self.to_str().expect("An invalid value was returned!!!")
    }

    pub fn as_string(&self) -> Option<&String> {
        match &self.pv {
            PartialValue::Utf8(s) => Some(s),
            PartialValue::Iutf8(s) => Some(s),
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

    pub fn to_partialvalue(&self) -> PartialValue {
        // Match on self to become a partialvalue.
        self.pv.clone()
    }

    pub fn validate(&self) -> bool {
        // Validate that extra-data constraints on the type exist and are
        // valid. IE json filter is really a filter, or cred types have supplemental
        // data.
        unimplemented!()
    }
}

impl Borrow<PartialValue> for Value {
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

    /*
    #[test]
    fn test_schema_syntax_json_filter() {
        let sa = SchemaAttribute {
            name: String::from("acp_receiver"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_RECEIVER)
                .expect("unable to parse static uuid"),
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
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UUID).expect("unable to parse static uuid"),
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

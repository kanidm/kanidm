use crate::audit::AuditScope;
use crate::be::dbvalue::DbValueV1;
use crate::error::OperationError;
use crate::server::QueryServerWriteTransaction;

use std::borrow::Borrow;
use std::convert::TryFrom;
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

    fn try_from(value: &str) -> Result<IndexType, Self::Error> {
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

impl IndexType {
    pub fn to_string(&self) -> String {
        String::from(match self {
            IndexType::EQUALITY => "EQUALITY",
            IndexType::PRESENCE => "PRESENCE",
            IndexType::SUBSTRING => "SUBSTRING",
        })
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
}

#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Deserialize, Serialize)]
pub(crate) enum PartialValue {
    Utf8(String),
    Iutf8(String),
    Uuid(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    // Does this make sense?
    // TODO: We'll probably add tagging to this type for the partial matching
    JsonFilt(String),
}

impl PartialValue {
    pub fn new_utf8(s: String) -> Self {
        PartialValue::Utf8(s)
    }

    pub fn new_utf8s(s: &str) -> Self {
        PartialValue::Utf8(s.to_string())
    }

    pub fn new_iutf8(s: &str) -> Self {
        PartialValue::Iutf8(s.to_lowercase())
    }

    #[inline]
    pub fn new_class(s: &str) -> Self {
        PartialValue::new_iutf8(s)
    }

    pub fn new_uuid(u: Uuid) -> Self {
        PartialValue::Uuid(u)
    }

    pub fn new_uuids(us: &str) -> Option<Self> {
        match Uuid::parse_str(us.as_str()) {
            Ok(u) => Some(PartialValue::Uuid(u)),
            Err(_) => None,
        }
    }

    pub fn new_refer(u: Uuid) -> Self {
        PartialValue::Refer(u)
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
}

// TODO: Store everything as partialValue and then have a extra ref to extra data
// for that type as needed?
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub(crate) enum Value {
    Utf8(String),
    Iutf8(String),
    Uuid(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    JsonFilt(String),
}

// TODO: Impl display

// Need new_<type> -> Result<_, _>
// Need from_db_value
// Need to_db_value
// Need to_string for most types.

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

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::from(s.as_str())
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        // Fuzzy match for uuid's
        // TODO: Will I regret this?
        match Uuid::parse_str(s) {
            Ok(u) => Value::Uuid(u),
            Err(_) => Value::Utf8(s.to_string()),
        }
    }
}

impl From<&Uuid> for Value {
    fn from(u: &Uuid) -> Self {
        Value::Uuid(u.clone())
    }
}

impl From<Uuid> for Value {
    fn from(u: Uuid) -> Self {
        Value::Uuid(u)
    }
}

impl From<SyntaxType> for Value {
    fn from(s: SyntaxType) -> Self {
        Value::Syntax(s)
    }
}

impl From<&SyntaxType> for Value {
    fn from(s: &SyntaxType) -> Self {
        Value::Syntax(s.clone())
    }
}

impl From<IndexType> for Value {
    fn from(i: IndexType) -> Self {
        Value::Index(i)
    }
}

impl From<&IndexType> for Value {
    fn from(i: &IndexType) -> Self {
        Value::Index(i.clone())
    }
}

impl Value {
    pub fn from_attr(
        audit: &AuditScope,
        qs: &QueryServerWriteTransaction,
        attr: &String,
        value: &String,
    ) -> Result<Self, OperationError> {
        unimplemented!();
    }

    // I get the feeling this will have a lot of matching ... sigh.
    fn new_utf8(s: String) -> Self {
        Value::Utf8(s)
    }

    pub fn new_insensitive_utf8(s: String) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        match self {
            Value::Iutf8(_) => true,
            _ => false,
        }
    }

    fn new_uuid(s: &String) -> Option<Self> {
        match Uuid::parse_str(s.as_str()) {
            Ok(u) => Some(Value::Uuid(u)),
            Err(_) => None,
        }
    }

    // Is this correct? Should ref be seperate?
    pub fn is_uuid(&self) -> bool {
        match self {
            Value::Uuid(_) => true,
            Value::Refer(_) => true,
            _ => false,
        }
    }

    pub fn new_class(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn new_attr(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    fn new_bool(s: &String) -> Option<Self> {
        unimplemented!();
    }

    #[inline]
    pub fn is_bool(&self) -> bool {
        match self {
            Value::Bool(_) => true,
            _ => false,
        }
    }

    fn new_syntax(s: &String) -> Option<Self> {
        unimplemented!();
    }

    pub fn is_syntax(&self) -> bool {
        match self {
            Value::Syntax(_) => true,
            _ => false,
        }
    }

    fn new_index(s: &String) -> Option<Self> {
        unimplemented!();
    }

    pub fn is_index(&self) -> bool {
        match self {
            Value::Index(_) => true,
            _ => false,
        }
    }

    pub fn new_reference(u: Uuid) -> Self {
        Value::Uuid(u)
    }

    pub fn new_refer(u: &Uuid) -> Self {
        Self::new_reference(u.clone())
    }

    fn new_json_filter(s: &String) -> Option<Self> {
        unimplemented!();
        /*
        use crate::proto::v1::Filter as ProtoFilter;
                serde_json::from_str(v.as_str())
                    .map_err(|_| SchemaError::InvalidAttributeSyntax)
                    .map(|_: ProtoFilter| ())
                */
    }

    pub fn is_json_filter(&self) -> bool {
        unimplemented!();
    }

    pub fn contains(&self, s: &PartialValue) -> bool {
        unimplemented!();
    }

    // Converters between DBRepr -> MemRepr. It's likely many of these
    // will be just wrappers to our from str types.

    // Keep this updated with DbValueV1 in be::dbvalue.
    pub(crate) fn from_db_valuev1(v: DbValueV1) -> Self {
        unimplemented!();
    }

    pub(crate) fn to_db_valuev1(&self) -> DbValueV1 {
        unimplemented!();
    }

    /// Convert to a proto/public value that can be read and consumed.
    pub(crate) fn to_proto_string_clone(&self) -> String {
        unimplemented!();
    }

    pub fn to_str(&self) -> Option<&str> {
        match self {
            Value::Utf8(s) => Some(s.as_str()),
            Value::Iutf8(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_str_unwrap(&self) -> &str {
        self.to_str().expect("An invalid value was returned!!!")
    }

    pub fn as_string(&self) -> Option<&String> {
        match self {
            Value::Utf8(s) => Some(s),
            Value::Iutf8(s) => Some(s),
            _ => None,
        }
    }

    // We need a seperate to-ref_uuid to distinguish from normal uuids
    // in refint plugin.
    pub fn to_ref_uuid(&self) -> Option<&Uuid> {
        match self {
            Value::Refer(u) => Some(&u),
            _ => None,
        }
    }

    pub fn to_uuid(&self) -> Option<&Uuid> {
        match self {
            Value::Uuid(u) => Some(&u),
            Value::Refer(u) => Some(&u),
            _ => None,
        }
    }

    pub fn to_indextype(&self) -> Option<&IndexType> {
        match self {
            Value::Index(i) => Some(&i),
            _ => None,
        }
    }

    pub fn to_syntaxtype(&self) -> Option<&SyntaxType> {
        match self {
            Value::Syntax(s) => Some(&s),
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

    pub fn to_partialvalue(&self) -> PartialValue {
        // Match on self to become a partialvalue.
        unimplemented!()
    }
}

impl Borrow<PartialValue> for Value {
    fn borrow(&self) -> &PartialValue {
        unimplemented!();
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

}

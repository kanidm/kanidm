use crate::audit::AuditScope;
use crate::constants::*;
use crate::entry::{Entry, EntryCommitted, EntryNew, EntryValid};
use crate::error::{ConsistencyError, OperationError, SchemaError};
use crate::proto::v1::Filter as ProtoFilter;
use crate::server::QueryServerWriteTransaction;

use regex::Regex;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;
use uuid::Uuid;

use concread::cowcell::{CowCell, CowCellReadTxn, CowCellWriteTxn};

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

// TODO: prefix on all schema types that are system?

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub enum SyntaxType {
    // We need an insensitive string type too ...
    // We also need to "self host" a syntax type, and index type
    UTF8STRING,
    UTF8STRING_PRINCIPAL,
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
        } else if value == "UTF8STRING_PRINCIPAL" {
            Ok(SyntaxType::UTF8STRING_PRINCIPAL)
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
            SyntaxType::UTF8STRING_PRINCIPAL => "UTF8STRING_PRINCIPAL",
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

#[derive(Debug, Clone)]
pub struct SchemaAttribute {
    // Is this ... used?
    // class: Vec<String>,
    pub name: String,
    pub uuid: Uuid,
    // Perhaps later add aliases?
    pub description: String,
    pub multivalue: bool,
    pub index: Vec<IndexType>,
    pub syntax: SyntaxType,
}

impl SchemaAttribute {
    pub fn try_from(
        audit: &mut AuditScope,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Convert entry to a schema attribute.
        // class
        if !value.attribute_value_pres("class", "attributetype") {
            audit_log!(audit, "class attribute type not present");
            return Err(OperationError::InvalidSchemaState("missing attributetype"));
        }

        // uuid
        let uuid = try_audit!(
            audit,
            Uuid::parse_str(value.get_uuid().as_str())
                .map_err(|_| OperationError::InvalidSchemaState("Invalid UUID"))
        );

        // name
        let name = try_audit!(
            audit,
            value
                .get_ava_single("name")
                .ok_or(OperationError::InvalidSchemaState("missing name"))
        );
        // description
        let description = try_audit!(
            audit,
            value
                .get_ava_single("description")
                .ok_or(OperationError::InvalidSchemaState("missing description"))
        );

        // multivalue
        let multivalue = try_audit!(
            audit,
            value
                .get_ava_single_bool("multivalue")
                .ok_or(OperationError::InvalidSchemaState("missing multivalue"))
        );
        // index vec
        // even if empty, it SHOULD be present ... (is that value to put an empty set?)
        // The get_ava_opt_index handles the optional case for us :)
        let index = try_audit!(
            audit,
            value
                .get_ava_opt_index("index")
                .map_err(|_| OperationError::InvalidSchemaState("Invalid index"))
        );
        // syntax type
        let syntax = try_audit!(
            audit,
            value
                .get_ava_single_syntax("syntax")
                .ok_or(OperationError::InvalidSchemaState("missing syntax"))
        );

        Ok(SchemaAttribute {
            name: name.clone(),
            uuid: uuid.clone(),
            description: description.clone(),
            multivalue: multivalue,
            index: index,
            syntax: syntax,
        })
    }

    // Implement Equality, PartialOrd, Normalisation,
    // Validation.
    fn validate_bool(&self, v: &String) -> Result<(), SchemaError> {
        bool::from_str(v.as_str())
            .map_err(|_| SchemaError::InvalidAttributeSyntax)
            .map(|_| ())
    }

    fn validate_syntax(&self, v: &String) -> Result<(), SchemaError> {
        SyntaxType::try_from(v.as_str())
            .map_err(|_| SchemaError::InvalidAttributeSyntax)
            .map(|_| ())
    }

    fn validate_index(&self, v: &String) -> Result<(), SchemaError> {
        debug!("validate_index -> {}", v);
        IndexType::try_from(v.as_str())
            .map_err(|_| SchemaError::InvalidAttributeSyntax)
            .map(|_| ())
    }

    fn validate_uuid(&self, v: &String) -> Result<(), SchemaError> {
        Uuid::parse_str(v.as_str())
            .map_err(|_| SchemaError::InvalidAttributeSyntax)
            .map(|_| ())
    }

    fn validate_principal(&self, v: &String) -> Result<(), SchemaError> {
        // Check that we actually have a valid principal name of the form
        // X@Y No excess @ allowed.
        lazy_static! {
            static ref PRIN_RE: Regex =
                Regex::new("^[^@]+@[^@]+$").expect("Unable to parse static regex");
        }
        if PRIN_RE.is_match(v.as_str()) {
            Ok(())
        } else {
            Err(SchemaError::InvalidAttributeSyntax)
        }
    }

    fn validate_json_filter(&self, v: &String) -> Result<(), SchemaError> {
        // I *think* we just check if this can become a ProtoFilter v1
        // rather than anything more complex.

        // Can it be deserialised? I think that's all we can do because
        // it's only when we go to apply that we can do the actual filter
        // conversion, resolution of Self, and validation etc.

        // In my mind there are some risks here, like the fact that we defer evaluation
        // and checking until we go to use the value, but we ccould make a plugin similar
        // to refint that verifies all of these filters still compile and schema check
        // after any kind of modification.

        // Storing these as protofilter has value in terms of the fact we don't need
        // filter to be seralisable when we go to add state type data to it, and we can
        // then do conversions inside operations to resolve Self -> Bound UUID as required.

        serde_json::from_str(v.as_str())
            .map_err(|_| SchemaError::InvalidAttributeSyntax)
            .map(|_: ProtoFilter| ())
    }

    fn validate_utf8string_insensitive(&self, v: &String) -> Result<(), SchemaError> {
        let t = v.to_lowercase();
        if &t == v {
            Ok(())
        } else {
            Err(SchemaError::InvalidAttributeSyntax)
        }
    }

    pub fn validate_value(&self, v: &String) -> Result<(), SchemaError> {
        match self.syntax {
            SyntaxType::BOOLEAN => self.validate_bool(v),
            SyntaxType::SYNTAX_ID => self.validate_syntax(v),
            SyntaxType::INDEX_ID => self.validate_index(v),
            SyntaxType::UUID => self.validate_uuid(v),
            // Syntaxwise, these are the same.
            // Referential integrity is handled in plugins.
            SyntaxType::REFERENCE_UUID => self.validate_uuid(v),
            SyntaxType::UTF8STRING_INSENSITIVE => self.validate_utf8string_insensitive(v),
            SyntaxType::UTF8STRING_PRINCIPAL => self.validate_principal(v),
            SyntaxType::JSON_FILTER => self.validate_json_filter(v),
            _ => Ok(()),
        }
    }

    pub fn validate_ava(&self, ava: &Vec<String>) -> Result<(), SchemaError> {
        debug!("Checking for ... {:?}", self);
        debug!("Checking ava -> {:?}", ava);
        // Check multivalue
        if self.multivalue == false && ava.len() > 1 {
            debug!("Ava len > 1 on single value attribute!");
            return Err(SchemaError::InvalidAttributeSyntax);
        };
        // If syntax, check the type is correct
        match self.syntax {
            SyntaxType::BOOLEAN => {
                ava.iter().fold(Ok(()), |acc, v| {
                    // If acc is err, fold will skip it.
                    if acc.is_ok() {
                        self.validate_bool(v)
                    } else {
                        acc
                    }
                })
            }
            SyntaxType::SYNTAX_ID => ava.iter().fold(Ok(()), |acc, v| {
                if acc.is_ok() {
                    self.validate_syntax(v)
                } else {
                    acc
                }
            }),
            SyntaxType::UUID => ava.iter().fold(Ok(()), |acc, v| {
                if acc.is_ok() {
                    self.validate_uuid(v)
                } else {
                    acc
                }
            }),
            // This is the same as a UUID, refint is a plugin
            SyntaxType::REFERENCE_UUID => ava.iter().fold(Ok(()), |acc, v| {
                if acc.is_ok() {
                    self.validate_uuid(v)
                } else {
                    acc
                }
            }),
            SyntaxType::INDEX_ID => ava.iter().fold(Ok(()), |acc, v| {
                if acc.is_ok() {
                    debug!("Checking index ... {}", v);
                    self.validate_index(v)
                } else {
                    acc
                }
            }),
            SyntaxType::UTF8STRING_INSENSITIVE => ava.iter().fold(Ok(()), |acc, v| {
                if acc.is_ok() {
                    self.validate_utf8string_insensitive(v)
                } else {
                    acc
                }
            }),
            SyntaxType::UTF8STRING_PRINCIPAL => ava.iter().fold(Ok(()), |acc, v| {
                if acc.is_ok() {
                    self.validate_principal(v)
                } else {
                    acc
                }
            }),
            _ => Ok(()),
        }
    }

    pub fn normalise_syntax(&self, v: &String) -> String {
        v.to_uppercase()
    }

    pub fn normalise_index(&self, v: &String) -> String {
        v.to_uppercase()
    }

    pub fn normalise_utf8string_insensitive(&self, v: &String) -> String {
        v.to_lowercase()
    }

    pub fn normalise_principal(&self, v: &String) -> String {
        v.to_lowercase()
    }

    pub fn normalise_uuid(&self, v: &String) -> String {
        // If we can, normalise, else return the original as a clone
        // and validate will catch it later.
        match Uuid::parse_str(v.as_str()) {
            Ok(inner) => inner.to_hyphenated().to_string(),
            Err(_) => v.clone(),
        }
    }

    // TODO: This clones everything, which is expensive!
    pub fn normalise_value(&self, v: &String) -> String {
        match self.syntax {
            SyntaxType::SYNTAX_ID => self.normalise_syntax(v),
            SyntaxType::INDEX_ID => self.normalise_index(v),
            SyntaxType::UUID => self.normalise_uuid(v),
            SyntaxType::REFERENCE_UUID => self.normalise_uuid(v),
            SyntaxType::UTF8STRING_INSENSITIVE => self.normalise_utf8string_insensitive(v),
            SyntaxType::UTF8STRING_PRINCIPAL => self.normalise_principal(v),
            _ => v.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaClass {
    // Is this used?
    // class: Vec<String>,
    pub name: String,
    pub uuid: Uuid,
    pub description: String,
    // This allows modification of system types to be extended in custom ways
    pub systemmay: Vec<String>,
    pub may: Vec<String>,
    pub systemmust: Vec<String>,
    pub must: Vec<String>,
}

impl SchemaClass {
    pub fn try_from(
        audit: &mut AuditScope,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Convert entry to a schema class.
        if !value.attribute_value_pres("class", "classtype") {
            audit_log!(audit, "class classtype not present");
            return Err(OperationError::InvalidSchemaState("missing classtype"));
        }

        // uuid
        let uuid = try_audit!(
            audit,
            Uuid::parse_str(value.get_uuid().as_str())
                .map_err(|_| OperationError::InvalidSchemaState("Invalid UUID"))
        );

        // name
        let name = try_audit!(
            audit,
            value
                .get_ava_single("name")
                .ok_or(OperationError::InvalidSchemaState("missing name"))
        );
        // description
        let description = try_audit!(
            audit,
            value
                .get_ava_single("description")
                .ok_or(OperationError::InvalidSchemaState("missing description"))
        );

        // These are all "optional" lists of strings.

        let systemmay = value.get_ava_opt("systemmay");
        let systemmust = value.get_ava_opt("systemmust");
        let may = value.get_ava_opt("may");
        let must = value.get_ava_opt("must");

        Ok(SchemaClass {
            name: name.clone(),
            uuid: uuid,
            description: description.clone(),
            systemmay: systemmay,
            systemmust: systemmust,
            may: may,
            must: must,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SchemaInner {
    // We contain sets of classes and attributes.
    classes: HashMap<String, SchemaClass>,
    attributes: HashMap<String, SchemaAttribute>,
}

pub trait SchemaTransaction {
    fn get_inner(&self) -> &SchemaInner;

    fn validate(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        self.get_inner().validate(audit)
    }

    fn is_multivalue(&self, attr: &str) -> Result<bool, SchemaError> {
        self.get_inner().is_multivalue(attr)
    }

    // Probably need something like get_classes or similar
    // so that externals can call and use this data.

    fn get_classes(&self) -> &HashMap<String, SchemaClass> {
        &self.get_inner().classes
    }

    fn get_attributes(&self) -> &HashMap<String, SchemaAttribute> {
        &self.get_inner().attributes
    }

    fn get_reference_types(&self) -> HashMap<&String, &SchemaAttribute> {
        self.get_attributes()
            .iter()
            .filter(|(_, sa)| match &sa.syntax {
                SyntaxType::REFERENCE_UUID => true,
                _ => false,
            })
            .collect()
    }
}

impl SchemaInner {
    pub fn new(audit: &mut AuditScope) -> Result<Self, OperationError> {
        let mut au = AuditScope::new("schema_new");
        let r = audit_segment!(au, || {
            //
            let mut s = SchemaInner {
                classes: HashMap::new(),
                attributes: HashMap::new(),
            };
            // Bootstrap in definitions of our own schema types
            // First, add all the needed core attributes for schema parsing
            s.attributes.insert(
                String::from("class"),
                SchemaAttribute {
                    name: String::from("class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_CLASS)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of classes defining an object"),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("uuid"),
                SchemaAttribute {
                    name: String::from("uuid"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UUID)
                        .expect("unable to parse static uuid"),
                    description: String::from("The universal unique id of the object"),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UUID,
                },
            );
            s.attributes.insert(
                String::from("name"),
                SchemaAttribute {
                    name: String::from("name"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_NAME)
                        .expect("unable to parse static uuid"),
                    description: String::from("The shortform name of an object"),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
            String::from("principal_name"),
                SchemaAttribute {
                    name: String::from("principal_name"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PRINCIPAL_NAME).expect("unable to parse static uuid"),
                    description: String::from("The longform name of an object, derived from name and domain. Example: alice@project.org"),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_PRINCIPAL,
                },
            );
            s.attributes.insert(
                String::from("description"),
                SchemaAttribute {
                    name: String::from("description"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DESCRIPTION)
                        .expect("unable to parse static uuid"),
                    description: String::from("A description of an attribute, object or class"),
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            s.attributes.insert(String::from("multivalue"), SchemaAttribute {
                name: String::from("multivalue"),
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MULTIVALUE).expect("unable to parse static uuid"),
                description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
                multivalue: false,
                index: vec![],
                syntax: SyntaxType::BOOLEAN,
            });
            s.attributes.insert(
                String::from("index"),
                SchemaAttribute {
                    name: String::from("index"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_INDEX)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Describe the indexes to apply to instances of this attribute.",
                    ),
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::INDEX_ID,
                },
            );
            s.attributes.insert(
                String::from("syntax"),
                SchemaAttribute {
                    name: String::from("syntax"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYNTAX)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Describe the syntax of this attribute. This affects indexing and sorting.",
                    ),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::SYNTAX_ID,
                },
            );
            s.attributes.insert(
                String::from("systemmay"),
                SchemaAttribute {
                    name: String::from("systemmay"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMAY)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A list of system provided optional attributes this class can store.",
                    ),
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("may"),
                SchemaAttribute {
                    name: String::from("may"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MAY)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A user modifiable list of optional attributes this class can store.",
                    ),
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("systemmust"),
                SchemaAttribute {
                    name: String::from("systemmust"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMUST)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A list of system provided required attributes this class must store.",
                    ),
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("must"),
                SchemaAttribute {
                    name: String::from("must"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MUST)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A user modifiable list of required attributes this class must store.",
                    ),
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // SYSINFO attrs
            // ACP attributes.
            s.attributes.insert(
                String::from("acp_enable"),
                SchemaAttribute {
                    name: String::from("acp_enable"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_ENABLE)
                        .expect("unable to parse static uuid"),
                    description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforce. False is checked but not enforced."),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::BOOLEAN,
                },
            );

            s.attributes.insert(
                String::from("acp_receiver"),
                SchemaAttribute {
                    name: String::from("acp_receiver"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_RECEIVER)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Who the ACP applies to, constraining or allowing operations.",
                    ),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            s.attributes.insert(
                String::from("acp_targetscope"),
                SchemaAttribute {
                    name: String::from("acp_targetscope"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_TARGETSCOPE)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The effective targets of the ACP, IE what will be acted upon.",
                    ),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            s.attributes.insert(
                String::from("acp_search_attr"),
                SchemaAttribute {
                    name: String::from("acp_search_attr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from("The attributes that may be viewed or searched by the reciever on targetscope."),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("acp_create_class"),
                SchemaAttribute {
                    name: String::from("acp_create_class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_CREATE_CLASS)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The set of classes that can be created on a new entry.",
                    ),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("acp_create_attr"),
                SchemaAttribute {
                    name: String::from("acp_create_attr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_CREATE_ATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The set of attribute types that can be created on an entry.",
                    ),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            s.attributes.insert(
                String::from("acp_modify_removedattr"),
                SchemaAttribute {
                    name: String::from("acp_modify_removedattr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of attribute types that could be removed or purged in a modification."),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("acp_modify_presentattr"),
                SchemaAttribute {
                    name: String::from("acp_modify_presentattr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of attribute types that could be added or asserted in a modification."),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                String::from("acp_modify_class"),
                SchemaAttribute {
                    name: String::from("acp_modify_class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // MO/Member
            s.attributes.insert(
                String::from("memberof"),
                SchemaAttribute {
                    name: String::from("memberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBEROF)
                        .expect("unable to parse static uuid"),
                    description: String::from("reverse group membership of the object"),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            s.attributes.insert(
                String::from("directmemberof"),
                SchemaAttribute {
                    name: String::from("directmemberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DIRECTMEMBEROF)
                        .expect("unable to parse static uuid"),
                    description: String::from("reverse direct group membership of the object"),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            s.attributes.insert(
                String::from("member"),
                SchemaAttribute {
                    name: String::from("member"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBER)
                        .expect("unable to parse static uuid"),
                    description: String::from("List of members of the group"),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            // Migration related
            s.attributes.insert(
                String::from("version"),
                SchemaAttribute {
                    name: String::from("version"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_VERSION)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The systems internal migration version for provided objects",
                    ),
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // Domain for sysinfo
            s.attributes.insert(
                String::from("domain"),
                SchemaAttribute {
                    name: String::from("domain"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DOMAIN)
                        .expect("unable to parse static uuid"),
                    description: String::from("A DNS Domain name entry."),
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            s.classes.insert(
                String::from("attributetype"),
                SchemaClass {
                    name: String::from("attributetype"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ATTRIBUTETYPE)
                        .expect("unable to parse static uuid"),
                    description: String::from("Definition of a schema attribute"),
                    systemmay: vec![String::from("index")],
                    may: vec![],
                    systemmust: vec![
                        String::from("class"),
                        String::from("name"),
                        String::from("multivalue"),
                        String::from("syntax"),
                        String::from("description"),
                    ],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("classtype"),
                SchemaClass {
                    name: String::from("classtype"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_CLASSTYPE)
                        .expect("unable to parse static uuid"),
                    description: String::from("Definition of a schema classtype"),
                    systemmay: vec![
                        String::from("systemmay"),
                        String::from("may"),
                        String::from("systemmust"),
                        String::from("must"),
                    ],
                    may: vec![],
                    systemmust: vec![
                        String::from("class"),
                        String::from("name"),
                        String::from("description"),
                    ],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("object"),
                SchemaClass {
                    name: String::from("object"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_OBJECT)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A system created class that all objects must contain",
                    ),
                    systemmay: vec![String::from("description"), String::from("name")],
                    may: vec![],
                    systemmust: vec![
                        String::from("class"),
                        // String::from("name"),
                        String::from("uuid"),
                    ],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("memberof"),
                SchemaClass {
                    name: String::from("memberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_MEMBEROF)
                        .expect("unable to parse static uuid"),
                    description: String::from("Class that is dynamically added to recepients of memberof or directmemberof"),
                    systemmay: vec![
                        "memberof".to_string(),
                        "directmemberof".to_string()
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("extensibleobject"),
                SchemaClass {
                    name: String::from("extensibleobject"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A class type that has green hair and turns off all rules ...",
                    ),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            /* These two classes are core to the entry lifecycle for recycling and tombstoning */
            s.classes.insert(
                String::from("recycled"),
                SchemaClass {
                    name: String::from("recycled"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_RECYCLED).expect("unable to parse static uuid"),
                    description: String::from("An object that has been deleted, but still recoverable via the revive operation. Recycled objects are not modifiable, only revivable."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("tombstone"),
                SchemaClass {
                    name: String::from("tombstone"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_TOMBSTONE).expect("unable to parse static uuid"),
                    description: String::from("An object that is purged from the recycle bin. This is a system internal state. Tombstones have no attributes beside UUID."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![
                        String::from("class"),
                        String::from("uuid"),
                    ],
                    must: vec![],
                },
            );
            // sysinfo
            s.classes.insert(
                String::from("system_info"),
                SchemaClass {
                    name: String::from("system_info"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_SYSTEM_INFO)
                        .expect("unable to parse static uuid"),
                    description: String::from("System metadata object class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![
                        String::from("version"),
                        // Needed when we implement principalnames?
                        String::from("domain"),
                        // String::from("hostname"),
                    ],
                    must: vec![],
                },
            );
            // ACP
            s.classes.insert(
                String::from("access_control_profile"),
                SchemaClass {
                    name: String::from("access_control_profile"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE)
                        .expect("unable to parse static uuid"),
                    description: String::from("System Access Control Profile Class"),
                    systemmay: vec!["description".to_string()],
                    may: vec![],
                    systemmust: vec![
                        "acp_enable".to_string(),
                        "acp_receiver".to_string(),
                        "acp_targetscope".to_string(),
                    ],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("access_control_search"),
                SchemaClass {
                    name: String::from("access_control_search"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH)
                        .expect("unable to parse static uuid"),
                    description: String::from("System Access Control Search Class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec!["acp_search_attr".to_string()],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("access_control_delete"),
                SchemaClass {
                    name: String::from("access_control_delete"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE)
                        .expect("unable to parse static uuid"),
                    description: String::from("System Access Control DELETE Class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("access_control_modify"),
                SchemaClass {
                    name: String::from("access_control_modify"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY)
                        .expect("unable to parse static uuid"),
                    description: String::from("System Access Control Modify Class"),
                    systemmay: vec![
                        "acp_modify_removedattr".to_string(),
                        "acp_modify_presentattr".to_string(),
                        "acp_modify_class".to_string(),
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("access_control_create"),
                SchemaClass {
                    name: String::from("access_control_create"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE)
                        .expect("unable to parse static uuid"),
                    description: String::from("System Access Control Create Class"),
                    systemmay: vec![
                        "acp_create_class".to_string(),
                        "acp_create_attr".to_string(),
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("system"),
                SchemaClass {
                    name: String::from("system"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_SYSTEM)
                        .expect("unable to parse static uuid"),
                    description: String::from("A class denoting that a type is system generated and protected. It has special internal behaviour."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );

            let r = s.validate(&mut au);
            if r.len() == 0 {
                Ok(s)
            } else {
                Err(OperationError::ConsistencyError(r))
            }
        });

        audit.append_scope(au);
        r
    }

    pub fn validate(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let mut res = Vec::new();
        // Does this need to validate anything further at all? The UUID
        // will be checked as part of the schema migration on startup, so I think
        // just that all the content is sane is fine.
        for class in self.classes.values() {
            // report the class we are checking
            for a in &class.systemmay {
                // report the attribute.
                /*
                audit_log!(
                    audit,
                    "validate systemmay class:attr -> {}:{}",
                    class.name,
                    a
                );
                */
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
            for a in &class.may {
                // report the attribute.
                /*
                audit_log!(audit, "validate may class:attr -> {}:{}", class.name, a);
                */
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
            for a in &class.systemmust {
                // report the attribute.
                /*
                audit_log!(
                    audit,
                    "validate systemmust class:attr -> {}:{}",
                    class.name,
                    a
                );
                */
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
            for a in &class.must {
                // report the attribute.
                /*
                audit_log!(audit, "validate must class:attr -> {}:{}", class.name, a);
                */
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
        }

        res
    }

    // Normalise *does not* validate.
    // Normalise just fixes some possible common issues, but it
    // can't fix *everything* possibly wrong ...
    pub fn normalise_filter(&mut self) {
        unimplemented!()
    }

    fn is_multivalue(&self, attr_name: &str) -> Result<bool, SchemaError> {
        match self.attributes.get(attr_name) {
            Some(a_schema) => Ok(a_schema.multivalue),
            None => {
                debug!("Attribute does not exist?!");
                return Err(SchemaError::InvalidAttribute);
            }
        }
    }
}

pub struct Schema {
    inner: CowCell<SchemaInner>,
}

pub struct SchemaWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, SchemaInner>,
}

impl<'a> SchemaWriteTransaction<'a> {
    // TODO: Schema probably needs to be part of the backend, so that commits are wholly atomic
    // but in the current design, we need to open be first, then schema, but we have to commit be
    // first, then schema to ensure that the be content matches our schema. Saying this, if your
    // schema commit fails we need to roll back still .... How great are transactions.
    // At the least, this is what validation is for!
    pub fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();
        Ok(())
    }

    pub fn update_attributes(
        &mut self,
        attributetypes: Vec<SchemaAttribute>,
    ) -> Result<(), OperationError> {
        // purge all old attributes.
        self.inner.attributes.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        attributetypes.into_iter().for_each(|a| {
            self.inner.attributes.insert(a.name.clone(), a);
        });
        Ok(())
    }

    pub fn update_classes(
        &mut self,
        attributetypes: Vec<SchemaClass>,
    ) -> Result<(), OperationError> {
        // purge all old attributes.
        self.inner.classes.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        attributetypes.into_iter().for_each(|a| {
            self.inner.classes.insert(a.name.clone(), a);
        });
        Ok(())
    }

    pub fn to_entries(&self) -> Vec<Entry<EntryValid, EntryNew>> {
        let r: Vec<_> = self
            .inner
            .attributes
            .values()
            .map(|a| Entry::<EntryValid, EntryNew>::from(a))
            .chain(
                self.inner
                    .classes
                    .values()
                    .map(|c| Entry::<EntryValid, EntryNew>::from(c)),
            )
            .collect();
        r
    }
}

impl<'a> SchemaTransaction for SchemaWriteTransaction<'a> {
    fn get_inner(&self) -> &SchemaInner {
        // Does this deref the CowCell for us?
        &self.inner
    }
}

pub struct SchemaReadTransaction {
    inner: CowCellReadTxn<SchemaInner>,
}

impl SchemaTransaction for SchemaReadTransaction {
    fn get_inner(&self) -> &SchemaInner {
        // Does this deref the CowCell for us?
        &self.inner
    }
}

impl Schema {
    pub fn new(audit: &mut AuditScope) -> Result<Self, OperationError> {
        SchemaInner::new(audit).map(|si| Schema {
            inner: CowCell::new(si),
        })
    }

    pub fn read(&self) -> SchemaReadTransaction {
        SchemaReadTransaction {
            inner: self.inner.read(),
        }
    }

    pub fn write(&self) -> SchemaWriteTransaction {
        SchemaWriteTransaction {
            inner: self.inner.write(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::constants::*;
    use crate::entry::{Entry, EntryInvalid, EntryNew, EntryNormalised, EntryValid};
    use crate::error::{ConsistencyError, SchemaError};
    // use crate::filter::{Filter, FilterValid};
    use crate::schema::SchemaTransaction;
    use crate::schema::{IndexType, Schema, SchemaAttribute, SchemaClass, SyntaxType};
    use serde_json;
    use std::convert::TryFrom;
    use uuid::Uuid;

    // use crate::proto_v1::Filter as ProtoFilter;

    macro_rules! validate_schema {
        ($sch:ident, $au:expr) => {{
            // Turns into a result type
            let r: Result<Vec<()>, ConsistencyError> = $sch.validate($au).into_iter().collect();
            assert!(r.is_ok());
        }};
    }

    macro_rules! sch_from_entry_ok {
        (
            $audit:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str($e).expect("json failure");
            let ev1 = unsafe { e1.to_valid_committed() };

            let r1 = <$type>::try_from($audit, &ev1);
            assert!(r1.is_ok());
        }};
    }

    macro_rules! sch_from_entry_err {
        (
            $audit:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str($e).expect("json failure");
            let ev1 = unsafe { e1.to_valid_committed() };

            let r1 = <$type>::try_from($audit, &ev1);
            assert!(r1.is_err());
        }};
    }

    #[test]
    fn test_schema_attribute_from_entry() {
        run_test!(|_qs: &QueryServer, audit: &mut AuditScope| {
            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "multivalue": ["false"],
                        "index": ["EQUALITY"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["htouaoeu"],
                        "index": ["EQUALITY"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "index": ["NTEHNOU"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "index": ["EQUALITY"],
                        "syntax": ["TNEOUNTUH"]
                    }
                }"#,
                SchemaAttribute
            );

            // Index is allowed to be empty
            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            // Index present
            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "name": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "index": ["EQUALITY"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );
        });
    }

    #[test]
    fn test_schema_class_from_entry() {
        run_test!(|_qs: &QueryServer, audit: &mut AuditScope| {
            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "classtype"],
                        "name": ["schema_class_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"]
                    }
                }"#,
                SchemaClass
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object"],
                        "name": ["schema_class_test"],
                        "description": ["class test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"]
                    }
                }"#,
                SchemaClass
            );

            // Classes can be valid with no attributes provided.
            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "classtype"],
                        "name": ["schema_class_test"],
                        "description": ["class test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"]
                    }
                }"#,
                SchemaClass
            );

            // Classes with various may/must
            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "classtype"],
                        "name": ["schema_class_test"],
                        "description": ["class test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "systemmust": ["d"]
                    }
                }"#,
                SchemaClass
            );

            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "classtype"],
                        "name": ["schema_class_test"],
                        "description": ["class test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "systemmay": ["c"]
                    }
                }"#,
                SchemaClass
            );

            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "classtype"],
                        "name": ["schema_class_test"],
                        "description": ["class test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "may": ["a"],
                        "must": ["b"]
                    }
                }"#,
                SchemaClass
            );

            sch_from_entry_ok!(
                audit,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "classtype"],
                        "name": ["schema_class_test"],
                        "description": ["class test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "may": ["a"],
                        "must": ["b"],
                        "systemmay": ["c"],
                        "systemmust": ["d"]
                    }
                }"#,
                SchemaClass
            );
        });
    }

    #[test]
    fn test_schema_index_tryfrom() {
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
    fn test_schema_syntax_tryfrom() {
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
    fn test_schema_syntax_principal() {
        let sa = SchemaAttribute {
                name: String::from("principal_name"),
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PRINCIPAL_NAME).expect("unable to parse static uuid"),
                description: String::from("The longform name of an object, derived from name and domain. Example: alice@project.org"),
                multivalue: false,
                index: vec![IndexType::EQUALITY],
                syntax: SyntaxType::UTF8STRING_PRINCIPAL,
            };

        let r1 = sa.validate_principal(&String::from("a@a"));
        assert!(r1.is_ok());

        let r2 = sa.validate_principal(&String::from("a@@a"));
        assert!(r2.is_err());

        let r3 = sa.validate_principal(&String::from("a@a@a"));
        assert!(r3.is_err());

        let r4 = sa.validate_principal(&String::from("@a"));
        assert!(r4.is_err());

        let r5 = sa.validate_principal(&String::from("a@"));
        assert!(r5.is_err());
    }

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

    #[test]
    fn test_schema_attribute_simple() {
        // Test schemaAttribute validation of types.

        // Test single value string
        let single_value_string = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("single_value"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING_INSENSITIVE,
        };

        let r1 = single_value_string.validate_ava(&vec![String::from("test")]);
        assert_eq!(r1, Ok(()));

        let r2 =
            single_value_string.validate_ava(&vec![String::from("test1"), String::from("test2")]);
        assert_eq!(r2, Err(SchemaError::InvalidAttributeSyntax));

        // test multivalue string, boolean

        let multi_value_string = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("mv_string"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING,
        };

        let r5 =
            multi_value_string.validate_ava(&vec![String::from("test1"), String::from("test2")]);
        assert_eq!(r5, Ok(()));

        let multi_value_boolean = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("mv_bool"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::BOOLEAN,
        };

        let r3 =
            multi_value_boolean.validate_ava(&vec![String::from("test1"), String::from("test2")]);
        assert_eq!(r3, Err(SchemaError::InvalidAttributeSyntax));

        let r4 =
            multi_value_boolean.validate_ava(&vec![String::from("true"), String::from("false")]);
        assert_eq!(r4, Ok(()));

        // syntax_id and index_type values
        let single_value_syntax = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("sv_syntax"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::SYNTAX_ID,
        };

        let r6 = single_value_syntax.validate_ava(&vec![String::from("UTF8STRING")]);
        assert_eq!(r6, Ok(()));

        let r7 = single_value_syntax.validate_ava(&vec![String::from("thaeountaheu")]);
        assert_eq!(r7, Err(SchemaError::InvalidAttributeSyntax));

        let single_value_index = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("sv_index"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::INDEX_ID,
        };
        //
        let r8 = single_value_index.validate_ava(&vec![String::from("EQUALITY")]);
        assert_eq!(r8, Ok(()));

        let r9 = single_value_index.validate_ava(&vec![String::from("thaeountaheu")]);
        assert_eq!(r9, Err(SchemaError::InvalidAttributeSyntax));
    }

    #[test]
    fn test_schema_classes_simple() {
        // Test basic functions of simple attributes

    }

    #[test]
    fn test_schema_simple() {
        let mut audit = AuditScope::new("test_schema_simple");
        let schema = Schema::new(&mut audit).expect("failed to create schema");
        let schema_ro = schema.read();
        validate_schema!(schema_ro, &mut audit);
        println!("{}", audit);
    }

    #[test]
    fn test_schema_export_validate() {
        // Test exporting schema to entries, then validate them
        // as legitimate entries.
    }

    #[test]
    fn test_schema_entries() {
        // Given an entry, assert it's schema is valid
        // We do
        let mut audit = AuditScope::new("test_schema_entries");
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.read();
        let e_no_uuid: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {}
        }"#,
        )
        .expect("json parse failure");

        assert_eq!(
            e_no_uuid.validate(&schema),
            Err(SchemaError::MissingMustAttribute("uuid".to_string()))
        );

        let e_no_class: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"]
            }
        }"#,
        )
        .expect("json parse failure");

        assert_eq!(e_no_class.validate(&schema), Err(SchemaError::InvalidClass));

        let e_bad_class: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "class": ["zzzzzz"]
            }
        }"#,
        )
        .expect("json parse failure");
        assert_eq!(
            e_bad_class.validate(&schema),
            Err(SchemaError::InvalidClass)
        );

        let e_attr_invalid: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "class": ["object", "attributetype"]
            }
        }"#,
        )
        .expect("json parse failure");

        let res = e_attr_invalid.validate(&schema);
        assert!(match res {
            Err(SchemaError::MissingMustAttribute(_)) => true,
            _ => false,
        });

        let e_attr_invalid_may: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["object", "attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["false"],
                "syntax": ["UTF8STRING"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "zzzzz": ["zzzz"]
            }
        }"#,
        )
        .expect("json parse failure");

        assert_eq!(
            e_attr_invalid_may.validate(&schema),
            Err(SchemaError::InvalidAttribute)
        );

        let e_attr_invalid_syn: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["object", "attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["zzzzz"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
        )
        .expect("json parse failure");

        assert_eq!(
            e_attr_invalid_syn.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax)
        );

        let e_ok: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["object", "attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["true"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
        )
        .expect("json parse failure");
        assert!(e_ok.validate(&schema).is_ok());
        println!("{}", audit);
    }

    #[test]
    fn test_schema_entry_validate() {
        // Check that entries can be normalised and validated sanely
        let mut audit = AuditScope::new("test_schema_entry_validate");
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let mut schema = schema_outer.write();

        // Check syntax to upper
        // check index to upper
        // insense to lower
        // attr name to lower
        let e_test: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["TestPerson"],
                "syntax": ["utf8string"],
                "UUID": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "InDeX": ["equality"]
            }
        }"#,
        )
        .expect("json parse failure");

        let e_expect: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "db237e8a-0079-4b8c-8a56-593b22aa44d1"
            },
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["testperson"],
                "syntax": ["UTF8STRING"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "index": ["EQUALITY"]
            }
        }"#,
        )
        .expect("json parse failure");

        let e_valid = e_test.validate(&schema).expect("validation failure");

        assert_eq!(e_expect, e_valid);
        println!("{}", audit);
    }

    #[test]
    fn test_schema_entry_normalise() {
        // Check that entries can be normalised sanely
        let mut audit = AuditScope::new("test_schema_entry_normalise");
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let mut schema = schema_outer.write();

        // Check that an entry normalises, despite being inconsistent to
        // schema.
        let e_test: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["TestPerson"],
                "syntax": ["utf8string"],
                "NotAllowed": ["Some Value"],
                "UUID": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "index": ["equality"]
            }
        }"#,
        )
        .expect("json parse failure");

        let e_expect: Entry<EntryNormalised, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["testperson"],
                "syntax": ["UTF8STRING"],
                "notallowed": ["Some Value"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "index": ["EQUALITY"]
            }
        }"#,
        )
        .expect("json parse failure");

        let e_normal = e_test.normalise(&schema).expect("validation failure");

        assert_eq!(e_expect, e_normal);
        println!("{}", audit);
    }

    #[test]
    fn test_schema_extensible() {
        let mut audit = AuditScope::new("test_schema_extensible");
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.read();
        // Just because you are extensible, doesn't mean you can be lazy

        let e_extensible_bad: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "multivalue": ["zzzz"]
            }
        }"#,
        )
        .expect("json parse failure");

        assert_eq!(
            e_extensible_bad.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax)
        );

        let e_extensible: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "multivalue": ["true"]
            }
        }"#,
        )
        .expect("json parse failure");

        /* Is okay because extensible! */
        assert!(e_extensible.validate(&schema).is_ok());
        println!("{}", audit);
    }

    #[test]
    fn test_schema_filter_validation() {
        let mut audit = AuditScope::new("test_schema_filter_validation");
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.read();
        // Test non existant attr name
        let f_mixed = filter_all!(f_eq("nonClAsS", "attributetype"));
        assert_eq!(
            f_mixed.validate(&schema),
            Err(SchemaError::InvalidAttribute)
        );

        // test syntax of bool
        let f_bool = filter_all!(f_eq("multivalue", "zzzz"));
        assert_eq!(
            f_bool.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        // test insensitive values
        let f_insense = filter_all!(f_eq("class", "AttributeType"));
        assert_eq!(
            f_insense.validate(&schema),
            Ok(unsafe { filter_valid!(f_eq("class", "attributetype")) })
        );
        // Test the recursive structures validate
        let f_or_empty = filter_all!(f_or!([]));
        assert_eq!(f_or_empty.validate(&schema), Err(SchemaError::EmptyFilter));
        let f_or = filter_all!(f_or!([f_eq("multivalue", "zzzz")]));
        assert_eq!(
            f_or.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        let f_or_mult = filter_all!(f_and!([
            f_eq("class", "attributetype"),
            f_eq("multivalue", "zzzzzzz"),
        ]));
        assert_eq!(
            f_or_mult.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        // Test mixed case attr name - this is a pass, due to normalisation
        let f_or_ok = filter_all!(f_andnot(f_and!([
            f_eq("Class", "AttributeType"),
            f_sub("class", "classtype"),
            f_pres("class")
        ])));
        assert_eq!(
            f_or_ok.validate(&schema),
            Ok(unsafe {
                filter_valid!(f_andnot(f_and!([
                    f_eq("class", "attributetype"),
                    f_sub("class", "classtype"),
                    f_pres("class")
                ])))
            })
        );
        println!("{}", audit);
    }

    #[test]
    fn test_schema_filter_normalisation() {
        // Test mixed case attr name
        // test syntax of bool
        // test normalise of insensitive strings
    }
}

use crate::audit::AuditScope;
use crate::constants::*;
use crate::error::{ConsistencyError, OperationError, SchemaError};
use crate::proto::v1::Filter as ProtoFilter;
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

// TODO: Account should be a login-bind-able object
//    needs account lock, timeout, policy?

// TODO: system_info metadata object schema

// TODO: system class to indicate the type is a system object?
// just a class? Does the class imply protections?
// probably just protection from delete and modify, except systemmay/systemmust/index?

// TODO: Schema types -> Entry conversion
// TODO: Entry -> Schema given class. This is for loading from the db.

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

#[derive(Debug, Clone)]
pub struct SchemaAttribute {
    // Is this ... used?
    // class: Vec<String>,
    pub name: String,
    pub uuid: Uuid,
    // Perhaps later add aliases?
    pub description: String,
    pub system: bool,
    pub secret: bool,
    pub multivalue: bool,
    pub index: Vec<IndexType>,
    pub syntax: SyntaxType,
}

impl SchemaAttribute {
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
        // FIXME: Is there a way to do this that doesn't involve a copy?
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
        // Check multivalue
        if self.multivalue == false && ava.len() > 1 {
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

    // FIXME: This clones everything, which is expensive!
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
                    system: true,
                    secret: false,
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
                    system: true,
                    secret: false,
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
                    system: true,
                    secret: false,
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
                system: true,
                secret: false,
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
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            s.attributes.insert(
                // FIXME: Rename to system_provided? Or should we eschew this in favour of class?
                // system_provided attr seems easier to provide access controls on, and can be
                // part of object ...
                String::from("system"),
                SchemaAttribute {
                    name: String::from("system"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEM)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Is this object or attribute provided from the core system?",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![],
                    syntax: SyntaxType::BOOLEAN,
                },
            );
            s.attributes.insert(String::from("secret"), SchemaAttribute {
            // FIXME: Rename from system to schema_private? system_private? attr_private? private_attr?
            name: String::from("secret"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SECRET).expect("unable to parse static uuid"),
            description: String::from("If true, this value is always hidden internally to the server, even beyond access controls."),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![],
            syntax: SyntaxType::BOOLEAN,
        });
            s.attributes.insert(String::from("multivalue"), SchemaAttribute {
            name: String::from("multivalue"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MULTIVALUE).expect("unable to parse static uuid"),
            description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![],
            syntax: SyntaxType::BOOLEAN,
        });
            s.attributes.insert(
                // FIXME: Rename to index_attribute? attr_index?
                String::from("index"),
                SchemaAttribute {
                    name: String::from("index"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_INDEX)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Describe the indexes to apply to instances of this attribute.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![],
                    syntax: SyntaxType::INDEX_ID,
                },
            );
            s.attributes.insert(
                // FIXME: Rename to attr_syntax?
                String::from("syntax"),
                SchemaAttribute {
                    name: String::from("syntax"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYNTAX)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Describe the syntax of this attribute. This affects indexing and sorting.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::SYNTAX_ID,
                },
            );
            s.attributes.insert(
                // FIXME: Rename to attribute_systemmay?
                String::from("systemmay"),
                SchemaAttribute {
                    name: String::from("systemmay"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMAY)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A list of system provided optional attributes this class can store.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                // FIXME: Rename to attribute_may? schema_may?
                String::from("may"),
                SchemaAttribute {
                    name: String::from("may"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MAY)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A user modifiable list of optional attributes this class can store.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                // FIXME: Rename to attribute_systemmust? schema_systemmust?
                String::from("systemmust"),
                SchemaAttribute {
                    name: String::from("systemmust"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMUST)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A list of system provided required attributes this class must store.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            s.attributes.insert(
                // FIXME: Rename to attribute_must? schema_must?
                String::from("must"),
                SchemaAttribute {
                    name: String::from("must"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MUST)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A user modifiable list of required attributes this class must store.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![],
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
                        String::from("system"),
                        String::from("secret"),
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
                    systemmay: vec![
                        // FIXME: Owner? Responsible? Contact?
                        String::from("description"),
                        String::from("principal_name"),
                    ],
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

            // TODO: Probably needs to do a collect.
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

    // This shouldn't fail?
    pub fn bootstrap_core(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // This will create a set of sane, system core schema that we can use
        // main types are users, groups
        let mut au = AuditScope::new("schema_bootstrap_core");
        let r = audit_segment!(au, || {
            // Create attributes
            // displayname // single
            self.attributes.insert(
                String::from("displayname"),
                SchemaAttribute {
                    name: String::from("displayname"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DISPLAYNAME)
                        .expect("unable to parse static uuid"),
                    description: String::from("The publicly visible display name of this person"),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            // name // single
            // mail // multi
            self.attributes.insert(
                String::from("mail"),
                SchemaAttribute {
                    name: String::from("mail"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MAIL)
                        .expect("unable to parse static uuid"),
                    description: String::from("mail addresses of the object"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            // memberof // multi
            self.attributes.insert(
                String::from("memberof"),
                SchemaAttribute {
                    name: String::from("memberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBEROF)
                        .expect("unable to parse static uuid"),
                    description: String::from("reverse group membership of the object"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            self.attributes.insert(
                String::from("directmemberof"),
                SchemaAttribute {
                    name: String::from("directmemberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DIRECTMEMBEROF)
                        .expect("unable to parse static uuid"),
                    description: String::from("reverse direct group membership of the object"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            // ssh_publickey // multi
            self.attributes.insert(
                String::from("ssh_publickey"),
                SchemaAttribute {
                    name: String::from("ssh_publickey"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SSH_PUBLICKEY)
                        .expect("unable to parse static uuid"),
                    description: String::from("SSH public keys of the object"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            // password // secret, multi
            self.attributes.insert(
                String::from("password"),
                SchemaAttribute {
                    name: String::from("password"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PASSWORD)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "password hash material of the object for authentication",
                    ),
                    system: true,
                    secret: true,
                    multivalue: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            //
            // member
            self.attributes.insert(
                String::from("member"),
                SchemaAttribute {
                    name: String::from("member"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBER)
                        .expect("unable to parse static uuid"),
                    description: String::from("List of members of the group"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );

            self.attributes.insert(
                String::from("version"),
                SchemaAttribute {
                    name: String::from("version"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_VERSION)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The systems internal migration version for provided objects",
                    ),
                    system: true,
                    secret: true,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            self.attributes.insert(
                String::from("domain"),
                SchemaAttribute {
                    name: String::from("domain"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DOMAIN)
                        .expect("unable to parse static uuid"),
                    description: String::from("A DNS Domain name entry."),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            // ACP related attributes
            /*
             * temporarily disabled while I decide if it's relevant at all ...
            self.attributes.insert(
                String::from("acp_allow"),
                SchemaAttribute {
                    name: String::from("acp_allow"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_ALLOW)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "A flag to determine if this is a deny or allow ACP. True is allow.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::BOOLEAN,
                },
            );
            */
            self.attributes.insert(
                String::from("acp_enable"),
                SchemaAttribute {
                    name: String::from("acp_enable"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_ENABLE)
                        .expect("unable to parse static uuid"),
                    description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforce. False is checked but not enforced."),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::BOOLEAN,
                },
            );

            self.attributes.insert(
                String::from("acp_receiver"),
                SchemaAttribute {
                    name: String::from("acp_receiver"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_RECEIVER)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "Who the ACP applies to, constraining or allowing operations.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            self.attributes.insert(
                String::from("acp_targetscope"),
                SchemaAttribute {
                    name: String::from("acp_targetscope"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_TARGETSCOPE)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The effective targets of the ACP, IE what will be acted upon.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: false,
                    index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            self.attributes.insert(
                String::from("acp_search_attr"),
                SchemaAttribute {
                    name: String::from("acp_search_attr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from("The attributes that may be viewed or searched by the reciever on targetscope."),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_create_class"),
                SchemaAttribute {
                    name: String::from("acp_create_class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_CREATE_CLASS)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The set of classes that can be created on a new entry.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_create_attr"),
                SchemaAttribute {
                    name: String::from("acp_create_attr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_CREATE_ATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from(
                        "The set of attribute types that can be created on an entry.",
                    ),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            self.attributes.insert(
                String::from("acp_modify_removedattr"),
                SchemaAttribute {
                    name: String::from("acp_modify_removedattr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of attribute types that could be removed or purged in a modification."),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_modify_presentattr"),
                SchemaAttribute {
                    name: String::from("acp_modify_presentattr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of attribute types that could be added or asserted in a modification."),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_modify_class"),
                SchemaAttribute {
                    name: String::from("acp_modify_class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS)
                        .expect("unable to parse static uuid"),
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            // Create the classes that use it
            // FIXME: Add account lock
            self.classes.insert(
                String::from("account"),
                SchemaClass {
                    name: String::from("account"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCOUNT)
                        .expect("unable to parse static uuid"),
                    description: String::from("Object representation of a person"),
                    systemmay: vec![
                        String::from("password"),
                        String::from("ssh_publickey"),
                        String::from("memberof"),
                        // String::from("uidnumber"),
                        // String::from("gidnumber"),
                    ],
                    may: vec![],
                    systemmust: vec![String::from("displayname"), String::from("name")],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("person"),
                SchemaClass {
                    name: String::from("person"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_PERSON)
                        .expect("unable to parse static uuid"),
                    description: String::from("Object representation of a person"),
                    systemmay: vec![
                        String::from("mail"),
                        String::from("memberof"),
                        // String::from("password"),
                    ],
                    may: vec![],
                    systemmust: vec![String::from("displayname"), String::from("name")],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("group"),
                SchemaClass {
                    name: String::from("group"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_GROUP)
                        .expect("unable to parse static uuid"),
                    description: String::from("Object representation of a group"),
                    systemmay: vec![
                        String::from("member"),
                        // String::from("gidnumber"),
                    ],
                    may: vec![],
                    systemmust: vec![String::from("name")],
                    must: vec![],
                },
            );
            self.classes.insert(
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
            self.classes.insert(
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
            self.classes.insert(
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
            self.classes.insert(
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
            self.classes.insert(
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
            self.classes.insert(
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

            // Finally, validate our content is sane.
            self.validate(&mut au)
        });

        audit.append_scope(au);

        if r.len() == 0 {
            Ok(())
        } else {
            Err(OperationError::ConsistencyError(r))
        }
    }

    pub fn validate(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let mut res = Vec::new();
        // TODO: Does this need to validate anything further at all? The UUID
        // will be checked as part of the schema migration on startup, so I think
        // just that all the content is sane is fine.
        for class in self.classes.values() {
            // report the class we are checking
            for a in &class.systemmay {
                // report the attribute.
                audit_log!(
                    audit,
                    "validate systemmay class:attr -> {}:{}",
                    class.name,
                    a
                );
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
            for a in &class.may {
                // report the attribute.
                audit_log!(audit, "validate may class:attr -> {}:{}", class.name, a);
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
            for a in &class.systemmust {
                // report the attribute.
                audit_log!(
                    audit,
                    "validate systemmust class:attr -> {}:{}",
                    class.name,
                    a
                );
                if !self.attributes.contains_key(a) {
                    res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                        class.name.clone(),
                        a.clone(),
                    )))
                }
            }
            for a in &class.must {
                // report the attribute.
                audit_log!(audit, "validate must class:attr -> {}:{}", class.name, a);
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
    pub fn bootstrap_core(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.inner.bootstrap_core(audit)
    }

    // TODO: Schema probably needs to be part of the backend, so that commits are wholly atomic
    // but in the current design, we need to open be first, then schema, but we have to commit be
    // first, then schema to ensure that the be content matches our schema. Saying this, if your
    // schema commit fails we need to roll back still .... How great are transactions.
    // At the least, this is what validation is for!
    pub fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();
        Ok(())
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
    use crate::schema::{IndexType, Schema, SchemaAttribute, SyntaxType};
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
                system: true,
                secret: false,
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
            system: true,
            secret: false,
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
            system: true,
            secret: false,
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
            system: true,
            secret: false,
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
            system: true,
            secret: false,
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
            system: true,
            secret: false,
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
            system: true,
            secret: false,
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
            system: true,
            secret: false,
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
                "class": ["attributetype"]
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
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
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
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
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
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
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
        schema
            .bootstrap_core(&mut audit)
            .expect("failed to bootstrap schema");

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
                "displayName": ["testperson"],
                "syntax": ["utf8string"],
                "UUID": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "index": ["equality"]
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
                "displayname": ["testperson"],
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
        schema
            .bootstrap_core(&mut audit)
            .expect("failed to bootstrap schema");

        // Check that an entry normalises, despite being inconsistent to
        // schema.
        let e_test: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["TestPerson"],
                "displayName": ["testperson"],
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
                "displayname": ["testperson"],
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
                "secret": ["zzzz"]
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
                "secret": ["true"]
            }
        }"#,
        )
        .expect("json parse failure");

        /* Is okay because extensible! */
        assert!(e_extensible.validate(&schema).is_ok());
        println!("{}", audit);
    }

    #[test]
    fn test_schema_loading() {
        // Validate loading schema from entries
    }

    #[test]
    fn test_schema_bootstrap() {
        let mut audit = AuditScope::new("test_schema_bootstrap");
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let mut schema = schema_outer.write();
        schema
            .bootstrap_core(&mut audit)
            .expect("schema bootstrap failed");

        // now test some entries
        let e_person: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "principal_name": ["testperson@project.org"],
                "description": ["testperson"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");
        assert!(e_person.validate(&schema).is_ok());

        let e_group: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "principal_name": ["testgroup@project.org"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "description": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");
        assert!(e_group.validate(&schema).is_ok());
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
        let f_bool = filter_all!(f_eq("secret", "zzzz"));
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
        let f_or = filter_all!(f_or!([f_eq("secret", "zzzz")]));
        assert_eq!(
            f_or.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        let f_or_mult = filter_all!(f_and!([
            f_eq("class", "attributetype"),
            f_eq("secret", "zzzzzzz"),
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

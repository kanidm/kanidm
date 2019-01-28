use super::audit::AuditScope;
use super::constants::*;
use super::entry::Entry;
use super::error::SchemaError;
use super::filter::Filter;
use std::collections::HashMap;
// Apparently this is nightly only?
use regex::Regex;
use std::convert::TryFrom;
use std::str::FromStr;
use uuid::Uuid;
use modify::ModifyList;

use concread::cowcell::{CowCell, CowCellReadTxn, CowCellWriteTxn};

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

// TODO: Schema should be copy-on-write

// TODO: Account should be a login-bind-able object
//    needs account lock, timeout, policy?

// TODO: system_info metadata object schema

// TODO: system class to indicate the type is a system object?
// just a class? Does the class imply protections?
// probably just protection from delete and modify, except systemmay/systemmust/index?

// TODO: Schema types -> Entry conversion
// TODO: Entry -> Schema given class. This is for loading from the db.

// TODO: prefix on all schema types that are system?

#[derive(Debug, PartialEq)]
enum Ternary {
    Empty,
    True,
    False,
}

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
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaAttribute {
    // Is this ... used?
    // class: Vec<String>,
    name: String,
    uuid: Uuid,
    // Perhaps later add aliases?
    description: String,
    system: bool,
    secret: bool,
    multivalue: bool,
    index: Vec<IndexType>,
    syntax: SyntaxType,
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
            static ref PRIN_RE: Regex = Regex::new("^[^@]+@[^@]+$").unwrap();
        }
        if PRIN_RE.is_match(v.as_str()) {
            Ok(())
        } else {
            Err(SchemaError::InvalidAttributeSyntax)
        }
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
            SyntaxType::UTF8STRING_INSENSITIVE => self.validate_utf8string_insensitive(v),
            SyntaxType::UTF8STRING_PRINCIPAL => self.validate_principal(v),
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
        // We unwrap here as we should already have been validated ...
        let c_uuid = Uuid::parse_str(v.as_str()).unwrap();
        c_uuid.to_hyphenated().to_string()
    }

    // FIXME: This clones everything, which is expensive!
    pub fn normalise_value(&self, v: &String) -> String {
        match self.syntax {
            SyntaxType::SYNTAX_ID => self.normalise_syntax(v),
            SyntaxType::INDEX_ID => self.normalise_index(v),
            SyntaxType::UUID => self.normalise_uuid(v),
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
    name: String,
    uuid: Uuid,
    description: String,
    // This allows modification of system types to be extended in custom ways
    systemmay: Vec<String>,
    may: Vec<String>,
    systemmust: Vec<String>,
    must: Vec<String>,
}

impl SchemaClass {
    // Implement Validation and Normalisation against entries
    pub fn validate_entry(&self, _entry: &Entry) -> Result<(), ()> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct SchemaInner {
    // We contain sets of classes and attributes.
    classes: HashMap<String, SchemaClass>,
    attributes: HashMap<String, SchemaAttribute>,
}

pub trait SchemaReadTransaction {
    fn get_inner(&self) -> &SchemaInner;

    fn validate(&self, audit: &mut AuditScope) -> Result<(), ()> {
        self.get_inner().validate(audit)
    }

    fn validate_entry(&self, entry: &Entry) -> Result<(), SchemaError> {
        self.get_inner().validate_entry(entry)
    }

    fn validate_filter(&self, filt: &Filter) -> Result<(), SchemaError> {
        self.get_inner().validate_filter(filt)
    }

    fn normalise_entry(&self, entry: &Entry) -> Entry {
        self.get_inner().normalise_entry(entry)
    }

    fn normalise_modlist(&self, modlist: &ModifyList) -> ModifyList {
        unimplemented!()
    }

    fn is_multivalue(&self, attr: &str) -> Result<bool, SchemaError> {
        self.get_inner().is_multivalue(attr)
    }
}

impl SchemaInner {
    pub fn new(audit: &mut AuditScope) -> Result<Self, ()> {
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_CLASS).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UUID).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_NAME).unwrap(),
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
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PRINCIPAL_NAME).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DESCRIPTION).unwrap(),
                    description: String::from("A description of an attribute, object or class"),
                    system: true,
                    secret: false,
                    multivalue: false,
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEM).unwrap(),
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
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SECRET).unwrap(),
            description: String::from("If true, this value is always hidden internally to the server, even beyond access controls."),
            system: true,
            secret: false,
            multivalue: false,
            index: vec![],
            syntax: SyntaxType::BOOLEAN,
        });
            s.attributes.insert(String::from("multivalue"), SchemaAttribute {
            name: String::from("multivalue"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MULTIVALUE).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_INDEX).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYNTAX).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMAY).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MAY).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMUST).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MUST).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ATTRIBUTETYPE).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_CLASSTYPE).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_OBJECT).unwrap(),
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
                        String::from("name"),
                        String::from("uuid"),
                    ],
                    must: vec![],
                },
            );
            s.classes.insert(
                String::from("extensibleobject"),
                SchemaClass {
                    name: String::from("extensibleobject"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT).unwrap(),
                    description: String::from("A class type that turns off all rules ..."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );

            match s.validate(&mut au) {
                Ok(_) => Ok(s),
                Err(e) => Err(e),
            }
        });

        audit.append_scope(au);

        r
    }

    // This shouldn't fail?
    pub fn bootstrap_core(&mut self, audit: &mut AuditScope) -> Result<(), ()> {
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DISPLAYNAME).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MAIL).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBEROF).unwrap(),
                    description: String::from("reverse group membership of the object"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // ssh_publickey // multi
            self.attributes.insert(
                String::from("ssh_publickey"),
                SchemaAttribute {
                    name: String::from("ssh_publickey"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SSH_PUBLICKEY).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PASSWORD).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBER).unwrap(),
                    description: String::from("List of members of the group"),
                    system: true,
                    secret: false,
                    multivalue: true,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            self.attributes.insert(
                String::from("version"),
                SchemaAttribute {
                    name: String::from("version"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_VERSION).unwrap(),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DOMAIN).unwrap(),
                    description: String::from("A DNS Domain name entry."),
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
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCOUNT).unwrap(),
                    description: String::from("Object representation of a person"),
                    systemmay: vec![
                        String::from("password"),
                        String::from("ssh_publickey"),
                        String::from("memberof"),
                        // String::from("uidnumber"),
                        // String::from("gidnumber"),
                    ],
                    may: vec![],
                    systemmust: vec![String::from("displayname")],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("person"),
                SchemaClass {
                    name: String::from("person"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_PERSON).unwrap(),
                    description: String::from("Object representation of a person"),
                    systemmay: vec![
                        String::from("mail"),
                        String::from("memberof"),
                        // String::from("password"),
                    ],
                    may: vec![],
                    systemmust: vec![String::from("displayname")],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("group"),
                SchemaClass {
                    name: String::from("group"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_GROUP).unwrap(),
                    description: String::from("Object representation of a group"),
                    systemmay: vec![
                        String::from("member"),
                        // String::from("gidnumber"),
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("system_info"),
                SchemaClass {
                    name: String::from("system_info"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_SYSTEM_INFO).unwrap(),
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

            // Finally, validate our content is sane.
            self.validate(&mut au)
        });

        audit.append_scope(au);

        r
    }

    pub fn validate(&self, audit: &mut AuditScope) -> Result<(), ()> {
        // FIXME: How can we make this return a proper result?
        //
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
                    return Err(());
                }
            }
            for a in &class.may {
                // report the attribute.
                audit_log!(audit, "validate may class:attr -> {}:{}", class.name, a);
                if !self.attributes.contains_key(a) {
                    return Err(());
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
                    return Err(());
                }
            }
            for a in &class.must {
                // report the attribute.
                audit_log!(audit, "validate must class:attr -> {}:{}", class.name, a);
                if !self.attributes.contains_key(a) {
                    return Err(());
                }
            }
        }

        Ok(())
    }

    pub fn validate_entry(&self, entry: &Entry) -> Result<(), SchemaError> {
        // First look at the classes on the entry.
        // Now, check they are valid classes
        //
        // FIXME: We could restructure this to be a map that gets Some(class)
        // if found, then do a len/filter/check on the resulting class set?
        let c_valid = entry.classes().fold(Ternary::Empty, |acc, c| {
            if acc == Ternary::False {
                // Begin shortcircuit
                acc
            } else {
                // Test the value (Could be True or Valid on entry.
                // We
                match self.classes.contains_key(c) {
                    true => Ternary::True,
                    false => Ternary::False,
                }
            }
        });

        if c_valid != Ternary::True {
            return Err(SchemaError::InvalidClass);
        };

        let classes: HashMap<String, &SchemaClass> = entry
            .classes()
            .map(|c| (c.clone(), self.classes.get(c).unwrap()))
            .collect();

        let extensible = classes.contains_key("extensibleobject");

        // What this is really doing is taking a set of classes, and building an
        // "overall" class that describes this exact object for checking

        //   for each class
        //      add systemmust/must and systemmay/may to their lists
        //      add anything from must also into may

        // Now from the set of valid classes make a list of must/may
        // FIXME: This is clone on read, which may be really slow. It also may
        // be inefficent on duplicates etc.
        let must: HashMap<String, &SchemaAttribute> = classes
            .iter()
            // Join our class systemmmust + must into one iter
            .flat_map(|(_, cls)| cls.systemmust.iter().chain(cls.must.iter()))
            .map(|s| (s.clone(), self.attributes.get(s).unwrap()))
            .collect();

        // FIXME: Error needs to say what is missing
        // We need to return *all* missing attributes.

        // Check that all must are inplace
        //   for each attr in must, check it's present on our ent
        // FIXME: Could we iter over only the attr_name
        for (attr_name, _attr) in must {
            let avas = entry.get_ava(&attr_name);
            if avas.is_none() {
                return Err(SchemaError::MissingMustAttribute(
                    String::from(attr_name)
                ));
            }
        }

        // Check that any other attributes are in may
        //   for each attr on the object, check it's in the may+must set
        for (attr_name, avas) in entry.avas() {
            match self.attributes.get(attr_name) {
                Some(a_schema) => {
                    // Now, for each type we do a *full* check of the syntax
                    // and validity of the ava.
                    let r = a_schema.validate_ava(avas);
                    // FIXME: This block could be more functional
                    if r.is_err() {
                        return r;
                    }
                }
                None => {
                    if !extensible {
                        return Err(SchemaError::InvalidAttribute);
                    }
                }
            }
        }

        // Well, we got here, so okay!
        Ok(())
    }

    // TODO: Restructure this when we change entry lifecycle types.
    pub fn normalise_entry(&self, entry: &Entry) -> Entry {
        // We duplicate the entry here, because we can't
        // modify what we got on the protocol level. It also
        // lets us extend and change things.

        let mut entry_new: Entry = entry.clone_no_attrs();
        // Better hope we have the attribute type ...
        let schema_attr_name = self.attributes.get("name").unwrap();
        // For each ava
        for (attr_name, avas) in entry.avas() {
            let attr_name_normal: String = schema_attr_name.normalise_value(attr_name);
            // Get the needed schema type
            let schema_a_r = self.attributes.get(&attr_name_normal);
            // if we can't find schema_a, clone and push
            // else

            let avas_normal: Vec<String> = match schema_a_r {
                Some(schema_a) => {
                    avas.iter()
                        .map(|av| {
                            // normalise those based on schema?
                            schema_a.normalise_value(av)
                        })
                        .collect()
                }
                None => avas.clone(),
            };
            // now push those to the new entry.
            entry_new.set_avas(attr_name_normal, avas_normal);
        }
        // Mark it is valid
        // entry_new.schema_validated = true;
        // Done!
        // TODO: Convert the entry type here to a validated type.
        entry_new
    }

    // This needs to be recursive?
    pub fn validate_filter(&self, filt: &Filter) -> Result<(), SchemaError> {
        match filt {
            Filter::Eq(attr, value) => match self.attributes.get(attr) {
                Some(schema_a) => schema_a.validate_value(value),
                None => Err(SchemaError::InvalidAttribute),
            },
            Filter::Sub(attr, value) => match self.attributes.get(attr) {
                Some(schema_a) => schema_a.validate_value(value),
                None => Err(SchemaError::InvalidAttribute),
            },
            Filter::Pres(attr) => {
                // This could be better as a contains_key
                // because we never use the value
                match self.attributes.get(attr) {
                    Some(_) => Ok(()),
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            Filter::Or(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EmptyFilter);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate_filter(filt)
                    } else {
                        acc
                    }
                })
            }
            Filter::And(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EmptyFilter);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate_filter(filt)
                    } else {
                        acc
                    }
                })
            }
            Filter::Not(filter) => {
                self.validate_filter(filter)
            }
        }
    }

    // Normalise *does not* validate.
    // Normalise just fixes some possible common issues, but it
    // can't fix *everything* possibly wrong ...
    pub fn normalise_filter(&mut self) {
        unimplemented!()
    }

    fn is_multivalue(&self, attr_name: &str) -> Result<bool, SchemaError> {
        match self.attributes.get(attr_name) {
            Some(a_schema) => {
                Ok(a_schema.multivalue)
            }
            None => {
                return Err(SchemaError::InvalidAttribute);
            }
        }
    }
}

// type Schema = CowCell<SchemaInner>;

pub struct Schema {
    inner: CowCell<SchemaInner>,
}

pub struct SchemaWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, SchemaInner>,
}

impl<'a> SchemaWriteTransaction<'a> {
    pub fn bootstrap_core(&mut self, audit: &mut AuditScope) -> Result<(), ()> {
        self.inner.bootstrap_core(audit)
    }

    // TODO: Schema probably needs to be part of the backend, so that commits are wholly atomic
    // but in the current design, we need to open be first, then schema, but we have to commit be
    // first, then schema to ensure that the be content matches our schema. Saying this, if your
    // schema commit fails we need to roll back still .... How great are transactions.
    // At the least, this is what validation is for!
    pub fn commit(self) {
        self.inner.commit();
    }
}

impl<'a> SchemaReadTransaction for SchemaWriteTransaction<'a> {
    fn get_inner(&self) -> &SchemaInner {
        // Does this deref the CowCell for us?
        &self.inner
    }
}

pub struct SchemaTransaction {
    inner: CowCellReadTxn<SchemaInner>,
}

impl SchemaReadTransaction for SchemaTransaction {
    fn get_inner(&self) -> &SchemaInner {
        // Does this deref the CowCell for us?
        &self.inner
    }
}

impl Schema {
    pub fn new(audit: &mut AuditScope) -> Result<Self, ()> {
        SchemaInner::new(audit).map(|si| Schema {
            inner: CowCell::new(si),
        })
    }

    pub fn read(&self) -> SchemaTransaction {
        SchemaTransaction {
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
    use super::super::audit::AuditScope;
    use super::super::constants::*;
    use super::super::entry::Entry;
    use super::super::error::SchemaError;
    use super::super::filter::Filter;
    use super::{IndexType, Schema, SchemaAttribute, SchemaClass, SyntaxType};
    use schema::SchemaReadTransaction;
    use serde_json;
    use std::convert::TryFrom;
    use uuid::Uuid;

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
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PRINCIPAL_NAME).unwrap(),
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
    fn test_schema_normalise_uuid() {
        let sa = SchemaAttribute {
            name: String::from("uuid"),
            uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UUID).unwrap(),
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
        let schema = Schema::new(&mut audit).unwrap();
        let schema_ro = schema.read();
        assert!(schema_ro.validate(&mut audit).is_ok());
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
        let schema_outer = Schema::new(&mut audit).unwrap();
        let schema = schema_outer.read();
        let e_no_class: Entry = serde_json::from_str(
            r#"{
            "attrs": {}
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_no_class),
            Err(SchemaError::InvalidClass)
        );

        let e_bad_class: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["zzzzzz"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_entry(&e_bad_class),
            Err(SchemaError::InvalidClass)
        );

        let e_attr_invalid: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"]
            }
        }"#,
        )
        .unwrap();

        let res = schema.validate_entry(&e_attr_invalid);
        assert!(match res {
            Err(SchemaError::MissingMustAttribute(_)) => true,
            _ => false,
        });

        let e_attr_invalid_may: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
                "multivalue": ["false"],
                "syntax": ["UTF8STRING"],
                "zzzzz": ["zzzz"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid_may),
            Err(SchemaError::InvalidAttribute)
        );

        let e_attr_invalid_syn: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
                "multivalue": ["zzzzz"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_attr_invalid_syn),
            Err(SchemaError::InvalidAttributeSyntax)
        );

        let e_ok: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["attributetype"],
                "name": ["testattr"],
                "description": ["testattr"],
                "system": ["false"],
                "secret": ["false"],
                "multivalue": ["true"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_ok), Ok(()));
        println!("{}", audit);
    }

    #[test]
    fn test_schema_entry_normalise() {
        // Check that entries can be normalised sanely
        let mut audit = AuditScope::new("test_schema_entry_normalise");
        let mut schema_outer = Schema::new(&mut audit).unwrap();
        let mut schema = schema_outer.write();
        schema.bootstrap_core(&mut audit).unwrap();

        // Check syntax to upper
        // check index to upper
        // insense to lower
        // attr name to lower
        let e_test: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["TestPerson"],
                "displayName": ["testperson"],
                "syntax": ["utf8string"],
                "index": ["equality"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_entry(&e_test),
            Err(SchemaError::InvalidAttributeSyntax)
        );

        let e_expect: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["testperson"],
                "displayname": ["testperson"],
                "syntax": ["UTF8STRING"],
                "index": ["EQUALITY"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_expect), Ok(()));

        let e_normalised = schema.normalise_entry(&e_test);

        assert_eq!(schema.validate_entry(&e_normalised), Ok(()));
        assert_eq!(e_expect, e_normalised);
        println!("{}", audit);
    }

    #[test]
    fn test_schema_extensible() {
        let mut audit = AuditScope::new("test_schema_extensible");
        let schema_outer = Schema::new(&mut audit).unwrap();
        let schema = schema_outer.read();
        // Just because you are extensible, doesn't mean you can be lazy

        let e_extensible_bad: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "secret": ["zzzz"]
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            schema.validate_entry(&e_extensible_bad),
            Err(SchemaError::InvalidAttributeSyntax)
        );

        let e_extensible: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "secret": ["true"]
            }
        }"#,
        )
        .unwrap();

        /* Is okay because extensible! */
        assert_eq!(schema.validate_entry(&e_extensible), Ok(()));
        println!("{}", audit);
    }

    #[test]
    fn test_schema_loading() {
        // Validate loading schema from entries
    }

    #[test]
    fn test_schema_bootstrap() {
        let mut audit = AuditScope::new("test_schema_bootstrap");
        let mut schema_outer = Schema::new(&mut audit).unwrap();
        let mut schema = schema_outer.write();
        schema.bootstrap_core(&mut audit).unwrap();

        // now test some entries
        let e_person: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "principal_name": ["testperson@project.org"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_person), Ok(()));

        let e_group: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "principal_name": ["testgroup@project.org"],
                "description": ["testperson"]
            }
        }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_entry(&e_group), Ok(()));
        println!("{}", audit);
    }

    #[test]
    fn test_schema_filter_validation() {
        let mut audit = AuditScope::new("test_schema_filter_validation");
        let schema_outer = Schema::new(&mut audit).unwrap();
        let schema = schema_outer.read();
        // Test mixed case attr name
        let f_mixed: Filter = serde_json::from_str(
            r#"{
            "Eq": [
                "ClAsS", "attributetype"
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_mixed),
            Err(SchemaError::InvalidAttribute)
        );
        // test syntax of bool
        let f_bool: Filter = serde_json::from_str(
            r#"{
            "Eq": [
                "secret", "zzzz"
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_bool),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        // test insensitise values
        let f_insense: Filter = serde_json::from_str(
            r#"{
            "Eq": [
                "class", "AttributeType"
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_insense),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        // Test the recursive structures validate
        let f_or_empty: Filter = serde_json::from_str(
            r#"{
            "Or": []
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_or_empty),
            Err(SchemaError::EmptyFilter)
        );
        let f_or: Filter = serde_json::from_str(
            r#"{
            "Or": [
              { "Eq": ["class", "AttributeType"] }
            ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_or),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        let f_or_mult: Filter = serde_json::from_str(
            r#"{
            "Or": [
              { "Eq": ["class", "attributetype"] },
              { "Eq": ["class", "AttributeType"] }
            ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            schema.validate_filter(&f_or_mult),
            Err(SchemaError::InvalidAttributeSyntax)
        );
        let f_or_ok: Filter = serde_json::from_str(
            r#"{
            "Or": [
              { "Eq": ["class", "attributetype"] },
              { "Eq": ["class", "classtype"] }
            ]
            }"#,
        )
        .unwrap();
        assert_eq!(schema.validate_filter(&f_or_ok), Ok(()));
        println!("{}", audit);
    }

    #[test]
    fn test_schema_filter_normalisation() {
        // Test mixed case attr name
        // test syntax of bool
        // test normalise of insensitive strings
    }
}

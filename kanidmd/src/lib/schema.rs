//! [`Schema`] is one of the foundational concepts of the server. It provides a
//! set of rules to enforce that [`Entries`] ava's must be compliant to, to be
//! considered valid for commit to the database. This allows us to provide
//! requirements and structure as to what an [`Entry`] must have and may contain
//! which enables many other parts to function.
//!
//! To define this structure we define [`Attributes`] that provide rules for how
//! and ava should be structured. We also define [`Classes`] that define
//! the rules of which [`Attributes`] may or must exist on an [`Entry`] for it
//! to be considered valid. An [`Entry`] must have at least 1 to infinite
//! [`Classes`]. [`Classes'] are additive.
//!
//! [`Schema`]: struct.Schema.html
//! [`Entries`]: ../entry/index.html
//! [`Entry`]: ../entry/index.html
//! [`Attributes`]: struct.SchemaAttribute.html
//! [`Classes`]: struct.SchemaClass.html

use crate::audit::AuditScope;
use crate::constants::*;
use crate::entry::{Entry, EntryCommitted, EntryInit, EntryNew, EntrySealed};
use crate::value::{IndexType, PartialValue, SyntaxType, Value};
use kanidm_proto::v1::{ConsistencyError, OperationError, SchemaError};

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use concread::collections::bptree::*;
use concread::cowcell::*;

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

// TODO #72: prefix on all schema types that are system?
lazy_static! {
    static ref PVCLASS_ATTRIBUTETYPE: PartialValue = PartialValue::new_class("attributetype");
    static ref PVCLASS_CLASSTYPE: PartialValue = PartialValue::new_class("classtype");
}

/// Schema stores the set of [`Classes`] and [`Attributes`] that the server will
/// use to validate [`Entries`], [`Filters`] and [`Modifications`]. Additionally the
/// schema stores an extracted copy of the current attribute indexing metadata that
/// is used by the backend during queries.
///
/// [`Filters`]: ../filter/index.html
/// [`Modifications`]: ../modify/index.html
/// [`Entries`]: ../entry/index.html
/// [`Attributes`]: struct.SchemaAttribute.html
/// [`Classes`]: struct.SchemaClass.html
pub struct Schema {
    classes: BptreeMap<String, SchemaClass>,
    attributes: BptreeMap<String, SchemaAttribute>,
    /// This is a copy-on-write cache of the index metadata that has been
    /// extracted from attributes set, in the correct format for the backend
    /// to consume.
    idxmeta: CowCell<BTreeSet<(String, IndexType)>>,
}

/// A writable transaction of the working schema set. You should not change this directly,
/// the writability is for the server internally to allow reloading of the schema. Changes
/// you make will be lost when the server re-reads the schema from disk.
pub struct SchemaWriteTransaction<'a> {
    classes: BptreeMapWriteTxn<'a, String, SchemaClass>,
    attributes: BptreeMapWriteTxn<'a, String, SchemaAttribute>,
    idxmeta: CowCellWriteTxn<'a, BTreeSet<(String, IndexType)>>,
}

/// A readonly transaction of the working schema set.
pub struct SchemaReadTransaction {
    classes: BptreeMapReadTxn<String, SchemaClass>,
    attributes: BptreeMapReadTxn<String, SchemaAttribute>,
    idxmeta: CowCellReadTxn<BTreeSet<(String, IndexType)>>,
}

/// An item reperesenting an attribute and the rules that enforce it. These rules enforce if an
/// attribute on an [`Entry`] may be single or multi value, must be unique amongst all other types
/// of this attribute, if the attribute should be [`indexed`], and what type of data [`syntax`] it may hold.
///
/// [`Entry`]: ../entry/index.html
/// [`indexed`]: ../value/enum.IndexType.html
/// [`syntax`]: ../value/enum.SyntaxType.html
#[derive(Debug, Clone)]
pub struct SchemaAttribute {
    // Is this ... used?
    // class: Vec<String>,
    pub name: String,
    pub uuid: Uuid,
    // Perhaps later add aliases?
    pub description: String,
    pub multivalue: bool,
    pub unique: bool,
    pub phantom: bool,
    pub index: Vec<IndexType>,
    pub syntax: SyntaxType,
}

impl SchemaAttribute {
    pub fn try_from(
        audit: &mut AuditScope,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Convert entry to a schema attribute.
        ltrace!(audit, "Converting -> {:?}", value);
        // class
        if !value.attribute_value_pres("class", &PVCLASS_ATTRIBUTETYPE) {
            ladmin_error!(audit, "class attribute type not present");
            return Err(OperationError::InvalidSchemaState(
                "missing attributetype".to_string(),
            ));
        }

        // uuid
        let uuid = *value.get_uuid();

        // name
        let name = try_audit!(
            audit,
            value.get_ava_single_string("attributename").ok_or_else(|| {
                OperationError::InvalidSchemaState("missing attributename".to_string())
            })
        );
        // description
        let description = try_audit!(
            audit,
            value.get_ava_single_string("description").ok_or_else(|| {
                OperationError::InvalidSchemaState("missing description".to_string())
            })
        );

        // multivalue
        let multivalue = try_audit!(
            audit,
            value.get_ava_single_bool("multivalue").ok_or_else(|| {
                OperationError::InvalidSchemaState("missing multivalue".to_string())
            })
        );
        let unique = try_audit!(
            audit,
            value
                .get_ava_single_bool("unique")
                .ok_or_else(|| OperationError::InvalidSchemaState("missing unique".to_string()))
        );
        let phantom = value.get_ava_single_bool("phantom").unwrap_or(false);
        // index vec
        // even if empty, it SHOULD be present ... (is that value to put an empty set?)
        // The get_ava_opt_index handles the optional case for us :)
        let index = try_audit!(
            audit,
            value
                .get_ava_opt_index("index")
                .and_then(|vv: Vec<&IndexType>| Ok(vv.into_iter().cloned().collect()))
                .map_err(|_| OperationError::InvalidSchemaState("Invalid index".to_string()))
        );
        // syntax type
        let syntax = try_audit!(
            audit,
            value
                .get_ava_single_syntax("syntax")
                .cloned()
                .ok_or_else(|| OperationError::InvalidSchemaState("missing syntax".to_string()))
        );

        Ok(SchemaAttribute {
            name,
            uuid,
            description,
            multivalue,
            unique,
            phantom,
            index,
            syntax,
        })
    }

    // There may be a difference between a value and a filter value on complex
    // types - IE a complex type may have multiple parts that are secret, but a filter
    // on that may only use a single tagged attribute for example.
    pub fn validate_partialvalue(&self, a: &str, v: &PartialValue) -> Result<(), SchemaError> {
        let r = match self.syntax {
            SyntaxType::BOOLEAN => v.is_bool(),
            SyntaxType::SYNTAX_ID => v.is_syntax(),
            SyntaxType::INDEX_ID => v.is_index(),
            SyntaxType::UUID => v.is_uuid(),
            SyntaxType::REFERENCE_UUID => v.is_refer(),
            SyntaxType::UTF8STRING_INSENSITIVE => v.is_iutf8(),
            SyntaxType::UTF8STRING_INAME => v.is_iname(),
            SyntaxType::UTF8STRING => v.is_utf8(),
            SyntaxType::JSON_FILTER => v.is_json_filter(),
            SyntaxType::CREDENTIAL => v.is_credential(),
            SyntaxType::RADIUS_UTF8STRING => v.is_radius_string(),
            SyntaxType::SSHKEY => v.is_sshkey(),
            SyntaxType::SERVICE_PRINCIPLE_NAME => v.is_spn(),
            SyntaxType::UINT32 => v.is_uint32(),
            SyntaxType::CID => v.is_cid(),
            SyntaxType::NSUNIQUEID => v.is_nsuniqueid(),
        };
        if r {
            Ok(())
        } else {
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }

    pub fn validate_value(&self, a: &str, v: &Value) -> Result<(), SchemaError> {
        let r = v.validate();
        if cfg!(test) {
            assert!(r);
        }
        if r {
            let pv: &PartialValue = v.borrow();
            self.validate_partialvalue(a, pv)
        } else {
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }

    pub fn validate_ava(&self, a: &str, ava: &BTreeSet<Value>) -> Result<(), SchemaError> {
        // ltrace!("Checking for valid {:?} -> {:?}", self.name, ava);
        // Check multivalue
        if !self.multivalue && ava.len() > 1 {
            // lrequest_error!("Ava len > 1 on single value attribute!");
            return Err(SchemaError::InvalidAttributeSyntax(a.to_string()));
        };
        // If syntax, check the type is correct
        match self.syntax {
            SyntaxType::BOOLEAN => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_bool() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::SYNTAX_ID => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_syntax() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::UUID => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_uuid() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            // This is the same as a UUID, refint is a plugin
            SyntaxType::REFERENCE_UUID => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_refer() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::INDEX_ID => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_index() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::UTF8STRING_INSENSITIVE => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_insensitive_utf8() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::UTF8STRING_INAME => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_iname() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::UTF8STRING => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_utf8() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::JSON_FILTER => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_json_filter() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::CREDENTIAL => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_credential() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::RADIUS_UTF8STRING => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_radius_string() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::SSHKEY => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_sshkey() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::SERVICE_PRINCIPLE_NAME => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_spn() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::UINT32 => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_uint32() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::CID => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_cid() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::NSUNIQUEID => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_nsuniqueid() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
        }
    }
}

/// An item reperesenting a class and the rules for that class. These rules enforce that an
/// [`Entry`]'s avas conform to a set of requirements, giving structure to an entry about
/// what avas must or may exist. The kanidm project provides attributes in `systemmust` and
/// `systemmay`, which can not be altered. An administrator may extend these in the `must`
/// and `may` attributes.
///
/// Classes are additive, meaning that if there are two classes, the `may` rules of both union,
/// and that if an attribute is `must` on one class, and `may` in another, the `must` rule
/// takes precedence. It is not possible to combine classes in an incompatible way due to these
/// rules.
///
/// That in mind, and entry that has one of every possible class would probably be nonsensical,
/// but the addition rules make it easy to construct and understand with concepts like [`access`]
/// controls or accounts and posix extensions.
///
/// [`Entry`]: ../entry/index.html
/// [`access`]: ../access/index.html
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
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        ltrace!(audit, "Converting {:?}", value);
        // Convert entry to a schema class.
        if !value.attribute_value_pres("class", &PVCLASS_CLASSTYPE) {
            ladmin_error!(audit, "class classtype not present");
            return Err(OperationError::InvalidSchemaState(
                "missing classtype".to_string(),
            ));
        }

        // uuid
        let uuid = *value.get_uuid();

        // name
        let name = try_audit!(
            audit,
            value
                .get_ava_single_string("classname")
                .ok_or_else(|| OperationError::InvalidSchemaState("missing classname".to_string()))
        );
        // description
        let description = try_audit!(
            audit,
            value.get_ava_single_string("description").ok_or_else(|| {
                OperationError::InvalidSchemaState("missing description".to_string())
            })
        );

        // These are all "optional" lists of strings.
        let systemmay = value.get_ava_opt_string("systemmay").ok_or_else(|| {
            OperationError::InvalidSchemaState("Missing or invalid systemmay".to_string())
        })?;
        let systemmust = value.get_ava_opt_string("systemmust").ok_or_else(|| {
            OperationError::InvalidSchemaState("Missing or invalid systemmust".to_string())
        })?;
        let may = value.get_ava_opt_string("may").ok_or_else(|| {
            OperationError::InvalidSchemaState("Missing or invalid may".to_string())
        })?;
        let must = value.get_ava_opt_string("must").ok_or_else(|| {
            OperationError::InvalidSchemaState("Missing or invalid must".to_string())
        })?;

        Ok(SchemaClass {
            name,
            uuid,
            description,
            systemmay,
            systemmust,
            may,
            must,
        })
    }
}

pub trait SchemaTransaction {
    fn get_classes(&self) -> BptreeMapReadSnapshot<String, SchemaClass>;
    fn get_attributes(&self) -> BptreeMapReadSnapshot<String, SchemaAttribute>;
    fn get_idxmeta(&self) -> &BTreeSet<(String, IndexType)>;

    fn validate(&self, _audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let mut res = Vec::new();

        let class_snapshot = self.get_classes();
        let attribute_snapshot = self.get_attributes();
        // Does this need to validate anything further at all? The UUID
        // will be checked as part of the schema migration on startup, so I think
        // just that all the content is sane is fine.
        class_snapshot.values().for_each(|class| {
            // report the class we are checking
            class
                .systemmay
                .iter()
                .chain(class.may.iter())
                .chain(class.systemmust.iter())
                .chain(class.must.iter())
                .for_each(|a| {
                    match attribute_snapshot.get(a) {
                        Some(attr) => {
                            // We have the attribute, ensure it's not a phantom.
                            if attr.phantom {
                                res.push(Err(ConsistencyError::SchemaClassPhantomAttribute(
                                    class.name.clone(),
                                    a.clone(),
                                )))
                            }
                        }
                        None => {
                            // No such attr, something is missing!
                            res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                                class.name.clone(),
                                a.clone(),
                            )))
                        }
                    }
                })
        }); // end for
        res
    }

    fn is_multivalue(&self, attr: &str) -> Result<bool, SchemaError> {
        match self.get_attributes().get(attr) {
            Some(a_schema) => Ok(a_schema.multivalue),
            None => {
                // ladmin_error!("Attribute does not exist?!");
                Err(SchemaError::InvalidAttribute(attr.to_string()))
            }
        }
    }

    fn normalise_attr_name(&self, an: &str) -> String {
        // Will duplicate.
        an.to_lowercase()
    }

    fn normalise_attr_if_exists(&self, an: &str) -> Option<String> {
        if self.get_attributes().contains_key(an) {
            Some(self.normalise_attr_name(an))
        } else {
            None
        }
    }

    fn get_attributes_unique(&self) -> Vec<String> {
        // This could be improved by caching this set on schema reload!
        self.get_attributes()
            .iter()
            .filter_map(|(k, v)| if v.unique { Some(k.clone()) } else { None })
            .collect()
    }

    // Probably need something like get_classes or similar
    // so that externals can call and use this data.

    fn get_reference_types(&self) -> BTreeMap<String, SchemaAttribute> {
        let snapshot = self.get_attributes();
        snapshot
            .iter()
            .filter(|(_, sa)| match &sa.syntax {
                SyntaxType::REFERENCE_UUID => true,
                _ => false,
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn get_idxmeta_set(&self) -> &BTreeSet<(String, IndexType)> {
        self.get_idxmeta()
    }
}

impl<'a> SchemaWriteTransaction<'a> {
    // Schema probably needs to be part of the backend, so that commits are wholly atomic
    // but in the current design, we need to open be first, then schema, but we have to commit be
    // first, then schema to ensure that the be content matches our schema. Saying this, if your
    // schema commit fails we need to roll back still .... How great are transactions.
    // At the least, this is what validation is for!
    pub fn commit(self) -> Result<(), OperationError> {
        let SchemaWriteTransaction {
            classes,
            attributes,
            idxmeta,
        } = self;

        classes.commit();
        attributes.commit();
        idxmeta.commit();
        Ok(())
    }

    pub fn update_attributes(
        &mut self,
        attributetypes: Vec<SchemaAttribute>,
    ) -> Result<(), OperationError> {
        // purge all old attributes.
        self.attributes.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        attributetypes.into_iter().for_each(|a| {
            self.attributes.insert(a.name.clone(), a);
        });
        // Now update the idxmeta
        self.reload_idxmeta();

        Ok(())
    }

    pub fn update_classes(&mut self, classtypes: Vec<SchemaClass>) -> Result<(), OperationError> {
        // purge all old attributes.
        self.classes.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        classtypes.into_iter().for_each(|a| {
            self.classes.insert(a.name.clone(), a);
        });
        Ok(())
    }

    fn reload_idxmeta(&mut self) {
        self.idxmeta.clear();
        self.idxmeta.extend(self.attributes.values().flat_map(|a| {
            a.index
                .iter()
                .map(move |itype: &IndexType| (a.name.clone(), (*itype).clone()))
        }));
    }

    pub fn to_entries(&self) -> Vec<Entry<EntryInit, EntryNew>> {
        let r: Vec<_> = self
            .attributes
            .values()
            .map(Entry::<EntryInit, EntryNew>::from)
            .chain(
                self.classes
                    .values()
                    .map(Entry::<EntryInit, EntryNew>::from),
            )
            .collect();
        r
    }

    pub fn generate_in_memory(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "schema::generate_in_memory", || {
            //
            self.classes.clear();
            self.attributes.clear();
            self.idxmeta.clear();
            // Bootstrap in definitions of our own schema types
            // First, add all the needed core attributes for schema parsing
            self.attributes.insert(
                String::from("class"),
                SchemaAttribute {
                    name: String::from("class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_CLASS)
                        .expect("unable to parse const uuid"),
                    description: String::from("The set of classes defining an object"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY, IndexType::PRESENCE],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("uuid"),
                SchemaAttribute {
                    name: String::from("uuid"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UUID)
                        .expect("unable to parse const uuid"),
                    description: String::from("The universal unique id of the object"),
                    multivalue: false,
                    // Uniqueness is handled by base.rs, not attrunique here due to
                    // needing to check recycled objects too.
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY, IndexType::PRESENCE],
                    syntax: SyntaxType::UUID,
                },
            );
            self.attributes.insert(
                String::from("last_modified_cid"),
                SchemaAttribute {
                    name: String::from("last_modified_cid"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_LAST_MOD_CID)
                        .expect("unable to parse const uuid"),
                    description: String::from("The cid of the last change to this object"),
                    multivalue: false,
                    // Uniqueness is handled by base.rs, not attrunique here due to
                    // needing to check recycled objects too.
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::CID,
                },
            );
            self.attributes.insert(
                String::from("name"),
                SchemaAttribute {
                    name: String::from("name"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_NAME)
                        .expect("unable to parse const uuid"),
                    description: String::from("The shortform name of an object"),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::EQUALITY, IndexType::PRESENCE],
                    syntax: SyntaxType::UTF8STRING_INAME,
                },
            );
            self.attributes.insert(
                String::from("spn"),
                SchemaAttribute {
                    name: String::from("spn"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SPN)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "The service principle name of an object, unique across all domain trusts",
                    ),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::SERVICE_PRINCIPLE_NAME,
                },
            );
            self.attributes.insert(
                String::from("attributename"),
                SchemaAttribute {
                    name: String::from("attributename"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ATTRIBUTENAME)
                        .expect("unable to parse const uuid"),
                    description: String::from("The name of a schema attribute"),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("classname"),
                SchemaAttribute {
                    name: String::from("classname"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_CLASSNAME)
                        .expect("unable to parse const uuid"),
                    description: String::from("The name of a schema class"),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("description"),
                SchemaAttribute {
                    name: String::from("description"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DESCRIPTION)
                        .expect("unable to parse const uuid"),
                    description: String::from("A description of an attribute, object or class"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            self.attributes.insert(String::from("multivalue"), SchemaAttribute {
                name: String::from("multivalue"),
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MULTIVALUE).expect("unable to parse const uuid"),
                description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
                multivalue: false,
                unique: false,
                phantom: false,
                index: vec![],
                syntax: SyntaxType::BOOLEAN,
            });
            self.attributes.insert(String::from("phantom"), SchemaAttribute {
                name: String::from("phantom"),
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PHANTOM).expect("unable to parse const uuid"),
                description: String::from("If true, this attribute must NOT be present in any may/must sets of a class as. This represents generated attributes."),
                multivalue: false,
                unique: false,
                phantom: false,
                index: vec![],
                syntax: SyntaxType::BOOLEAN,
            });
            self.attributes.insert(String::from("unique"), SchemaAttribute {
                name: String::from("unique"),
                uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_UNIQUE).expect("unable to parse const uuid"),
                description: String::from("If true, this attribute must store a unique value through out the database."),
                multivalue: false,
                unique: false,
                phantom: false,
                index: vec![],
                syntax: SyntaxType::BOOLEAN,
            });
            self.attributes.insert(
                String::from("index"),
                SchemaAttribute {
                    name: String::from("index"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_INDEX)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "Describe the indexes to apply to instances of this attribute.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::INDEX_ID,
                },
            );
            self.attributes.insert(
                String::from("syntax"),
                SchemaAttribute {
                    name: String::from("syntax"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYNTAX)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "Describe the syntax of this attribute. This affects indexing and sorting.",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::SYNTAX_ID,
                },
            );
            self.attributes.insert(
                String::from("systemmay"),
                SchemaAttribute {
                    name: String::from("systemmay"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMAY)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "A list of system provided optional attributes this class can store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("may"),
                SchemaAttribute {
                    name: String::from("may"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MAY)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "A user modifiable list of optional attributes this class can store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("systemmust"),
                SchemaAttribute {
                    name: String::from("systemmust"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_SYSTEMMUST)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "A list of system provided required attributes this class must store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("must"),
                SchemaAttribute {
                    name: String::from("must"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MUST)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "A user modifiable list of required attributes this class must store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // SYSINFO attrs
            // ACP attributes.
            self.attributes.insert(
                String::from("acp_enable"),
                SchemaAttribute {
                    name: String::from("acp_enable"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_ENABLE)
                        .expect("unable to parse const uuid"),
                    description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforce. False is checked but not enforced."),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::BOOLEAN,
                },
            );

            self.attributes.insert(
                String::from("acp_receiver"),
                SchemaAttribute {
                    name: String::from("acp_receiver"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_RECEIVER)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "Who the ACP applies to, constraining or allowing operations.",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            self.attributes.insert(
                String::from("acp_targetscope"),
                SchemaAttribute {
                    name: String::from("acp_targetscope"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_TARGETSCOPE)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "The effective targets of the ACP, IE what will be acted upon.",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY, IndexType::SUBSTRING],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            self.attributes.insert(
                String::from("acp_search_attr"),
                SchemaAttribute {
                    name: String::from("acp_search_attr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR)
                        .expect("unable to parse const uuid"),
                    description: String::from("The attributes that may be viewed or searched by the reciever on targetscope."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_create_class"),
                SchemaAttribute {
                    name: String::from("acp_create_class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_CREATE_CLASS)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "The set of classes that can be created on a new entry.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_create_attr"),
                SchemaAttribute {
                    name: String::from("acp_create_attr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_CREATE_ATTR)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "The set of attribute types that can be created on an entry.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );

            self.attributes.insert(
                String::from("acp_modify_removedattr"),
                SchemaAttribute {
                    name: String::from("acp_modify_removedattr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR)
                        .expect("unable to parse const uuid"),
                    description: String::from("The set of attribute types that could be removed or purged in a modification."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_modify_presentattr"),
                SchemaAttribute {
                    name: String::from("acp_modify_presentattr"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR)
                        .expect("unable to parse const uuid"),
                    description: String::from("The set of attribute types that could be added or asserted in a modification."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("acp_modify_class"),
                SchemaAttribute {
                    name: String::from("acp_modify_class"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS)
                        .expect("unable to parse const uuid"),
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // MO/Member
            self.attributes.insert(
                String::from("memberof"),
                SchemaAttribute {
                    name: String::from("memberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBEROF)
                        .expect("unable to parse const uuid"),
                    description: String::from("reverse group membership of the object"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            self.attributes.insert(
                String::from("directmemberof"),
                SchemaAttribute {
                    name: String::from("directmemberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DIRECTMEMBEROF)
                        .expect("unable to parse const uuid"),
                    description: String::from("reverse direct group membership of the object"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            self.attributes.insert(
                String::from("member"),
                SchemaAttribute {
                    name: String::from("member"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_MEMBER)
                        .expect("unable to parse const uuid"),
                    description: String::from("List of members of the group"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            // Migration related
            self.attributes.insert(
                String::from("version"),
                SchemaAttribute {
                    name: String::from("version"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_VERSION)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "The systems internal migration version for provided objects",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UINT32,
                },
            );
            // Domain for sysinfo
            self.attributes.insert(
                String::from("domain"),
                SchemaAttribute {
                    name: String::from("domain"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DOMAIN)
                        .expect("unable to parse const uuid"),
                    description: String::from("A DNS Domain name entry."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::EQUALITY],
                    syntax: SyntaxType::UTF8STRING_INAME,
                },
            );
            self.attributes.insert(
                String::from("claim"),
                SchemaAttribute {
                    name: String::from("claim"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_CLAIM)
                        .expect("unable to parse const uuid"),
                    description: String::from("The spn of a claim this entry holds"),
                    multivalue: true,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::SERVICE_PRINCIPLE_NAME,
                },
            );
            self.attributes.insert(
                String::from("password_import"),
                SchemaAttribute {
                    name: String::from("password_import"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_PASSWORD_IMPORT)
                        .expect("unable to parse const uuid"),
                    description: String::from("An imported password hash from an external system."),
                    multivalue: true,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );

            // LDAP Masking Phantoms
            self.attributes.insert(
                String::from("dn"),
                SchemaAttribute {
                    name: String::from("dn"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_DN).expect("unable to parse const uuid"),
                    description: String::from("An LDAP Compatible DN"),
                    multivalue: false,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            self.attributes.insert(
                String::from("entryuuid"),
                SchemaAttribute {
                    name: String::from("entryuuid"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_ENTRYUUID)
                        .expect("unable to parse const uuid"),
                    description: String::from("An LDAP Compatible entryUUID"),
                    multivalue: false,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::UUID,
                },
            );
            self.attributes.insert(
                String::from("objectclass"),
                SchemaAttribute {
                    name: String::from("objectclass"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_ATTR_OBJECTCLASS)
                        .expect("unable to parse const uuid"),
                    description: String::from("An LDAP Compatible objectClass"),
                    multivalue: true,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING_INSENSITIVE,
                },
            );
            // end LDAP masking phantoms

            self.classes.insert(
                String::from("attributetype"),
                SchemaClass {
                    name: String::from("attributetype"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ATTRIBUTETYPE)
                        .expect("unable to parse const uuid"),
                    description: String::from("Definition of a schema attribute"),
                    systemmay: vec![String::from("phantom"), String::from("index")],
                    may: vec![],
                    systemmust: vec![
                        String::from("class"),
                        String::from("attributename"),
                        String::from("multivalue"),
                        String::from("unique"),
                        String::from("syntax"),
                        String::from("description"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("classtype"),
                SchemaClass {
                    name: String::from("classtype"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_CLASSTYPE)
                        .expect("unable to parse const uuid"),
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
                        String::from("classname"),
                        String::from("description"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("object"),
                SchemaClass {
                    name: String::from("object"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_OBJECT)
                        .expect("unable to parse const uuid"),
                    description: String::from(
                        "A system created class that all objects must contain",
                    ),
                    systemmay: vec![String::from("description")],
                    may: vec![],
                    systemmust: vec![
                        String::from("class"),
                        String::from("uuid"),
                        String::from("last_modified_cid"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("memberof"),
                SchemaClass {
                    name: String::from("memberof"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_MEMBEROF)
                        .expect("unable to parse const uuid"),
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
            self.classes.insert(
                String::from("extensibleobject"),
                SchemaClass {
                    name: String::from("extensibleobject"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT)
                        .expect("unable to parse const uuid"),
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
            self.classes.insert(
                String::from("recycled"),
                SchemaClass {
                    name: String::from("recycled"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_RECYCLED).expect("unable to parse const uuid"),
                    description: String::from("An object that has been deleted, but still recoverable via the revive operation. Recycled objects are not modifiable, only revivable."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("tombstone"),
                SchemaClass {
                    name: String::from("tombstone"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_TOMBSTONE).expect("unable to parse const uuid"),
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
            self.classes.insert(
                String::from("system_info"),
                SchemaClass {
                    name: String::from("system_info"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_SYSTEM_INFO)
                        .expect("unable to parse const uuid"),
                    description: String::from("System metadata object class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![
                        String::from("version"),
                        // Needed when we implement principalnames?
                        // String::from("domain"),
                        // String::from("hostname"),
                    ],
                    must: vec![],
                },
            );
            // ACP
            self.classes.insert(
                String::from("access_control_profile"),
                SchemaClass {
                    name: String::from("access_control_profile"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE)
                        .expect("unable to parse const uuid"),
                    description: String::from("System Access Control Profile Class"),
                    systemmay: vec!["acp_enable".to_string(), "description".to_string()],
                    may: vec![],
                    systemmust: vec![
                        "acp_receiver".to_string(),
                        "acp_targetscope".to_string(),
                        "name".to_string(),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                String::from("access_control_search"),
                SchemaClass {
                    name: String::from("access_control_search"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH)
                        .expect("unable to parse const uuid"),
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
                        .expect("unable to parse const uuid"),
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
                        .expect("unable to parse const uuid"),
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
                        .expect("unable to parse const uuid"),
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
            self.classes.insert(
                String::from("system"),
                SchemaClass {
                    name: String::from("system"),
                    uuid: Uuid::parse_str(UUID_SCHEMA_CLASS_SYSTEM)
                        .expect("unable to parse const uuid"),
                    description: String::from("A class denoting that a type is system generated and protected. It has special internal behaviour."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );

            let r = self.validate(audit);
            if r.is_empty() {
                ladmin_info!(audit, "schema validate -> passed");
                self.reload_idxmeta();
                Ok(())
            } else {
                ladmin_info!(audit, "schema validate -> errors {:?}", r);
                Err(OperationError::ConsistencyError(r))
            }
        })
    }
}

impl<'a> SchemaTransaction for SchemaWriteTransaction<'a> {
    fn get_classes(&self) -> BptreeMapReadSnapshot<String, SchemaClass> {
        self.classes.to_snapshot()
    }

    fn get_attributes(&self) -> BptreeMapReadSnapshot<String, SchemaAttribute> {
        self.attributes.to_snapshot()
    }

    fn get_idxmeta(&self) -> &BTreeSet<(String, IndexType)> {
        &self.idxmeta
    }
}

impl SchemaTransaction for SchemaReadTransaction {
    fn get_classes(&self) -> BptreeMapReadSnapshot<String, SchemaClass> {
        self.classes.to_snapshot()
    }

    fn get_attributes(&self) -> BptreeMapReadSnapshot<String, SchemaAttribute> {
        self.attributes.to_snapshot()
    }

    fn get_idxmeta(&self) -> &BTreeSet<(String, IndexType)> {
        &(*self.idxmeta)
    }
}

impl Schema {
    pub fn new(audit: &mut AuditScope) -> Result<Self, OperationError> {
        let s = Schema {
            classes: BptreeMap::new(),
            attributes: BptreeMap::new(),
            idxmeta: CowCell::new(BTreeSet::new()),
        };
        let mut sw = s.write();
        let r1 = sw.generate_in_memory(audit);
        debug_assert!(r1.is_ok());
        r1?;
        let r2 = sw.commit().map(|_| s);
        debug_assert!(r2.is_ok());
        r2
    }

    pub fn read(&self) -> SchemaReadTransaction {
        SchemaReadTransaction {
            classes: self.classes.read(),
            attributes: self.attributes.read(),
            idxmeta: self.idxmeta.read(),
        }
    }

    pub fn write(&self) -> SchemaWriteTransaction {
        SchemaWriteTransaction {
            classes: self.classes.write(),
            attributes: self.attributes.write(),
            idxmeta: self.idxmeta.write(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    // use crate::constants::*;
    use crate::entry::{Entry, EntryInit, EntryInvalid, EntryNew, EntryValid};
    use kanidm_proto::v1::{ConsistencyError, SchemaError};
    // use crate::filter::{Filter, FilterValid};
    use crate::schema::SchemaTransaction;
    use crate::schema::{IndexType, Schema, SchemaAttribute, SchemaClass, SyntaxType};
    use crate::value::{PartialValue, Value};
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
            let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_sealed_committed() };

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
            let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_sealed_committed() };

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
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "unique": ["false"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "multivalue": ["false"],
                        "unique": ["false"],
                        "index": ["EQUALITY"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["htouaoeu"],
                        "unique": ["false"],
                        "index": ["EQUALITY"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "unique": ["false"],
                        "index": ["NTEHNOU"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "unique": ["false"],
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
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "unique": ["false"],
                        "syntax": ["UTF8STRING"]
                    }
                }"#,
                SchemaAttribute
            );

            // Index present
            sch_from_entry_ok!(
                audit,
                r#"{
                    "attrs": {
                        "class": ["object", "attributetype"],
                        "attributename": ["schema_attr_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"],
                        "description": ["Test attr parsing"],
                        "multivalue": ["false"],
                        "unique": ["false"],
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
                    "attrs": {
                        "class": ["object", "classtype"],
                        "classname": ["schema_class_test"],
                        "uuid": ["66c68b2f-d02c-4243-8013-7946e40fe321"]
                    }
                }"#,
                SchemaClass
            );

            sch_from_entry_err!(
                audit,
                r#"{
                    "attrs": {
                        "class": ["object"],
                        "classname": ["schema_class_test"],
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
                    "attrs": {
                        "class": ["object", "classtype"],
                        "classname": ["schema_class_test"],
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
                    "attrs": {
                        "class": ["object", "classtype"],
                        "classname": ["schema_class_test"],
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
                    "attrs": {
                        "class": ["object", "classtype"],
                        "classname": ["schema_class_test"],
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
                    "attrs": {
                        "class": ["object", "classtype"],
                        "classname": ["schema_class_test"],
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
                    "attrs": {
                        "class": ["object", "classtype"],
                        "classname": ["schema_class_test"],
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
    fn test_schema_attribute_simple() {
        // Test schemaAttribute validation of types.

        // Test single value string
        let single_value_string = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("single_value"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            unique: false,
            phantom: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING_INSENSITIVE,
        };

        let r1 =
            single_value_string.validate_ava("single_value", &btreeset![Value::new_iutf8s("test")]);
        assert_eq!(r1, Ok(()));

        let r2 = single_value_string.validate_ava(
            "single_value",
            &btreeset![Value::new_iutf8s("test1"), Value::new_iutf8s("test2")],
        );
        assert_eq!(
            r2,
            Err(SchemaError::InvalidAttributeSyntax(
                "single_value".to_string()
            ))
        );

        // test multivalue string, boolean

        let multi_value_string = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("mv_string"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            unique: false,
            phantom: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::UTF8STRING,
        };

        let r5 = multi_value_string.validate_ava(
            "mv_string",
            &btreeset![Value::new_utf8s("test1"), Value::new_utf8s("test2")],
        );
        assert_eq!(r5, Ok(()));

        let multi_value_boolean = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("mv_bool"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            unique: false,
            phantom: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::BOOLEAN,
        };

        let r3 = multi_value_boolean.validate_ava(
            "mv_bool",
            &btreeset![
                Value::new_bool(true),
                Value::new_iutf8s("test1"),
                Value::new_iutf8s("test2")
            ],
        );
        assert_eq!(
            r3,
            Err(SchemaError::InvalidAttributeSyntax("mv_bool".to_string()))
        );

        let r4 = multi_value_boolean.validate_ava(
            "mv_bool",
            &btreeset![Value::new_bool(true), Value::new_bool(false)],
        );
        assert_eq!(r4, Ok(()));

        // syntax_id and index_type values
        let single_value_syntax = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("sv_syntax"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            unique: false,
            phantom: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::SYNTAX_ID,
        };

        let r6 = single_value_syntax.validate_ava(
            "sv_syntax",
            &btreeset![Value::new_syntaxs("UTF8STRING").unwrap()],
        );
        assert_eq!(r6, Ok(()));

        let r7 = single_value_syntax
            .validate_ava("sv_syntax", &btreeset![Value::new_utf8s("thaeountaheu")]);
        assert_eq!(
            r7,
            Err(SchemaError::InvalidAttributeSyntax("sv_syntax".to_string()))
        );

        let single_value_index = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: String::from("sv_index"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            unique: false,
            phantom: false,
            index: vec![IndexType::EQUALITY],
            syntax: SyntaxType::INDEX_ID,
        };
        //
        let r8 = single_value_index.validate_ava(
            "sv_index",
            &btreeset![Value::new_indexs("EQUALITY").unwrap()],
        );
        assert_eq!(r8, Ok(()));

        let r9 = single_value_index
            .validate_ava("sv_index", &btreeset![Value::new_utf8s("thaeountaheu")]);
        assert_eq!(
            r9,
            Err(SchemaError::InvalidAttributeSyntax("sv_index".to_string()))
        );
    }

    #[test]
    fn test_schema_simple() {
        let mut audit = AuditScope::new("test_schema_simple", uuid::Uuid::new_v4(), None);
        let schema = Schema::new(&mut audit).expect("failed to create schema");
        let schema_ro = schema.read();
        validate_schema!(schema_ro, &mut audit);
        audit.write_log();
    }

    #[test]
    fn test_schema_entries() {
        // Given an entry, assert it's schema is valid
        // We do
        let mut audit = AuditScope::new("test_schema_entries", uuid::Uuid::new_v4(), None);
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.read();
        let e_no_uuid: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {}
        }"#,
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_no_uuid.validate(&schema),
            Err(SchemaError::MissingMustAttribute(vec!["uuid".to_string()]))
        );

        let e_no_class: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        assert_eq!(e_no_class.validate(&schema), Err(SchemaError::NoClassFound));

        let e_bad_class: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "class": ["zzzzzz"]
            }
        }"#,
            )
            .into_invalid_new()
        };
        assert_eq!(
            e_bad_class.validate(&schema),
            Err(SchemaError::InvalidClass(vec!["zzzzzz".to_string()]))
        );

        let e_attr_invalid: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "class": ["object", "attributetype"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        let res = e_attr_invalid.validate(&schema);
        assert!(match res {
            Err(SchemaError::MissingMustAttribute(_)) => true,
            _ => false,
        });

        let e_attr_invalid_may: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["object", "attributetype"],
                "attributename": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["false"],
                "unique": ["false"],
                "syntax": ["UTF8STRING"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "zzzzz": ["zzzz"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_attr_invalid_may.validate(&schema),
            Err(SchemaError::InvalidAttribute("zzzzz".to_string()))
        );

        let e_attr_invalid_syn: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["object", "attributetype"],
                "attributename": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["zzzzz"],
                "unique": ["false"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_attr_invalid_syn.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );

        // You may not have the phantom.
        let e_phantom: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["object", "attributetype"],
                "attributename": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["true"],
                "unique": ["false"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "syntax": ["UTF8STRING"],
                "password_import": ["password"]
            }
        }"#,
            )
            .into_invalid_new()
        };
        assert!(e_phantom.validate(&schema).is_err());

        let e_ok: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["object", "attributetype"],
                "attributename": ["testattr"],
                "description": ["testattr"],
                "multivalue": ["true"],
                "unique": ["false"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "syntax": ["UTF8STRING"]
            }
        }"#,
            )
            .into_invalid_new()
        };
        assert!(e_ok.validate(&schema).is_ok());
        audit.write_log();
    }

    #[test]
    fn test_schema_entry_validate() {
        // Check that entries can be normalised and validated sanely
        let mut audit = AuditScope::new("test_schema_entry_validate", uuid::Uuid::new_v4(), None);
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.write();

        // Check syntax to upper
        // check index to upper
        // insense to lower
        // attr name to lower
        let e_test: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "name": ["TestPerson"],
                "syntax": ["utf8string"],
                "UUID": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "InDeX": ["equality"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        let e_expect: Entry<EntryValid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
                "attrs": {
                    "class": ["extensibleobject"],
                    "name": ["testperson"],
                    "syntax": ["UTF8STRING"],
                    "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                    "index": ["EQUALITY"]
                }
            }"#,
            )
            .into_valid_new()
        };

        let e_valid = e_test.validate(&schema).expect("validation failure");

        assert_eq!(e_expect, e_valid);
        audit.write_log();
    }

    #[test]
    fn test_schema_extensible() {
        let mut audit = AuditScope::new("test_schema_extensible", uuid::Uuid::new_v4(), None);
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.read();
        // Just because you are extensible, doesn't mean you can be lazy

        let e_extensible_bad: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "multivalue": ["zzzz"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_extensible_bad.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );

        // Extensible doesn't mean you can have the phantoms
        let e_extensible_phantom: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "password_import": ["zzzz"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_extensible_phantom.validate(&schema),
            Err(SchemaError::PhantomAttribute("password_import".to_string()))
        );

        let e_extensible: Entry<EntryInvalid, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["extensibleobject"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "multivalue": ["true"]
            }
        }"#,
            )
            .into_invalid_new()
        };

        /* Is okay because extensible! */
        assert!(e_extensible.validate(&schema).is_ok());
        audit.write_log();
    }

    #[test]
    fn test_schema_filter_validation() {
        let mut audit =
            AuditScope::new("test_schema_filter_validation", uuid::Uuid::new_v4(), None);
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let schema = schema_outer.read();
        // Test non existant attr name
        let f_mixed = filter_all!(f_eq("nonClAsS", PartialValue::new_class("attributetype")));
        assert_eq!(
            f_mixed.validate(&schema),
            Err(SchemaError::InvalidAttribute("nonclass".to_string()))
        );

        // test syntax of bool
        let f_bool = filter_all!(f_eq("multivalue", PartialValue::new_iutf8s("zzzz")));
        assert_eq!(
            f_bool.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        // test insensitive values
        let f_insense = filter_all!(f_eq("class", PartialValue::new_class("AttributeType")));
        assert_eq!(
            f_insense.validate(&schema),
            Ok(unsafe { filter_valid!(f_eq("class", PartialValue::new_class("attributetype"))) })
        );
        // Test the recursive structures validate
        let f_or_empty = filter_all!(f_or!([]));
        assert_eq!(f_or_empty.validate(&schema), Err(SchemaError::EmptyFilter));
        let f_or = filter_all!(f_or!([f_eq(
            "multivalue",
            PartialValue::new_iutf8s("zzzz")
        )]));
        assert_eq!(
            f_or.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        let f_or_mult = filter_all!(f_and!([
            f_eq("class", PartialValue::new_class("attributetype")),
            f_eq("multivalue", PartialValue::new_iutf8s("zzzzzzz")),
        ]));
        assert_eq!(
            f_or_mult.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        // Test mixed case attr name - this is a pass, due to normalisation
        let f_or_ok = filter_all!(f_andnot(f_and!([
            f_eq("Class", PartialValue::new_class("AttributeType")),
            f_sub("class", PartialValue::new_class("classtype")),
            f_pres("class")
        ])));
        assert_eq!(
            f_or_ok.validate(&schema),
            Ok(unsafe {
                filter_valid!(f_andnot(f_and!([
                    f_eq("class", PartialValue::new_class("attributetype")),
                    f_sub("class", PartialValue::new_class("classtype")),
                    f_pres("class")
                ])))
            })
        );
        audit.write_log();
    }

    #[test]
    fn test_schema_class_phantom_reject() {
        // Check that entries can be normalised and validated sanely
        let mut audit = AuditScope::new(
            "test_schema_class_phantom_reject",
            uuid::Uuid::new_v4(),
            None,
        );
        let schema_outer = Schema::new(&mut audit).expect("failed to create schema");
        let mut schema = schema_outer.write();

        assert!(schema.validate(&mut audit).len() == 0);

        // Attempt to create a class with a phantom attribute, should be refused.
        let class = SchemaClass {
            name: String::from("testobject"),
            uuid: Uuid::new_v4(),
            description: String::from("test object"),
            systemmay: vec!["claim".to_string()],
            may: vec![],
            systemmust: vec![],
            must: vec![],
        };

        assert!(schema.update_classes(vec![class]).is_ok());

        assert!(schema.validate(&mut audit).len() == 1);

        audit.write_log();
    }
}

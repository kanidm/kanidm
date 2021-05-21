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
use crate::be::IdxKey;
use crate::prelude::*;
use kanidm_proto::v1::{ConsistencyError, OperationError, SchemaError};

use hashbrown::HashMap;
use hashbrown::HashSet;
use std::borrow::Borrow;
use std::collections::BTreeSet;
use uuid::Uuid;

// use concread::cowcell::asynch::*;
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
    classes: CowCell<HashMap<AttrString, SchemaClass>>,
    attributes: CowCell<HashMap<AttrString, SchemaAttribute>>,
    unique_cache: CowCell<Vec<AttrString>>,
    ref_cache: CowCell<HashMap<AttrString, SchemaAttribute>>,
}

/// A writable transaction of the working schema set. You should not change this directly,
/// the writability is for the server internally to allow reloading of the schema. Changes
/// you make will be lost when the server re-reads the schema from disk.
pub struct SchemaWriteTransaction<'a> {
    classes: CowCellWriteTxn<'a, HashMap<AttrString, SchemaClass>>,
    attributes: CowCellWriteTxn<'a, HashMap<AttrString, SchemaAttribute>>,

    unique_cache: CowCellWriteTxn<'a, Vec<AttrString>>,
    ref_cache: CowCellWriteTxn<'a, HashMap<AttrString, SchemaAttribute>>,
}

/// A readonly transaction of the working schema set.
pub struct SchemaReadTransaction {
    classes: CowCellReadTxn<HashMap<AttrString, SchemaClass>>,
    attributes: CowCellReadTxn<HashMap<AttrString, SchemaAttribute>>,

    unique_cache: CowCellReadTxn<Vec<AttrString>>,
    ref_cache: CowCellReadTxn<HashMap<AttrString, SchemaAttribute>>,
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
    pub name: AttrString,
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
        let name = value
            .get_ava_single_str("attributename")
            .map(|s| s.into())
            .ok_or_else(|| {
                ladmin_error!(audit, "missing attributename");
                OperationError::InvalidSchemaState("missing attributename".to_string())
            })?;
        // description
        let description = value
            .get_ava_single_str("description")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ladmin_error!(audit, "missing description");
                OperationError::InvalidSchemaState("missing description".to_string())
            })?;

        // multivalue
        let multivalue = value.get_ava_single_bool("multivalue").ok_or_else(|| {
            ladmin_error!(audit, "missing multivalue");
            OperationError::InvalidSchemaState("missing multivalue".to_string())
        })?;
        let unique = value.get_ava_single_bool("unique").ok_or_else(|| {
            ladmin_error!(audit, "missing unique");
            OperationError::InvalidSchemaState("missing unique".to_string())
        })?;
        let phantom = value.get_ava_single_bool("phantom").unwrap_or(false);
        // index vec
        // even if empty, it SHOULD be present ... (is that value to put an empty set?)
        // The get_ava_opt_index handles the optional case for us :)
        let index = value
            .get_ava_opt_index("index")
            .map(|vv: Vec<&IndexType>| vv.into_iter().cloned().collect())
            .map_err(|_| {
                ladmin_error!(audit, "invalid index");
                OperationError::InvalidSchemaState("Invalid index".to_string())
            })?;
        // syntax type
        let syntax = value
            .get_ava_single_syntax("syntax")
            .cloned()
            .ok_or_else(|| {
                ladmin_error!(audit, "missing syntax");
                OperationError::InvalidSchemaState("missing syntax".to_string())
            })?;

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
            SyntaxType::Boolean => v.is_bool(),
            SyntaxType::SYNTAX_ID => v.is_syntax(),
            SyntaxType::INDEX_ID => v.is_index(),
            SyntaxType::Uuid => v.is_uuid(),
            SyntaxType::REFERENCE_UUID => v.is_refer(),
            SyntaxType::Utf8StringInsensitive => v.is_iutf8(),
            SyntaxType::Utf8StringIname => v.is_iname(),
            SyntaxType::UTF8STRING => v.is_utf8(),
            SyntaxType::JSON_FILTER => v.is_json_filter(),
            SyntaxType::Credential => v.is_credential(),
            SyntaxType::RadiusUtf8String => v.is_radius_string(),
            SyntaxType::SshKey => v.is_sshkey(),
            SyntaxType::ServicePrincipalName => v.is_spn(),
            SyntaxType::UINT32 => v.is_uint32(),
            SyntaxType::Cid => v.is_cid(),
            SyntaxType::NsUniqueId => v.is_nsuniqueid(),
            SyntaxType::DateTime => v.is_datetime(),
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
            SyntaxType::Boolean => ava.iter().fold(Ok(()), |acc, v| {
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
            SyntaxType::Uuid => ava.iter().fold(Ok(()), |acc, v| {
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
            SyntaxType::Utf8StringInsensitive => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_insensitive_utf8() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::Utf8StringIname => ava.iter().fold(Ok(()), |acc, v| {
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
            SyntaxType::Credential => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_credential() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::RadiusUtf8String => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_radius_string() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::SshKey => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_sshkey() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::ServicePrincipalName => ava.iter().fold(Ok(()), |acc, v| {
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
            SyntaxType::Cid => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_cid() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::NsUniqueId => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_nsuniqueid() {
                        Ok(())
                    } else {
                        Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
                    }
                })
            }),
            SyntaxType::DateTime => ava.iter().fold(Ok(()), |acc, v| {
                acc.and_then(|_| {
                    if v.is_datetime() {
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
    pub name: AttrString,
    pub uuid: Uuid,
    pub description: String,
    // This allows modification of system types to be extended in custom ways
    pub systemmay: Vec<AttrString>,
    pub may: Vec<AttrString>,
    pub systemmust: Vec<AttrString>,
    pub must: Vec<AttrString>,
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
        let name = value
            .get_ava_single_str("classname")
            .map(AttrString::from)
            .ok_or_else(|| {
                ladmin_error!(audit, "missing classname");
                OperationError::InvalidSchemaState("missing classname".to_string())
            })?;
        // description
        let description = value
            .get_ava_single_str("description")
            .map(String::from)
            .ok_or_else(|| {
                ladmin_error!(audit, "missing description");
                OperationError::InvalidSchemaState("missing description".to_string())
            })?;

        // These are all "optional" lists of strings.
        let systemmay = value
            .get_ava_as_str("systemmay")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let systemmust = value
            .get_ava_as_str("systemmust")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let may = value
            .get_ava_as_str("may")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let must = value
            .get_ava_as_str("must")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

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
    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass>;
    fn get_attributes(&self) -> &HashMap<AttrString, SchemaAttribute>;

    fn get_attributes_unique(&self) -> &Vec<AttrString>;
    fn get_reference_types(&self) -> &HashMap<AttrString, SchemaAttribute>;

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
                                    class.name.to_string(),
                                    a.to_string(),
                                )))
                            }
                        }
                        None => {
                            // No such attr, something is missing!
                            res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                                class.name.to_string(),
                                a.to_string(),
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

    fn normalise_attr_name(&self, an: &str) -> AttrString {
        // Will duplicate.
        AttrString::from(an.to_lowercase())
    }

    fn normalise_attr_if_exists(&self, an: &str) -> Option<AttrString> {
        if self.get_attributes().contains_key(an) {
            Some(self.normalise_attr_name(an))
        } else {
            None
        }
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
            unique_cache,
            ref_cache,
        } = self;

        unique_cache.commit();
        ref_cache.commit();
        classes.commit();
        attributes.commit();
        Ok(())
    }

    pub fn update_attributes(
        &mut self,
        attributetypes: Vec<SchemaAttribute>,
    ) -> Result<(), OperationError> {
        // purge all old attributes.
        self.attributes.clear();

        self.unique_cache.clear();
        self.ref_cache.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        attributetypes.into_iter().for_each(|a| {
            // Update the unique and ref caches.
            if a.syntax == SyntaxType::REFERENCE_UUID {
                self.ref_cache.insert(a.name.clone(), a.clone());
            }
            if a.unique {
                self.unique_cache.push(a.name.clone());
            }
            // Finally insert.
            self.attributes.insert(a.name.clone(), a);
        });

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

    pub(crate) fn reload_idxmeta(&self) -> HashSet<IdxKey> {
        self.get_attributes()
            .values()
            .flat_map(|a| {
                a.index.iter().map(move |itype: &IndexType| IdxKey {
                    attr: a.name.clone(),
                    itype: (*itype).clone(),
                })
            })
            .collect()
    }

    pub fn generate_in_memory(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        lperf_trace_segment!(audit, "schema::generate_in_memory", || {
            //
            self.classes.clear();
            self.attributes.clear();
            // Bootstrap in definitions of our own schema types
            // First, add all the needed core attributes for schema parsing
            self.attributes.insert(
                AttrString::from("class"),
                SchemaAttribute {
                    name: AttrString::from("class"),
                    uuid: *UUID_SCHEMA_ATTR_CLASS,
                    description: String::from("The set of classes defining an object"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality, IndexType::Presence],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("uuid"),
                SchemaAttribute {
                    name: AttrString::from("uuid"),
                    uuid: *UUID_SCHEMA_ATTR_UUID,
                    description: String::from("The universal unique id of the object"),
                    multivalue: false,
                    // Uniqueness is handled by base.rs, not attrunique here due to
                    // needing to check recycled objects too.
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality, IndexType::Presence],
                    syntax: SyntaxType::Uuid,
                },
            );
            self.attributes.insert(
                AttrString::from("last_modified_cid"),
                SchemaAttribute {
                    name: AttrString::from("last_modified_cid"),
                    uuid: *UUID_SCHEMA_ATTR_LAST_MOD_CID,
                    description: String::from("The cid of the last change to this object"),
                    multivalue: false,
                    // Uniqueness is handled by base.rs, not attrunique here due to
                    // needing to check recycled objects too.
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::Cid,
                },
            );
            self.attributes.insert(
                AttrString::from("name"),
                SchemaAttribute {
                    name: AttrString::from("name"),
                    uuid: *UUID_SCHEMA_ATTR_NAME,
                    description: String::from("The shortform name of an object"),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::Equality, IndexType::Presence],
                    syntax: SyntaxType::Utf8StringIname,
                },
            );
            self.attributes.insert(
                AttrString::from("spn"),
                SchemaAttribute {
                    name: AttrString::from("spn"),
                    uuid: *UUID_SCHEMA_ATTR_SPN,
                    description: String::from(
                        "The Service Principal Name of an object, unique across all domain trusts",
                    ),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::ServicePrincipalName,
                },
            );
            self.attributes.insert(
                AttrString::from("attributename"),
                SchemaAttribute {
                    name: AttrString::from("attributename"),
                    uuid: *UUID_SCHEMA_ATTR_ATTRIBUTENAME,
                    description: String::from("The name of a schema attribute"),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("classname"),
                SchemaAttribute {
                    name: AttrString::from("classname"),
                    uuid: *UUID_SCHEMA_ATTR_CLASSNAME,
                    description: String::from("The name of a schema class"),
                    multivalue: false,
                    unique: true,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("description"),
                SchemaAttribute {
                    name: AttrString::from("description"),
                    uuid: *UUID_SCHEMA_ATTR_DESCRIPTION,
                    description: String::from("A description of an attribute, object or class"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::UTF8STRING,
                },
            );
            self.attributes.insert(AttrString::from("multivalue"), SchemaAttribute {
                name: AttrString::from("multivalue"),
                uuid: *UUID_SCHEMA_ATTR_MULTIVALUE,
                description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
                multivalue: false,
                unique: false,
                phantom: false,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
            self.attributes.insert(AttrString::from("phantom"), SchemaAttribute {
                name: AttrString::from("phantom"),
                uuid: *UUID_SCHEMA_ATTR_PHANTOM,
                description: String::from("If true, this attribute must NOT be present in any may/must sets of a class as. This represents generated attributes."),
                multivalue: false,
                unique: false,
                phantom: false,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
            self.attributes.insert(AttrString::from("unique"), SchemaAttribute {
                name: AttrString::from("unique"),
                uuid: *UUID_SCHEMA_ATTR_UNIQUE,
                description: String::from("If true, this attribute must store a unique value through out the database."),
                multivalue: false,
                unique: false,
                phantom: false,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
            self.attributes.insert(
                AttrString::from("index"),
                SchemaAttribute {
                    name: AttrString::from("index"),
                    uuid: *UUID_SCHEMA_ATTR_INDEX,
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
                AttrString::from("syntax"),
                SchemaAttribute {
                    name: AttrString::from("syntax"),
                    uuid: *UUID_SCHEMA_ATTR_SYNTAX,
                    description: String::from(
                        "Describe the syntax of this attribute. This affects indexing and sorting.",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::SYNTAX_ID,
                },
            );
            self.attributes.insert(
                AttrString::from("systemmay"),
                SchemaAttribute {
                    name: AttrString::from("systemmay"),
                    uuid: *UUID_SCHEMA_ATTR_SYSTEMMAY,
                    description: String::from(
                        "A list of system provided optional attributes this class can store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("may"),
                SchemaAttribute {
                    name: AttrString::from("may"),
                    uuid: *UUID_SCHEMA_ATTR_MAY,
                    description: String::from(
                        "A user modifiable list of optional attributes this class can store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("systemmust"),
                SchemaAttribute {
                    name: AttrString::from("systemmust"),
                    uuid: *UUID_SCHEMA_ATTR_SYSTEMMUST,
                    description: String::from(
                        "A list of system provided required attributes this class must store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("must"),
                SchemaAttribute {
                    name: AttrString::from("must"),
                    uuid: *UUID_SCHEMA_ATTR_MUST,
                    description: String::from(
                        "A user modifiable list of required attributes this class must store.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            // SYSINFO attrs
            // ACP attributes.
            self.attributes.insert(
                AttrString::from("acp_enable"),
                SchemaAttribute {
                    name: AttrString::from("acp_enable"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_ENABLE,
                    description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforce. False is checked but not enforced."),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Boolean,
                },
            );

            self.attributes.insert(
                AttrString::from("acp_receiver"),
                SchemaAttribute {
                    name: AttrString::from("acp_receiver"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_RECEIVER,
                    description: String::from(
                        "Who the ACP applies to, constraining or allowing operations.",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality, IndexType::SubString],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            self.attributes.insert(
                AttrString::from("acp_targetscope"),
                SchemaAttribute {
                    name: AttrString::from("acp_targetscope"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_TARGETSCOPE,
                    description: String::from(
                        "The effective targets of the ACP, IE what will be acted upon.",
                    ),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality, IndexType::SubString],
                    syntax: SyntaxType::JSON_FILTER,
                },
            );
            self.attributes.insert(
                AttrString::from("acp_search_attr"),
                SchemaAttribute {
                    name: AttrString::from("acp_search_attr"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR,
                    description: String::from("The attributes that may be viewed or searched by the reciever on targetscope."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("acp_create_class"),
                SchemaAttribute {
                    name: AttrString::from("acp_create_class"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_CREATE_CLASS,
                    description: String::from(
                        "The set of classes that can be created on a new entry.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("acp_create_attr"),
                SchemaAttribute {
                    name: AttrString::from("acp_create_attr"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_CREATE_ATTR,
                    description: String::from(
                        "The set of attribute types that can be created on an entry.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );

            self.attributes.insert(
                AttrString::from("acp_modify_removedattr"),
                SchemaAttribute {
                    name: AttrString::from("acp_modify_removedattr"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR,
                    description: String::from("The set of attribute types that could be removed or purged in a modification."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("acp_modify_presentattr"),
                SchemaAttribute {
                    name: AttrString::from("acp_modify_presentattr"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR,
                    description: String::from("The set of attribute types that could be added or asserted in a modification."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("acp_modify_class"),
                SchemaAttribute {
                    name: AttrString::from("acp_modify_class"),
                    uuid: *UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS,
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            // MO/Member
            self.attributes.insert(
                AttrString::from("memberof"),
                SchemaAttribute {
                    name: AttrString::from("memberof"),
                    uuid: *UUID_SCHEMA_ATTR_MEMBEROF,
                    description: String::from("reverse group membership of the object"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            self.attributes.insert(
                AttrString::from("directmemberof"),
                SchemaAttribute {
                    name: AttrString::from("directmemberof"),
                    uuid: *UUID_SCHEMA_ATTR_DIRECTMEMBEROF,
                    description: String::from("reverse direct group membership of the object"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            self.attributes.insert(
                AttrString::from("member"),
                SchemaAttribute {
                    name: AttrString::from("member"),
                    uuid: *UUID_SCHEMA_ATTR_MEMBER,
                    description: String::from("List of members of the group"),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::REFERENCE_UUID,
                },
            );
            // Migration related
            self.attributes.insert(
                AttrString::from("version"),
                SchemaAttribute {
                    name: AttrString::from("version"),
                    uuid: *UUID_SCHEMA_ATTR_VERSION,
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
                AttrString::from("domain"),
                SchemaAttribute {
                    name: AttrString::from("domain"),
                    uuid: *UUID_SCHEMA_ATTR_DOMAIN,
                    description: String::from("A DNS Domain name entry."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringIname,
                },
            );
            self.attributes.insert(
                AttrString::from("claim"),
                SchemaAttribute {
                    name: AttrString::from("claim"),
                    uuid: *UUID_SCHEMA_ATTR_CLAIM,
                    description: String::from("The spn of a claim this entry holds"),
                    multivalue: true,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::ServicePrincipalName,
                },
            );
            self.attributes.insert(
                AttrString::from("password_import"),
                SchemaAttribute {
                    name: AttrString::from("password_import"),
                    uuid: *UUID_SCHEMA_ATTR_PASSWORD_IMPORT,
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
                AttrString::from("dn"),
                SchemaAttribute {
                    name: AttrString::from("dn"),
                    uuid: *UUID_SCHEMA_ATTR_DN,
                    description: String::from("An LDAP Compatible DN"),
                    multivalue: false,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            self.attributes.insert(
                AttrString::from("entryuuid"),
                SchemaAttribute {
                    name: AttrString::from("entryuuid"),
                    uuid: *UUID_SCHEMA_ATTR_ENTRYUUID,
                    description: String::from("An LDAP Compatible entryUUID"),
                    multivalue: false,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::Uuid,
                },
            );
            self.attributes.insert(
                AttrString::from("objectclass"),
                SchemaAttribute {
                    name: AttrString::from("objectclass"),
                    uuid: *UUID_SCHEMA_ATTR_OBJECTCLASS,
                    description: String::from("An LDAP Compatible objectClass"),
                    multivalue: true,
                    unique: false,
                    phantom: true,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
            // end LDAP masking phantoms

            self.classes.insert(
                AttrString::from("attributetype"),
                SchemaClass {
                    name: AttrString::from("attributetype"),
                    uuid: *UUID_SCHEMA_CLASS_ATTRIBUTETYPE,
                    description: String::from("Definition of a schema attribute"),
                    systemmay: vec![AttrString::from("phantom"), AttrString::from("index")],
                    may: vec![],
                    systemmust: vec![
                        AttrString::from("class"),
                        AttrString::from("attributename"),
                        AttrString::from("multivalue"),
                        AttrString::from("unique"),
                        AttrString::from("syntax"),
                        AttrString::from("description"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("classtype"),
                SchemaClass {
                    name: AttrString::from("classtype"),
                    uuid: *UUID_SCHEMA_CLASS_CLASSTYPE,
                    description: String::from("Definition of a schema classtype"),
                    systemmay: vec![
                        AttrString::from("systemmay"),
                        AttrString::from("may"),
                        AttrString::from("systemmust"),
                        AttrString::from("must"),
                    ],
                    may: vec![],
                    systemmust: vec![
                        AttrString::from("class"),
                        AttrString::from("classname"),
                        AttrString::from("description"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("object"),
                SchemaClass {
                    name: AttrString::from("object"),
                    uuid: *UUID_SCHEMA_CLASS_OBJECT,
                    description: String::from(
                        "A system created class that all objects must contain",
                    ),
                    systemmay: vec![AttrString::from("description")],
                    may: vec![],
                    systemmust: vec![
                        AttrString::from("class"),
                        AttrString::from("uuid"),
                        AttrString::from("last_modified_cid"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("memberof"),
                SchemaClass {
                    name: AttrString::from("memberof"),
                    uuid: *UUID_SCHEMA_CLASS_MEMBEROF,
                    description: String::from("Class that is dynamically added to recepients of memberof or directmemberof"),
                    systemmay: vec![
                        AttrString::from("memberof"),
                        AttrString::from("directmemberof")
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("extensibleobject"),
                SchemaClass {
                    name: AttrString::from("extensibleobject"),
                    uuid: *UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT,
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
                AttrString::from("recycled"),
                SchemaClass {
                    name: AttrString::from("recycled"),
                    uuid: *UUID_SCHEMA_CLASS_RECYCLED,
                    description: String::from("An object that has been deleted, but still recoverable via the revive operation. Recycled objects are not modifiable, only revivable."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("tombstone"),
                SchemaClass {
                    name: AttrString::from("tombstone"),
                    uuid: *UUID_SCHEMA_CLASS_TOMBSTONE,
                    description: String::from("An object that is purged from the recycle bin. This is a system internal state. Tombstones have no attributes beside UUID."),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![
                        AttrString::from("class"),
                        AttrString::from("uuid"),
                    ],
                    must: vec![],
                },
            );
            // sysinfo
            self.classes.insert(
                AttrString::from("system_info"),
                SchemaClass {
                    name: AttrString::from("system_info"),
                    uuid: *UUID_SCHEMA_CLASS_SYSTEM_INFO,
                    description: String::from("System metadata object class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![
                        AttrString::from("version"),
                        // Needed when we implement principalnames?
                        // String::from("domain"),
                        // String::from("hostname"),
                    ],
                    must: vec![],
                },
            );
            // ACP
            self.classes.insert(
                AttrString::from("access_control_profile"),
                SchemaClass {
                    name: AttrString::from("access_control_profile"),
                    uuid: *UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE,
                    description: String::from("System Access Control Profile Class"),
                    systemmay: vec![
                        AttrString::from("acp_enable"),
                        AttrString::from("description"),
                    ],
                    may: vec![],
                    systemmust: vec![
                        AttrString::from("acp_receiver"),
                        AttrString::from("acp_targetscope"),
                        AttrString::from("name"),
                    ],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("access_control_search"),
                SchemaClass {
                    name: AttrString::from("access_control_search"),
                    uuid: *UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH,
                    description: String::from("System Access Control Search Class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![AttrString::from("acp_search_attr")],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("access_control_delete"),
                SchemaClass {
                    name: AttrString::from("access_control_delete"),
                    uuid: *UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE,
                    description: String::from("System Access Control DELETE Class"),
                    systemmay: vec![],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("access_control_modify"),
                SchemaClass {
                    name: AttrString::from("access_control_modify"),
                    uuid: *UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY,
                    description: String::from("System Access Control Modify Class"),
                    systemmay: vec![
                        AttrString::from("acp_modify_removedattr"),
                        AttrString::from("acp_modify_presentattr"),
                        AttrString::from("acp_modify_class"),
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("access_control_create"),
                SchemaClass {
                    name: AttrString::from("access_control_create"),
                    uuid: *UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE,
                    description: String::from("System Access Control Create Class"),
                    systemmay: vec![
                        AttrString::from("acp_create_class"),
                        AttrString::from("acp_create_attr"),
                    ],
                    may: vec![],
                    systemmust: vec![],
                    must: vec![],
                },
            );
            self.classes.insert(
                AttrString::from("system"),
                SchemaClass {
                    name: AttrString::from("system"),
                    uuid: *UUID_SCHEMA_CLASS_SYSTEM,
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
                Ok(())
            } else {
                ladmin_info!(audit, "schema validate -> errors {:?}", r);
                Err(OperationError::ConsistencyError(r))
            }
        })
    }
}

impl<'a> SchemaTransaction for SchemaWriteTransaction<'a> {
    fn get_attributes_unique(&self) -> &Vec<AttrString> {
        &(*self.unique_cache)
    }

    fn get_reference_types(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &(*self.ref_cache)
    }

    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass> {
        &(*self.classes)
    }

    fn get_attributes(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &(*self.attributes)
    }
}

impl SchemaTransaction for SchemaReadTransaction {
    fn get_attributes_unique(&self) -> &Vec<AttrString> {
        &(*self.unique_cache)
    }

    fn get_reference_types(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &(*self.ref_cache)
    }

    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass> {
        &(*self.classes)
    }

    fn get_attributes(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &(*self.attributes)
    }
}

impl Schema {
    pub fn new(audit: &mut AuditScope) -> Result<Self, OperationError> {
        let s = Schema {
            classes: CowCell::new(HashMap::with_capacity(128)),
            attributes: CowCell::new(HashMap::with_capacity(128)),
            unique_cache: CowCell::new(Vec::new()),
            ref_cache: CowCell::new(HashMap::with_capacity(64)),
        };
        // let mut sw = task::block_on(s.write());
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
            unique_cache: self.unique_cache.read(),
            ref_cache: self.ref_cache.read(),
        }
    }

    pub fn write(&self) -> SchemaWriteTransaction<'_> {
        SchemaWriteTransaction {
            classes: self.classes.write(),
            attributes: self.attributes.write(),
            unique_cache: self.unique_cache.write(),
            ref_cache: self.ref_cache.write(),
        }
    }

    pub(crate) fn write_blocking(&self) -> SchemaWriteTransaction<'_> {
        self.write()
    }

    /*
    pub async fn write<'a>(&'a self) -> SchemaWriteTransaction<'a> {
        SchemaWriteTransaction {
            classes: self.classes.write().await,
            attributes: self.attributes.write().await,
            unique_cache: self.unique_cache.write().await,
            ref_cache: self.ref_cache.write().await,
        }
    }

    #[cfg(test)]
    pub fn write_blocking<'a>(&'a self) -> SchemaWriteTransaction<'a> {
        task::block_on(self.write())
    }
    */
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::schema::SchemaTransaction;
    use crate::schema::{IndexType, Schema, SchemaAttribute, SchemaClass, SyntaxType};
    use kanidm_proto::v1::{ConsistencyError, SchemaError};
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
            name: AttrString::from("single_value"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            unique: false,
            phantom: false,
            index: vec![IndexType::Equality],
            syntax: SyntaxType::Utf8StringInsensitive,
        };

        let r1 =
            single_value_string.validate_ava("single_value", &btreeset![Value::new_iutf8("test")]);
        assert_eq!(r1, Ok(()));

        let r2 = single_value_string.validate_ava(
            "single_value",
            &btreeset![Value::new_iutf8("test1"), Value::new_iutf8("test2")],
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
            name: AttrString::from("mv_string"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            unique: false,
            phantom: false,
            index: vec![IndexType::Equality],
            syntax: SyntaxType::UTF8STRING,
        };

        let r5 = multi_value_string.validate_ava(
            "mv_string",
            &btreeset![Value::new_utf8s("test1"), Value::new_utf8s("test2")],
        );
        assert_eq!(r5, Ok(()));

        let multi_value_boolean = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: AttrString::from("mv_bool"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            unique: false,
            phantom: false,
            index: vec![IndexType::Equality],
            syntax: SyntaxType::Boolean,
        };

        let r3 = multi_value_boolean.validate_ava(
            "mv_bool",
            &btreeset![
                Value::new_bool(true),
                Value::new_iutf8("test1"),
                Value::new_iutf8("test2")
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
            name: AttrString::from("sv_syntax"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            unique: false,
            phantom: false,
            index: vec![IndexType::Equality],
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
            name: AttrString::from("sv_index"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: false,
            unique: false,
            phantom: false,
            index: vec![IndexType::Equality],
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
        let schema = schema_outer.write_blocking();

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
        let f_bool = filter_all!(f_eq("multivalue", PartialValue::new_iutf8("zzzz")));
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
        let f_or = filter_all!(f_or!([f_eq("multivalue", PartialValue::new_iutf8("zzzz"))]));
        assert_eq!(
            f_or.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        let f_or_mult = filter_all!(f_and!([
            f_eq("class", PartialValue::new_class("attributetype")),
            f_eq("multivalue", PartialValue::new_iutf8("zzzzzzz")),
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
        let mut schema = schema_outer.write_blocking();

        assert!(schema.validate(&mut audit).len() == 0);

        // Attempt to create a class with a phantom attribute, should be refused.
        let class = SchemaClass {
            name: AttrString::from("testobject"),
            uuid: Uuid::new_v4(),
            description: String::from("test object"),
            systemmay: vec![AttrString::from("claim")],
            may: vec![],
            systemmust: vec![],
            must: vec![],
        };

        assert!(schema.update_classes(vec![class]).is_ok());

        assert!(schema.validate(&mut audit).len() == 1);

        audit.write_log();
    }
}

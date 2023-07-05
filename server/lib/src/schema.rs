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

use std::collections::BTreeSet;

use concread::cowcell::*;
use hashbrown::{HashMap, HashSet};
use kanidm_proto::v1::{ConsistencyError, OperationError, SchemaError};
use tracing::trace;
use uuid::Uuid;

use crate::be::IdxKey;
use crate::prelude::*;
use crate::valueset::ValueSet;

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

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

/// An item representing an attribute and the rules that enforce it. These rules enforce if an
/// attribute on an [`Entry`] may be single or multi value, must be unique amongst all other types
/// of this attribute, if the attribute should be [`indexed`], and what type of data [`syntax`] it may hold.
///
/// [`Entry`]: ../entry/index.html
/// [`indexed`]: ../value/enum.IndexType.html
/// [`syntax`]: ../value/enum.SyntaxType.html
#[derive(Debug, Clone, Default)]
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
    pub sync_allowed: bool,
    pub replicated: bool,
    pub index: Vec<IndexType>,
    pub syntax: SyntaxType,
}

impl SchemaAttribute {
    pub fn try_from(value: &Entry<EntrySealed, EntryCommitted>) -> Result<Self, OperationError> {
        // Convert entry to a schema attribute.
        trace!("Converting -> {}", value);

        // uuid
        let uuid = value.get_uuid();

        // class
        if !value.attribute_equality("class", &PVCLASS_ATTRIBUTETYPE) {
            admin_error!("class attribute type not present - {:?}", uuid);
            return Err(OperationError::InvalidSchemaState(
                "missing attributetype".to_string(),
            ));
        }

        // name
        let name = value
            .get_ava_single_iutf8("attributename")
            .map(|s| s.into())
            .ok_or_else(|| {
                admin_error!("missing attributename - {:?}", uuid);
                OperationError::InvalidSchemaState("missing attributename".to_string())
            })?;
        // description
        let description = value
            .get_ava_single_utf8("description")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                admin_error!("missing description - {}", name);
                OperationError::InvalidSchemaState("missing description".to_string())
            })?;

        // multivalue
        let multivalue = value.get_ava_single_bool("multivalue").ok_or_else(|| {
            admin_error!("missing multivalue - {}", name);
            OperationError::InvalidSchemaState("missing multivalue".to_string())
        })?;
        let unique = value.get_ava_single_bool("unique").ok_or_else(|| {
            admin_error!("missing unique - {}", name);
            OperationError::InvalidSchemaState("missing unique".to_string())
        })?;

        let phantom = value.get_ava_single_bool("phantom").unwrap_or(false);

        let sync_allowed = value.get_ava_single_bool("sync_allowed").unwrap_or(false);

        // Default, all attributes are replicated unless you opt in for them to NOT be.
        // Generally this is internal to the server only, so we don't advertise it.
        let replicated = value.get_ava_single_bool("replicated").unwrap_or(true);

        // index vec
        // even if empty, it SHOULD be present ... (is that valid to put an empty set?)
        // The get_ava_opt_index handles the optional case for us :)
        let index = value.get_ava_opt_index("index").ok_or_else(|| {
            admin_error!("invalid index - {}", name);
            OperationError::InvalidSchemaState("invalid index".to_string())
        })?;
        // syntax type
        let syntax = value.get_ava_single_syntax("syntax").ok_or_else(|| {
            admin_error!("missing syntax - {}", name);
            OperationError::InvalidSchemaState("missing syntax".to_string())
        })?;

        Ok(SchemaAttribute {
            name,
            uuid,
            description,
            multivalue,
            unique,
            phantom,
            sync_allowed,
            replicated,
            index,
            syntax,
        })
    }

    // There may be a difference between a value and a filter value on complex
    // types - IE a complex type may have multiple parts that are secret, but a filter
    // on that may only use a single tagged attribute for example.
    pub fn validate_partialvalue(&self, a: &str, v: &PartialValue) -> Result<(), SchemaError> {
        let r = match self.syntax {
            SyntaxType::Boolean => matches!(v, PartialValue::Bool(_)),
            SyntaxType::SyntaxId => matches!(v, PartialValue::Syntax(_)),
            SyntaxType::IndexId => matches!(v, PartialValue::Index(_)),
            SyntaxType::Uuid => matches!(v, PartialValue::Uuid(_)),
            SyntaxType::ReferenceUuid => matches!(v, PartialValue::Refer(_)),
            SyntaxType::Utf8StringInsensitive => matches!(v, PartialValue::Iutf8(_)),
            SyntaxType::Utf8StringIname => matches!(v, PartialValue::Iname(_)),
            SyntaxType::Utf8String => matches!(v, PartialValue::Utf8(_)),
            SyntaxType::JsonFilter => matches!(v, PartialValue::JsonFilt(_)),
            SyntaxType::Credential => matches!(v, PartialValue::Cred(_)),
            SyntaxType::SecretUtf8String => matches!(v, PartialValue::SecretValue),
            SyntaxType::SshKey => matches!(v, PartialValue::SshKey(_)),
            SyntaxType::SecurityPrincipalName => matches!(v, PartialValue::Spn(_, _)),
            SyntaxType::Uint32 => matches!(v, PartialValue::Uint32(_)),
            SyntaxType::Cid => matches!(v, PartialValue::Cid(_)),
            SyntaxType::NsUniqueId => matches!(v, PartialValue::Nsuniqueid(_)),
            SyntaxType::DateTime => matches!(v, PartialValue::DateTime(_)),
            SyntaxType::EmailAddress => matches!(v, PartialValue::EmailAddress(_)),
            SyntaxType::Url => matches!(v, PartialValue::Url(_)),
            SyntaxType::OauthScope => matches!(v, PartialValue::OauthScope(_)),
            SyntaxType::OauthScopeMap => matches!(v, PartialValue::Refer(_)),
            SyntaxType::PrivateBinary => matches!(v, PartialValue::PrivateBinary),
            SyntaxType::IntentToken => matches!(v, PartialValue::IntentToken(_)),
            SyntaxType::Passkey => matches!(v, PartialValue::Passkey(_)),
            SyntaxType::DeviceKey => matches!(v, PartialValue::DeviceKey(_)),
            // Allow refer types.
            SyntaxType::Session => matches!(v, PartialValue::Refer(_)),
            SyntaxType::ApiToken => matches!(v, PartialValue::Refer(_)),
            SyntaxType::Oauth2Session => matches!(v, PartialValue::Refer(_)),
            // These are just insensitive string lookups on the hex-ified kid.
            SyntaxType::JwsKeyEs256 => matches!(v, PartialValue::Iutf8(_)),
            SyntaxType::JwsKeyRs256 => matches!(v, PartialValue::Iutf8(_)),
            SyntaxType::UiHint => matches!(v, PartialValue::UiHint(_)),
            // Comparing on the label.
            SyntaxType::TotpSecret => matches!(v, PartialValue::Utf8(_)),
            SyntaxType::AuditLogString => matches!(v, PartialValue::Utf8(_)),
        };
        if r {
            Ok(())
        } else {
            trace!(
                ?a,
                ?self,
                ?v,
                "validate_partialvalue InvalidAttributeSyntax"
            );
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }

    pub fn validate_value(&self, a: &str, v: &Value) -> Result<(), SchemaError> {
        let r = v.validate()
            && match self.syntax {
                SyntaxType::Boolean => matches!(v, Value::Bool(_)),
                SyntaxType::SyntaxId => matches!(v, Value::Syntax(_)),
                SyntaxType::IndexId => matches!(v, Value::Index(_)),
                SyntaxType::Uuid => matches!(v, Value::Uuid(_)),
                SyntaxType::ReferenceUuid => matches!(v, Value::Refer(_)),
                SyntaxType::Utf8StringInsensitive => matches!(v, Value::Iutf8(_)),
                SyntaxType::Utf8StringIname => matches!(v, Value::Iname(_)),
                SyntaxType::Utf8String => matches!(v, Value::Utf8(_)),
                SyntaxType::JsonFilter => matches!(v, Value::JsonFilt(_)),
                SyntaxType::Credential => matches!(v, Value::Cred(_, _)),
                SyntaxType::SecretUtf8String => matches!(v, Value::SecretValue(_)),
                SyntaxType::SshKey => matches!(v, Value::SshKey(_, _)),
                SyntaxType::SecurityPrincipalName => matches!(v, Value::Spn(_, _)),
                SyntaxType::Uint32 => matches!(v, Value::Uint32(_)),
                SyntaxType::Cid => matches!(v, Value::Cid(_)),
                SyntaxType::NsUniqueId => matches!(v, Value::Nsuniqueid(_)),
                SyntaxType::DateTime => matches!(v, Value::DateTime(_)),
                SyntaxType::EmailAddress => matches!(v, Value::EmailAddress(_, _)),
                SyntaxType::Url => matches!(v, Value::Url(_)),
                SyntaxType::OauthScope => matches!(v, Value::OauthScope(_)),
                SyntaxType::OauthScopeMap => matches!(v, Value::OauthScopeMap(_, _)),
                SyntaxType::PrivateBinary => matches!(v, Value::PrivateBinary(_)),
                SyntaxType::IntentToken => matches!(v, Value::IntentToken(_, _)),
                SyntaxType::Passkey => matches!(v, Value::Passkey(_, _, _)),
                SyntaxType::DeviceKey => matches!(v, Value::DeviceKey(_, _, _)),
                SyntaxType::Session => matches!(v, Value::Session(_, _)),
                SyntaxType::ApiToken => matches!(v, Value::ApiToken(_, _)),
                SyntaxType::Oauth2Session => matches!(v, Value::Oauth2Session(_, _)),
                SyntaxType::JwsKeyEs256 => matches!(v, Value::JwsKeyEs256(_)),
                SyntaxType::JwsKeyRs256 => matches!(v, Value::JwsKeyRs256(_)),
                SyntaxType::UiHint => matches!(v, Value::UiHint(_)),
                SyntaxType::TotpSecret => matches!(v, Value::TotpSecret(_, _)),
                SyntaxType::AuditLogString => matches!(v, Value::Utf8(_)),
            };
        if r {
            Ok(())
        } else {
            trace!(
                ?a,
                ?self,
                ?v,
                "validate_value failure - InvalidAttributeSyntax"
            );
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }

    pub fn validate_ava(&self, a: &str, ava: &ValueSet) -> Result<(), SchemaError> {
        trace!("Checking for valid {:?} -> {:?}", self.name, ava);
        // Check multivalue
        if !self.multivalue && ava.len() > 1 {
            // lrequest_error!("Ava len > 1 on single value attribute!");
            admin_error!("Ava len > 1 on single value attribute!");
            return Err(SchemaError::InvalidAttributeSyntax(a.to_string()));
        };
        // If syntax, check the type is correct
        let valid = self.syntax == ava.syntax();
        if valid && ava.validate(self) {
            Ok(())
        } else {
            admin_error!(
                ?a,
                "validate_ava - InvalidAttributeSyntax for {:?}",
                self.syntax
            );
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }
}

/// An item representing a class and the rules for that class. These rules enforce that an
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
#[derive(Debug, Clone, Default)]
pub struct SchemaClass {
    // Is this used?
    // class: Vec<String>,
    pub name: AttrString,
    pub uuid: Uuid,
    pub description: String,
    pub sync_allowed: bool,
    /// This allows modification of system types to be extended in custom ways
    pub systemmay: Vec<AttrString>,
    pub may: Vec<AttrString>,
    pub systemmust: Vec<AttrString>,
    pub must: Vec<AttrString>,
    /// A list of classes that this extends. These are an "or", as at least one
    /// of the supplementing classes must also be present. Think of this as
    /// "inherits toward" or "provides". This is just as "strict" as requires but
    /// operates in the opposite direction allowing a tree structure.
    pub systemsupplements: Vec<AttrString>,
    pub supplements: Vec<AttrString>,
    /// A list of classes that can not co-exist with this item at the same time.
    pub systemexcludes: Vec<AttrString>,
    pub excludes: Vec<AttrString>,
}

impl SchemaClass {
    pub fn try_from(value: &Entry<EntrySealed, EntryCommitted>) -> Result<Self, OperationError> {
        trace!("Converting {}", value);
        // uuid
        let uuid = value.get_uuid();
        // Convert entry to a schema class.
        if !value.attribute_equality("class", &PVCLASS_CLASSTYPE) {
            admin_error!("class classtype not present - {:?}", uuid);
            return Err(OperationError::InvalidSchemaState(
                "missing classtype".to_string(),
            ));
        }

        // name
        let name = value
            .get_ava_single_iutf8("classname")
            .map(AttrString::from)
            .ok_or_else(|| {
                admin_error!("missing classname - {:?}", uuid);
                OperationError::InvalidSchemaState("missing classname".to_string())
            })?;
        // description
        let description = value
            .get_ava_single_utf8("description")
            .map(String::from)
            .ok_or_else(|| {
                admin_error!("missing description - {}", name);
                OperationError::InvalidSchemaState("missing description".to_string())
            })?;

        let sync_allowed = value.get_ava_single_bool("sync_allowed").unwrap_or(false);

        // These are all "optional" lists of strings.
        let systemmay = value
            .get_ava_iter_iutf8("systemmay")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let systemmust = value
            .get_ava_iter_iutf8("systemmust")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let may = value
            .get_ava_iter_iutf8("may")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let must = value
            .get_ava_iter_iutf8("must")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let systemsupplements = value
            .get_ava_iter_iutf8("systemsupplements")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let supplements = value
            .get_ava_iter_iutf8("supplements")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let systemexcludes = value
            .get_ava_iter_iutf8("systemexcludes")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);
        let excludes = value
            .get_ava_iter_iutf8("excludes")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        Ok(SchemaClass {
            name,
            uuid,
            description,
            sync_allowed,
            systemmay,
            may,
            systemmust,
            must,
            systemsupplements,
            supplements,
            systemexcludes,
            excludes,
        })
    }

    /// An iterator over the full set of attrs that may or must exist
    /// on this class.
    pub fn may_iter(&self) -> impl Iterator<Item = &AttrString> {
        self.systemmay
            .iter()
            .chain(self.may.iter())
            .chain(self.systemmust.iter())
            .chain(self.must.iter())
    }
}

pub trait SchemaTransaction {
    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass>;
    fn get_attributes(&self) -> &HashMap<AttrString, SchemaAttribute>;

    fn get_attributes_unique(&self) -> &Vec<AttrString>;
    fn get_reference_types(&self) -> &HashMap<AttrString, SchemaAttribute>;

    fn validate(&self) -> Vec<Result<(), ConsistencyError>> {
        let mut res = Vec::new();

        let class_snapshot = self.get_classes();
        let attribute_snapshot = self.get_attributes();

        // We need to check that every uuid is unique because during tests we aren't doing
        // a disk reload, which means we were missing this and causing potential migration
        // failures on upgrade.

        let mut unique_uuid_set = HashSet::new();
        class_snapshot
            .values()
            .map(|class| &class.uuid)
            .chain(attribute_snapshot.values().map(|attr| &attr.uuid))
            .for_each(|uuid| {
                // If the set did not have this value present, true is returned.
                if !unique_uuid_set.insert(uuid) {
                    res.push(Err(ConsistencyError::SchemaUuidNotUnique(*uuid)))
                }
            });

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

    fn is_replicated(&self, attr: &str) -> bool {
        match self.get_attributes().get(attr) {
            Some(a_schema) => {
                // We'll likely add more conditions here later.
                // Allow items that are replicated and not phantoms
                a_schema.replicated && !a_schema.phantom
            }
            None => {
                warn!(
                    "Attribute {} was not found in schema during replication request",
                    attr
                );
                false
            }
        }
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

    fn query_attrs_difference(
        &self,
        prev_class: &BTreeSet<&str>,
        new_class: &BTreeSet<&str>,
    ) -> Result<(BTreeSet<&str>, BTreeSet<&str>), SchemaError> {
        let schema_classes = self.get_classes();

        let mut invalid_classes = Vec::with_capacity(0);

        let prev_attrs: BTreeSet<&str> = prev_class
            .iter()
            .filter_map(|cls| match schema_classes.get(*cls) {
                Some(x) => Some(x.may_iter()),
                None => {
                    admin_debug!("invalid class: {:?}", cls);
                    invalid_classes.push(cls.to_string());
                    None
                }
            })
            // flatten all the inner iters.
            .flatten()
            .map(|s| s.as_str())
            .collect();

        if !invalid_classes.is_empty() {
            return Err(SchemaError::InvalidClass(invalid_classes));
        };

        let new_attrs: BTreeSet<&str> = new_class
            .iter()
            .filter_map(|cls| match schema_classes.get(*cls) {
                Some(x) => Some(x.may_iter()),
                None => {
                    admin_debug!("invalid class: {:?}", cls);
                    invalid_classes.push(cls.to_string());
                    None
                }
            })
            // flatten all the inner iters.
            .flatten()
            .map(|s| s.as_str())
            .collect();

        if !invalid_classes.is_empty() {
            return Err(SchemaError::InvalidClass(invalid_classes));
        };

        let removed = prev_attrs.difference(&new_attrs).copied().collect();
        let added = new_attrs.difference(&prev_attrs).copied().collect();

        Ok((added, removed))
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
            if a.syntax == SyntaxType::ReferenceUuid ||
                a.syntax == SyntaxType::OauthScopeMap ||
                // So that when an rs is removed we trigger removal of the sessions.
                a.syntax == SyntaxType::Oauth2Session
            // May not need to be a ref type since it doesn't have external links/impact?
            // || a.syntax == SyntaxType::Session
            {
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

    pub fn reload_idxmeta(&self) -> Vec<IdxKey> {
        self.get_attributes()
            .values()
            .flat_map(|a| {
                a.index.iter().map(move |itype: &IndexType| IdxKey {
                    attr: a.name.clone(),
                    itype: *itype,
                })
            })
            .collect()
    }

    #[instrument(level = "debug", name = "schema::generate_in_memory", skip_all)]
    pub fn generate_in_memory(&mut self) -> Result<(), OperationError> {
        //
        self.classes.clear();
        self.attributes.clear();
        // Bootstrap in definitions of our own schema types
        // First, add all the needed core attributes for schema parsing
        self.attributes.insert(
            AttrString::from("class"),
            SchemaAttribute {
                name: AttrString::from("class"),
                uuid: UUID_SCHEMA_ATTR_CLASS,
                description: String::from("The set of classes defining an object"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality, IndexType::Presence],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("uuid"),
            SchemaAttribute {
                name: AttrString::from("uuid"),
                uuid: UUID_SCHEMA_ATTR_UUID,
                description: String::from("The universal unique id of the object"),
                multivalue: false,
                // Uniqueness is handled by base.rs, not attrunique here due to
                // needing to check recycled objects too.
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality, IndexType::Presence],
                syntax: SyntaxType::Uuid,
            },
        );
        self.attributes.insert(
            AttrString::from("last_modified_cid"),
            SchemaAttribute {
                name: AttrString::from("last_modified_cid"),
                uuid: UUID_SCHEMA_ATTR_LAST_MOD_CID,
                description: String::from("The cid of the last change to this object"),
                multivalue: false,
                // Uniqueness is handled by base.rs, not attrunique here due to
                // needing to check recycled objects too.
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Cid,
            },
        );
        self.attributes.insert(
            AttrString::from("name"),
            SchemaAttribute {
                name: AttrString::from("name"),
                uuid: UUID_SCHEMA_ATTR_NAME,
                description: String::from("The shortform name of an object"),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: true,
                replicated: true,
                index: vec![IndexType::Equality, IndexType::Presence],
                syntax: SyntaxType::Utf8StringIname,
            },
        );
        self.attributes.insert(
            AttrString::from("spn"),
            SchemaAttribute {
                name: AttrString::from("spn"),
                uuid: UUID_SCHEMA_ATTR_SPN,
                description: String::from(
                    "The Security Principal Name of an object, unique across all domain trusts",
                ),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::SecurityPrincipalName,
            },
        );
        self.attributes.insert(
            AttrString::from("attributename"),
            SchemaAttribute {
                name: AttrString::from("attributename"),
                uuid: UUID_SCHEMA_ATTR_ATTRIBUTENAME,
                description: String::from("The name of a schema attribute"),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("classname"),
            SchemaAttribute {
                name: AttrString::from("classname"),
                uuid: UUID_SCHEMA_ATTR_CLASSNAME,
                description: String::from("The name of a schema class"),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("description"),
            SchemaAttribute {
                name: AttrString::from("description"),
                uuid: UUID_SCHEMA_ATTR_DESCRIPTION,
                description: String::from("A description of an attribute, object or class"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: true,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8String,
            },
        );
        self.attributes.insert(AttrString::from("multivalue"), SchemaAttribute {
                name: AttrString::from("multivalue"),
                uuid: UUID_SCHEMA_ATTR_MULTIVALUE,
                description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(AttrString::from("phantom"), SchemaAttribute {
                name: AttrString::from("phantom"),
                uuid: UUID_SCHEMA_ATTR_PHANTOM,
                description: String::from("If true, this attribute must NOT be present in any may/must sets of a class as. This represents generated attributes."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(AttrString::from("sync_allowed"), SchemaAttribute {
                name: AttrString::from("sync_allowed"),
                uuid: UUID_SCHEMA_ATTR_SYNC_ALLOWED,
                description: String::from("If true, this attribute or class can by synchronised by an external scim import"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(AttrString::from("replicated"), SchemaAttribute {
                name: AttrString::from("replicated"),
                uuid: UUID_SCHEMA_ATTR_REPLICATED,
                description: String::from("If true, this attribute or class can by replicated between nodes in the topology"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(
            AttrString::from("unique"),
            SchemaAttribute {
                name: AttrString::from("unique"),
                uuid: UUID_SCHEMA_ATTR_UNIQUE,
                description: String::from(
                    "If true, this attribute must store a unique value through out the database.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Boolean,
            },
        );
        self.attributes.insert(
            AttrString::from("index"),
            SchemaAttribute {
                name: AttrString::from("index"),
                uuid: UUID_SCHEMA_ATTR_INDEX,
                description: String::from(
                    "Describe the indexes to apply to instances of this attribute.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::IndexId,
            },
        );
        self.attributes.insert(
            AttrString::from("syntax"),
            SchemaAttribute {
                name: AttrString::from("syntax"),
                uuid: UUID_SCHEMA_ATTR_SYNTAX,
                description: String::from(
                    "Describe the syntax of this attribute. This affects indexing and sorting.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::SyntaxId,
            },
        );
        self.attributes.insert(
            AttrString::from("systemmay"),
            SchemaAttribute {
                name: AttrString::from("systemmay"),
                uuid: UUID_SCHEMA_ATTR_SYSTEMMAY,
                description: String::from(
                    "A list of system provided optional attributes this class can store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("may"),
            SchemaAttribute {
                name: AttrString::from("may"),
                uuid: UUID_SCHEMA_ATTR_MAY,
                description: String::from(
                    "A user modifiable list of optional attributes this class can store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("systemmust"),
            SchemaAttribute {
                name: AttrString::from("systemmust"),
                uuid: UUID_SCHEMA_ATTR_SYSTEMMUST,
                description: String::from(
                    "A list of system provided required attributes this class must store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("must"),
            SchemaAttribute {
                name: AttrString::from("must"),
                uuid: UUID_SCHEMA_ATTR_MUST,
                description: String::from(
                    "A user modifiable list of required attributes this class must store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
                AttrString::from("systemsupplements"),
                SchemaAttribute {
                    name: AttrString::from("systemsupplements"),
                    uuid: UUID_SCHEMA_ATTR_SYSTEMSUPPLEMENTS,
                    description: String::from(
                        "A set of classes that this type supplements too, where this class can't exist without their presence.",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: true,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
        self.attributes.insert(
                AttrString::from("supplements"),
                SchemaAttribute {
                    name: AttrString::from("supplements"),
                    uuid: UUID_SCHEMA_ATTR_SUPPLEMENTS,
                    description: String::from(
                        "A set of user modifiable classes, where this determines that at least one other type must supplement this type",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: true,
                    index: vec![],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
        self.attributes.insert(
            AttrString::from("systemexcludes"),
            SchemaAttribute {
                name: AttrString::from("systemexcludes"),
                uuid: UUID_SCHEMA_ATTR_SYSTEMEXCLUDES,
                description: String::from(
                    "A set of classes that are denied presence in connection to this class",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
                AttrString::from("excludes"),
                SchemaAttribute {
                    name: AttrString::from("excludes"),
                    uuid: UUID_SCHEMA_ATTR_EXCLUDES,
                    description: String::from(
                        "A set of user modifiable classes that are denied presence in connection to this class",
                    ),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: true,
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
                    uuid: UUID_SCHEMA_ATTR_ACP_ENABLE,
                    description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforce. False is checked but not enforced."),
                    multivalue: false,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: true,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Boolean,
                },
            );

        self.attributes.insert(
            AttrString::from("acp_receiver"),
            SchemaAttribute {
                name: AttrString::from("acp_receiver"),
                uuid: UUID_SCHEMA_ATTR_ACP_RECEIVER,
                description: String::from(
                    "Who the ACP applies to, constraining or allowing operations.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality, IndexType::SubString],
                syntax: SyntaxType::JsonFilter,
            },
        );
        self.attributes.insert(
            AttrString::from("acp_receiver_group"),
            SchemaAttribute {
                name: AttrString::from("acp_receiver_group"),
                uuid: UUID_SCHEMA_ATTR_ACP_RECEIVER_GROUP,
                description: String::from(
                    "The group that receives this access control to allow access",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::ReferenceUuid,
            },
        );

        self.attributes.insert(
            AttrString::from("acp_targetscope"),
            SchemaAttribute {
                name: AttrString::from("acp_targetscope"),
                uuid: UUID_SCHEMA_ATTR_ACP_TARGETSCOPE,
                description: String::from(
                    "The effective targets of the ACP, IE what will be acted upon.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality, IndexType::SubString],
                syntax: SyntaxType::JsonFilter,
            },
        );
        self.attributes.insert(
            AttrString::from("acp_search_attr"),
            SchemaAttribute {
                name: AttrString::from("acp_search_attr"),
                uuid: UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR,
                description: String::from(
                    "The attributes that may be viewed or searched by the receiver on targetscope.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("acp_create_class"),
            SchemaAttribute {
                name: AttrString::from("acp_create_class"),
                uuid: UUID_SCHEMA_ATTR_ACP_CREATE_CLASS,
                description: String::from("The set of classes that can be created on a new entry."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("acp_create_attr"),
            SchemaAttribute {
                name: AttrString::from("acp_create_attr"),
                uuid: UUID_SCHEMA_ATTR_ACP_CREATE_ATTR,
                description: String::from(
                    "The set of attribute types that can be created on an entry.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        self.attributes.insert(
            AttrString::from("acp_modify_removedattr"),
            SchemaAttribute {
                name: AttrString::from("acp_modify_removedattr"),
                uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR,
                description: String::from(
                    "The set of attribute types that could be removed or purged in a modification.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("acp_modify_presentattr"),
            SchemaAttribute {
                name: AttrString::from("acp_modify_presentattr"),
                uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR,
                description: String::from(
                    "The set of attribute types that could be added or asserted in a modification.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
                AttrString::from("acp_modify_class"),
                SchemaAttribute {
                    name: AttrString::from("acp_modify_class"),
                    uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS,
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: true,
                    index: vec![IndexType::Equality],
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
        // MO/Member
        self.attributes.insert(
            AttrString::from("memberof"),
            SchemaAttribute {
                name: AttrString::from("memberof"),
                uuid: UUID_SCHEMA_ATTR_MEMBEROF,
                description: String::from("reverse group membership of the object"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: false,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            AttrString::from("directmemberof"),
            SchemaAttribute {
                name: AttrString::from("directmemberof"),
                uuid: UUID_SCHEMA_ATTR_DIRECTMEMBEROF,
                description: String::from("reverse direct group membership of the object"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: false,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            AttrString::from("member"),
            SchemaAttribute {
                name: AttrString::from("member"),
                uuid: UUID_SCHEMA_ATTR_MEMBER,
                description: String::from("List of members of the group"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: true,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            AttrString::from("dynmember"),
            SchemaAttribute {
                name: AttrString::from("dynmember"),
                uuid: UUID_SCHEMA_ATTR_DYNMEMBER,
                description: String::from("List of dynamic members of the group"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: true,
                replicated: false,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        // Migration related
        self.attributes.insert(
            AttrString::from("version"),
            SchemaAttribute {
                name: AttrString::from("version"),
                uuid: UUID_SCHEMA_ATTR_VERSION,
                description: String::from(
                    "The systems internal migration version for provided objects",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Uint32,
            },
        );
        // Domain for sysinfo
        self.attributes.insert(
            AttrString::from("domain"),
            SchemaAttribute {
                name: AttrString::from("domain"),
                uuid: UUID_SCHEMA_ATTR_DOMAIN,
                description: String::from("A DNS Domain name entry."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringIname,
            },
        );
        self.attributes.insert(
            AttrString::from("claim"),
            SchemaAttribute {
                name: AttrString::from("claim"),
                uuid: UUID_SCHEMA_ATTR_CLAIM,
                description: String::from(
                    "The string identifier of an extracted claim that can be filtered",
                ),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("scope"),
            SchemaAttribute {
                name: AttrString::from("scope"),
                uuid: UUID_SCHEMA_ATTR_SCOPE,
                description: String::from(
                    "The string identifier of a permission scope in a session",
                ),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        // External Scim Sync
        self.attributes.insert(
            AttrString::from("sync_external_id"),
            SchemaAttribute {
                name: AttrString::from("sync_external_id"),
                uuid: UUID_SCHEMA_ATTR_SYNC_EXTERNAL_ID,
                description: String::from(
                    "An external string ID of an entry imported from a sync agreement",
                ),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("sync_parent_uuid"),
            SchemaAttribute {
                name: AttrString::from("sync_parent_uuid"),
                uuid: UUID_SCHEMA_ATTR_SYNC_PARENT_UUID,
                description: String::from(
                    "The UUID of the parent sync agreement that created this entry.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![IndexType::Equality],
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            AttrString::from("sync_class"),
            SchemaAttribute {
                name: AttrString::from("sync_class"),
                uuid: UUID_SCHEMA_ATTR_SYNC_CLASS,
                description: String::from("The set of classes requested by the sync client."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: true,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        self.attributes.insert(
            AttrString::from("password_import"),
            SchemaAttribute {
                name: AttrString::from("password_import"),
                uuid: UUID_SCHEMA_ATTR_PASSWORD_IMPORT,
                description: String::from("An imported password hash from an external system."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: true,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Utf8String,
            },
        );

        self.attributes.insert(
            AttrString::from("totp_import"),
            SchemaAttribute {
                name: AttrString::from("totp_import"),
                uuid: UUID_SCHEMA_ATTR_TOTP_IMPORT,
                description: String::from("An imported totp secret from an external system."),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: true,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::TotpSecret,
            },
        );

        // LDAP Masking Phantoms
        self.attributes.insert(
            AttrString::from("dn"),
            SchemaAttribute {
                name: AttrString::from("dn"),
                uuid: UUID_SCHEMA_ATTR_DN,
                description: String::from("An LDAP Compatible DN"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("entrydn"),
            SchemaAttribute {
                name: AttrString::from("entrydn"),
                uuid: UUID_SCHEMA_ATTR_ENTRYDN,
                description: String::from("An LDAP Compatible EntryDN"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("entryuuid"),
            SchemaAttribute {
                name: AttrString::from("entryuuid"),
                uuid: UUID_SCHEMA_ATTR_ENTRYUUID,
                description: String::from("An LDAP Compatible entryUUID"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Uuid,
            },
        );
        self.attributes.insert(
            AttrString::from("objectclass"),
            SchemaAttribute {
                name: AttrString::from("objectclass"),
                uuid: UUID_SCHEMA_ATTR_OBJECTCLASS,
                description: String::from("An LDAP Compatible objectClass"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            AttrString::from("cn"),
            SchemaAttribute {
                name: AttrString::from("cn"),
                uuid: UUID_SCHEMA_ATTR_CN,
                description: String::from("An LDAP Compatible objectClass"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Utf8StringIname,
            },
        );
        self.attributes.insert(
            AttrString::from("keys"),
            SchemaAttribute {
                name: AttrString::from("keys"),
                uuid: UUID_SCHEMA_ATTR_KEYS,
                description: String::from("An LDAP Compatible keys (ssh)"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::SshKey,
            },
        );
        self.attributes.insert(
            AttrString::from("sshpublickey"),
            SchemaAttribute {
                name: AttrString::from("sshpublickey"),
                uuid: UUID_SCHEMA_ATTR_SSHPUBLICKEY,
                description: String::from("An LDAP Compatible sshPublicKey"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::SshKey,
            },
        );
        self.attributes.insert(
            AttrString::from("email"),
            SchemaAttribute {
                name: AttrString::from("email"),
                uuid: UUID_SCHEMA_ATTR_EMAIL,
                description: String::from("An LDAP Compatible email"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            AttrString::from("emailprimary"),
            SchemaAttribute {
                name: AttrString::from("emailprimary"),
                uuid: UUID_SCHEMA_ATTR_EMAILPRIMARY,
                description: String::from("An LDAP Compatible primary email"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            AttrString::from("emailalternative"),
            SchemaAttribute {
                name: AttrString::from("emailalternative"),
                uuid: UUID_SCHEMA_ATTR_EMAILALTERNATIVE,
                description: String::from("An LDAP Compatible alternative email"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            AttrString::from("emailaddress"),
            SchemaAttribute {
                name: AttrString::from("emailaddress"),
                uuid: UUID_SCHEMA_ATTR_EMAILADDRESS,
                description: String::from("An LDAP Compatible emailAddress"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            AttrString::from("uidnumber"),
            SchemaAttribute {
                name: AttrString::from("uidnumber"),
                uuid: UUID_SCHEMA_ATTR_UIDNUMBER,
                description: String::from("An LDAP Compatible uidNumber"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: false,
                index: vec![],
                syntax: SyntaxType::Uint32,
            },
        );
        // end LDAP masking phantoms

        self.classes.insert(
            AttrString::from("attributetype"),
            SchemaClass {
                name: AttrString::from("attributetype"),
                uuid: UUID_SCHEMA_CLASS_ATTRIBUTETYPE,
                description: String::from("Definition of a schema attribute"),
                systemmay: vec![
                    AttrString::from("replicated"),
                    AttrString::from("phantom"),
                    AttrString::from("sync_allowed"),
                    AttrString::from("index"),
                ],
                systemmust: vec![
                    AttrString::from("class"),
                    AttrString::from("attributename"),
                    AttrString::from("multivalue"),
                    AttrString::from("unique"),
                    AttrString::from("syntax"),
                    AttrString::from("description"),
                ],
                systemexcludes: vec![AttrString::from("classtype")],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("classtype"),
            SchemaClass {
                name: AttrString::from("classtype"),
                uuid: UUID_SCHEMA_CLASS_CLASSTYPE,
                description: String::from("Definition of a schema classtype"),
                systemmay: vec![
                    AttrString::from("sync_allowed"),
                    AttrString::from("systemmay"),
                    AttrString::from("may"),
                    AttrString::from("systemmust"),
                    AttrString::from("must"),
                    AttrString::from("systemsupplements"),
                    AttrString::from("supplements"),
                    AttrString::from("systemexcludes"),
                    AttrString::from("excludes"),
                ],
                systemmust: vec![
                    AttrString::from("class"),
                    AttrString::from("classname"),
                    AttrString::from("description"),
                ],
                systemexcludes: vec![AttrString::from("attributetype")],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("object"),
            SchemaClass {
                name: AttrString::from("object"),
                uuid: UUID_SCHEMA_CLASS_OBJECT,
                description: String::from("A system created class that all objects must contain"),
                systemmay: vec![AttrString::from("description")],
                systemmust: vec![
                    AttrString::from("class"),
                    AttrString::from("uuid"),
                    AttrString::from("last_modified_cid"),
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("memberof"),
            SchemaClass {
                name: AttrString::from("memberof"),
                uuid: UUID_SCHEMA_CLASS_MEMBEROF,
                description: String::from(
                    "Class that is dynamically added to recipients of memberof or directmemberof",
                ),
                systemmay: vec![
                    AttrString::from("memberof"),
                    AttrString::from("directmemberof"),
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("extensibleobject"),
            SchemaClass {
                name: AttrString::from("extensibleobject"),
                uuid: UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT,
                description: String::from(
                    "A class type that has green hair and turns off all rules ...",
                ),
                ..Default::default()
            },
        );
        /* These two classes are core to the entry lifecycle for recycling and tombstoning */
        self.classes.insert(
                AttrString::from("recycled"),
                SchemaClass {
                    name: AttrString::from("recycled"),
                    uuid: UUID_SCHEMA_CLASS_RECYCLED,
                    description: String::from("An object that has been deleted, but still recoverable via the revive operation. Recycled objects are not modifiable, only revivable."),
                    .. Default::default()
                },
            );
        self.classes.insert(
                AttrString::from("tombstone"),
                SchemaClass {
                    name: AttrString::from("tombstone"),
                    uuid: UUID_SCHEMA_CLASS_TOMBSTONE,
                    description: String::from("An object that is purged from the recycle bin. This is a system internal state. Tombstones have no attributes beside UUID."),
                    systemmust: vec![
                        AttrString::from("class"),
                        AttrString::from("uuid"),
                    ],
                    .. Default::default()
                },
            );
        // sysinfo
        self.classes.insert(
            AttrString::from("system_info"),
            SchemaClass {
                name: AttrString::from("system_info"),
                uuid: UUID_SCHEMA_CLASS_SYSTEM_INFO,
                description: String::from("System metadata object class"),
                systemmust: vec![AttrString::from("version")],
                ..Default::default()
            },
        );
        // ACP
        self.classes.insert(
            AttrString::from("access_control_profile"),
            SchemaClass {
                name: AttrString::from("access_control_profile"),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE,
                description: String::from("System Access Control Profile Class"),
                systemmay: vec![
                    AttrString::from("acp_enable"),
                    AttrString::from("description"),
                    AttrString::from("acp_receiver"),
                ],
                systemmust: vec![
                    AttrString::from("acp_receiver_group"),
                    AttrString::from("acp_targetscope"),
                    AttrString::from("name"),
                ],
                systemsupplements: vec![
                    AttrString::from("access_control_search"),
                    AttrString::from("access_control_delete"),
                    AttrString::from("access_control_modify"),
                    AttrString::from("access_control_create"),
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("access_control_search"),
            SchemaClass {
                name: AttrString::from("access_control_search"),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH,
                description: String::from("System Access Control Search Class"),
                systemmust: vec![AttrString::from("acp_search_attr")],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("access_control_delete"),
            SchemaClass {
                name: AttrString::from("access_control_delete"),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE,
                description: String::from("System Access Control DELETE Class"),
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("access_control_modify"),
            SchemaClass {
                name: AttrString::from("access_control_modify"),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY,
                description: String::from("System Access Control Modify Class"),
                systemmay: vec![
                    AttrString::from("acp_modify_removedattr"),
                    AttrString::from("acp_modify_presentattr"),
                    AttrString::from("acp_modify_class"),
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("access_control_create"),
            SchemaClass {
                name: AttrString::from("access_control_create"),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE,
                description: String::from("System Access Control Create Class"),
                systemmay: vec![
                    AttrString::from("acp_create_class"),
                    AttrString::from("acp_create_attr"),
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("system"),
            SchemaClass {
                name: AttrString::from("system"),
                uuid: UUID_SCHEMA_CLASS_SYSTEM,
                description: String::from("A class denoting that a type is system generated and protected. It has special internal behaviour."),
                .. Default::default()
            },
        );
        self.classes.insert(
            AttrString::from("sync_object"),
            SchemaClass {
                name: AttrString::from("sync_object"),
                uuid: UUID_SCHEMA_CLASS_SYNC_OBJECT,
                description: String::from("A class denoting that an entry is synchronised from an external source. This entry may not be modifiable."),
                systemmust: vec![
                    AttrString::from("sync_parent_uuid")
                ],
                systemmay: vec![
                    AttrString::from("sync_external_id"),
                    AttrString::from("sync_class"),
                ],
                .. Default::default()
            },
        );

        let r = self.validate();
        if r.is_empty() {
            admin_debug!("schema validate -> passed");
            Ok(())
        } else {
            admin_error!(err = ?r, "schema validate -> errors");
            Err(OperationError::ConsistencyError(r))
        }
    }
}

impl<'a> SchemaTransaction for SchemaWriteTransaction<'a> {
    fn get_attributes_unique(&self) -> &Vec<AttrString> {
        &self.unique_cache
    }

    fn get_reference_types(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &self.ref_cache
    }

    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass> {
        &self.classes
    }

    fn get_attributes(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &self.attributes
    }
}

impl SchemaTransaction for SchemaReadTransaction {
    fn get_attributes_unique(&self) -> &Vec<AttrString> {
        &self.unique_cache
    }

    fn get_reference_types(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &self.ref_cache
    }

    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass> {
        &self.classes
    }

    fn get_attributes(&self) -> &HashMap<AttrString, SchemaAttribute> {
        &self.attributes
    }
}

impl Schema {
    pub fn new() -> Result<Self, OperationError> {
        let s = Schema {
            classes: CowCell::new(HashMap::with_capacity(128)),
            attributes: CowCell::new(HashMap::with_capacity(128)),
            unique_cache: CowCell::new(Vec::new()),
            ref_cache: CowCell::new(HashMap::with_capacity(64)),
        };
        // let mut sw = task::block_on(s.write());
        let mut sw = s.write();
        let r1 = sw.generate_in_memory();
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

    #[cfg(test)]
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
    use kanidm_proto::v1::{ConsistencyError, SchemaError};
    use uuid::Uuid;

    use crate::prelude::*;
    use crate::schema::{
        IndexType, Schema, SchemaAttribute, SchemaClass, SchemaTransaction, SyntaxType,
    };

    // use crate::proto_v1::Filter as ProtoFilter;

    macro_rules! validate_schema {
        ($sch:ident) => {{
            // Turns into a result type
            let r: Result<Vec<()>, ConsistencyError> = $sch.validate().into_iter().collect();
            assert!(r.is_ok());
        }};
    }

    macro_rules! sch_from_entry_ok {
        (
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_sealed_committed() };

            let r1 = <$type>::try_from(&ev1);
            assert!(r1.is_ok());
        }};
    }

    macro_rules! sch_from_entry_err {
        (
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_sealed_committed() };

            let r1 = <$type>::try_from(&ev1);
            assert!(r1.is_err());
        }};
    }

    #[test]
    fn test_schema_attribute_from_entry() {
        sch_from_entry_err!(
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
    }

    #[test]
    fn test_schema_class_from_entry() {
        sch_from_entry_err!(
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
            index: vec![IndexType::Equality],
            syntax: SyntaxType::Utf8StringInsensitive,
            ..Default::default()
        };

        let r1 = single_value_string.validate_ava("single_value", &(vs_iutf8!["test"] as _));
        assert_eq!(r1, Ok(()));

        let rvs = vs_iutf8!["test1", "test2"] as _;
        let r2 = single_value_string.validate_ava("single_value", &rvs);
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
            index: vec![IndexType::Equality],
            syntax: SyntaxType::Utf8String,
            ..Default::default()
        };

        let rvs = vs_utf8!["test1".to_string(), "test2".to_string()] as _;
        let r5 = multi_value_string.validate_ava("mv_string", &rvs);
        assert_eq!(r5, Ok(()));

        let multi_value_boolean = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: AttrString::from("mv_bool"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            index: vec![IndexType::Equality],
            syntax: SyntaxType::Boolean,
            ..Default::default()
        };

        // Since valueset now disallows such shenangians at a type level, this can't occur
        /*
        let rvs = unsafe {
            valueset![
                Value::new_bool(true),
                Value::new_iutf8("test1"),
                Value::new_iutf8("test2")
            ]
        };
        let r3 = multi_value_boolean.validate_ava("mv_bool", &rvs);
        assert_eq!(
            r3,
            Err(SchemaError::InvalidAttributeSyntax("mv_bool".to_string()))
        );
        */

        let rvs = vs_bool![true, false];
        let r4 = multi_value_boolean.validate_ava("mv_bool", &(rvs as _));
        assert_eq!(r4, Ok(()));

        // syntax_id and index_type values
        let single_value_syntax = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: AttrString::from("sv_syntax"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            index: vec![IndexType::Equality],
            syntax: SyntaxType::SyntaxId,
            ..Default::default()
        };

        let rvs = vs_syntax![SyntaxType::try_from("UTF8STRING").unwrap()] as _;
        let r6 = single_value_syntax.validate_ava("sv_syntax", &rvs);
        assert_eq!(r6, Ok(()));

        let rvs = vs_utf8!["thaeountaheu".to_string()] as _;
        let r7 = single_value_syntax.validate_ava("sv_syntax", &rvs);
        assert_eq!(
            r7,
            Err(SchemaError::InvalidAttributeSyntax("sv_syntax".to_string()))
        );

        let single_value_index = SchemaAttribute {
            // class: vec![String::from("attributetype")],
            name: AttrString::from("sv_index"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            index: vec![IndexType::Equality],
            syntax: SyntaxType::IndexId,
            ..Default::default()
        };
        //
        let rvs = vs_index![IndexType::try_from("EQUALITY").unwrap()] as _;
        let r8 = single_value_index.validate_ava("sv_index", &rvs);
        assert_eq!(r8, Ok(()));

        let rvs = vs_utf8!["thaeountaheu".to_string()] as _;
        let r9 = single_value_index.validate_ava("sv_index", &rvs);
        assert_eq!(
            r9,
            Err(SchemaError::InvalidAttributeSyntax("sv_index".to_string()))
        );
    }

    #[test]
    fn test_schema_simple() {
        let schema = Schema::new().expect("failed to create schema");
        let schema_ro = schema.read();
        validate_schema!(schema_ro);
    }

    #[test]
    fn test_schema_entries() {
        sketching::test_init();
        // Given an entry, assert it's schema is valid
        // We do
        let schema_outer = Schema::new().expect("failed to create schema");
        let schema = schema_outer.read();

        let e_no_uuid = unsafe { entry_init!().into_invalid_new() };

        assert_eq!(
            e_no_uuid.validate(&schema),
            Err(SchemaError::MissingMustAttribute(vec!["uuid".to_string()]))
        );

        let e_no_class = unsafe {
            entry_init!((
                "uuid",
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ))
            .into_invalid_new()
        };

        assert_eq!(e_no_class.validate(&schema), Err(SchemaError::NoClassFound));

        let e_bad_class = unsafe {
            entry_init!(
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
                ),
                ("class", Value::new_class("zzzzzz"))
            )
            .into_invalid_new()
        };
        assert_eq!(
            e_bad_class.validate(&schema),
            Err(SchemaError::InvalidClass(vec!["zzzzzz".to_string()]))
        );

        let e_attr_invalid = unsafe {
            entry_init!(
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
                ),
                ("class", CLASS_OBJECT.clone()),
                ("class", CLASS_ATTRIBUTETYPE.clone())
            )
            .into_invalid_new()
        };
        let res = e_attr_invalid.validate(&schema);
        assert!(match res {
            Err(SchemaError::MissingMustAttribute(_)) => true,
            _ => false,
        });

        let e_attr_invalid_may = unsafe {
            entry_init!(
                ("class", CLASS_OBJECT.clone()),
                ("class", CLASS_ATTRIBUTETYPE.clone()),
                ("attributename", Value::new_iutf8("testattr")),
                ("description", Value::Utf8("testattr".to_string())),
                ("multivalue", Value::Bool(false)),
                ("unique", Value::Bool(false)),
                ("syntax", Value::Syntax(SyntaxType::Utf8String)),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
                ),
                ("zzzzz", Value::Utf8("zzzz".to_string()))
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_attr_invalid_may.validate(&schema),
            Err(SchemaError::AttributeNotValidForClass("zzzzz".to_string()))
        );

        let e_attr_invalid_syn = unsafe {
            entry_init!(
                ("class", CLASS_OBJECT.clone()),
                ("class", CLASS_ATTRIBUTETYPE.clone()),
                ("attributename", Value::new_iutf8("testattr")),
                ("description", Value::Utf8("testattr".to_string())),
                ("multivalue", Value::Utf8("false".to_string())),
                ("unique", Value::Bool(false)),
                ("syntax", Value::Syntax(SyntaxType::Utf8String)),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
                )
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
        let e_phantom = unsafe {
            entry_init!(
                ("class", CLASS_OBJECT.clone()),
                ("class", CLASS_ATTRIBUTETYPE.clone()),
                ("attributename", Value::new_iutf8("testattr")),
                ("description", Value::Utf8("testattr".to_string())),
                ("multivalue", Value::Bool(false)),
                ("unique", Value::Bool(false)),
                ("syntax", Value::Syntax(SyntaxType::Utf8String)),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
                ),
                ("password_import", Value::Utf8("password".to_string()))
            )
            .into_invalid_new()
        };
        assert!(e_phantom.validate(&schema).is_err());

        let e_ok = unsafe {
            entry_init!(
                ("class", CLASS_OBJECT.clone()),
                ("class", CLASS_ATTRIBUTETYPE.clone()),
                ("attributename", Value::new_iutf8("testattr")),
                ("description", Value::Utf8("testattr".to_string())),
                ("multivalue", Value::Bool(true)),
                ("unique", Value::Bool(false)),
                ("syntax", Value::Syntax(SyntaxType::Utf8String)),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
                )
            )
            .into_invalid_new()
        };
        assert!(e_ok.validate(&schema).is_ok());
    }

    #[test]
    fn test_schema_entry_validate() {
        // Check that entries can be normalised and validated sanely
        let schema_outer = Schema::new().expect("failed to create schema");
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
    }

    #[test]
    fn test_schema_extensible() {
        let schema_outer = Schema::new().expect("failed to create schema");
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
    }

    #[test]
    fn test_schema_filter_validation() {
        let schema_outer = Schema::new().expect("failed to create schema");
        let schema = schema_outer.read();
        // Test non existent attr name
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
    }

    #[test]
    fn test_schema_class_phantom_reject() {
        // Check that entries can be normalised and validated sanely
        let schema_outer = Schema::new().expect("failed to create schema");
        let mut schema = schema_outer.write_blocking();

        assert!(schema.validate().is_empty());

        // Attempt to create a class with a phantom attribute, should be refused.
        let class = SchemaClass {
            name: AttrString::from("testobject"),
            uuid: Uuid::new_v4(),
            description: String::from("test object"),
            systemmay: vec![AttrString::from("claim")],
            ..Default::default()
        };

        assert!(schema.update_classes(vec![class]).is_ok());

        assert!(schema.validate().len() == 1);
    }

    #[test]
    fn test_schema_class_exclusion_requires() {
        sketching::test_init();

        let schema_outer = Schema::new().expect("failed to create schema");
        let mut schema = schema_outer.write_blocking();

        assert!(schema.validate().is_empty());

        // We setup some classes that have requires and excludes and check that they
        // are enforced correctly.
        let class_account = SchemaClass {
            name: AttrString::from("account"),
            uuid: Uuid::new_v4(),
            description: String::from("account object"),
            systemmust: vec![
                AttrString::from("class"),
                AttrString::from("uuid"),
                AttrString::from("last_modified_cid"),
            ],
            systemsupplements: vec![AttrString::from("service"), AttrString::from("person")],
            ..Default::default()
        };

        let class_person = SchemaClass {
            name: AttrString::from("person"),
            uuid: Uuid::new_v4(),
            description: String::from("person object"),
            systemmust: vec![
                AttrString::from("class"),
                AttrString::from("uuid"),
                AttrString::from("last_modified_cid"),
            ],
            ..Default::default()
        };

        let class_service = SchemaClass {
            name: AttrString::from("service"),
            uuid: Uuid::new_v4(),
            description: String::from("service object"),
            systemmust: vec![
                AttrString::from("class"),
                AttrString::from("uuid"),
                AttrString::from("last_modified_cid"),
            ],
            excludes: vec![AttrString::from("person")],
            ..Default::default()
        };

        assert!(schema
            .update_classes(vec![class_account, class_person, class_service])
            .is_ok());

        // Missing person or service account.
        let e_account = unsafe {
            entry_init!(
                ("class", Value::new_class("account")),
                ("uuid", Value::Uuid(Uuid::new_v4()))
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_account.validate(&schema),
            Err(SchemaError::SupplementsNotSatisfied(vec![
                "service".to_string(),
                "person".to_string(),
            ]))
        );

        // Service account missing account
        /*
        let e_service = unsafe { entry_init!(
            ("class", Value::new_class("service")),
            ("uuid", Value::new_uuid(Uuid::new_v4()))
        ).into_invalid_new() };

        assert_eq!(
            e_service.validate(&schema),
            Err(SchemaError::RequiresNotSatisfied(vec!["account".to_string()]))
        );
        */

        // Service can't have person
        let e_service_person = unsafe {
            entry_init!(
                ("class", Value::new_class("service")),
                ("class", Value::new_class("account")),
                ("class", Value::new_class("person")),
                ("uuid", Value::Uuid(Uuid::new_v4()))
            )
            .into_invalid_new()
        };

        assert_eq!(
            e_service_person.validate(&schema),
            Err(SchemaError::ExcludesNotSatisfied(
                vec!["person".to_string()]
            ))
        );

        // These are valid configurations.
        let e_service_valid = unsafe {
            entry_init!(
                ("class", Value::new_class("service")),
                ("class", Value::new_class("account")),
                ("uuid", Value::Uuid(Uuid::new_v4()))
            )
            .into_invalid_new()
        };

        assert!(e_service_valid.validate(&schema).is_ok());

        let e_person_valid = unsafe {
            entry_init!(
                ("class", Value::new_class("person")),
                ("class", Value::new_class("account")),
                ("uuid", Value::Uuid(Uuid::new_v4()))
            )
            .into_invalid_new()
        };

        assert!(e_person_valid.validate(&schema).is_ok());

        let e_person_valid = unsafe {
            entry_init!(
                ("class", Value::new_class("person")),
                ("uuid", Value::Uuid(Uuid::new_v4()))
            )
            .into_invalid_new()
        };

        assert!(e_person_valid.validate(&schema).is_ok());
    }
}

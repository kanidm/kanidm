//! Entries are the base unit of object storage in the server. This is one of the three foundational
//! concepts along with [`filter`]s and [`schema`] that everything else builds upon.
//!
//! An [`Entry`] is a collection of attribute-value sets. There are sometimes called attribute value
//! assertions, or AVAs. The attribute is a "key" and it holds 1 to infinite associated values
//! with no ordering. An entry has many AVAs. A pseudo example, minus schema and typing:
//!
//! ```text
//! Entry {
//!   "name": ["william"],
//!   "uuid": ["..."],
//!   "mail": ["maila@example.com", "mailb@example.com"],
//! };
//! ```
//!
//! There are three rules for entries:
//! * Must have an AVA for UUID containing a single value.
//! * Any AVA with zero values will be removed.
//! * AVAs are stored with no sorting.
//!
//! For more, see the [`Entry`] type.
//!
//! [`Entry`]: struct.Entry.html
//! [`filter`]: ../filter/index.html
//! [`schema`]: ../schema/index.html

use crate::credential::Credential;
use crate::filter::{Filter, FilterInvalid, FilterResolved, FilterValidResolved};
use crate::ldap::ldap_vattr_map;
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};
use crate::value::{IndexType, SyntaxType};
use crate::value::{PartialValue, Value};
use crate::valueset::ValueSet;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::Filter as ProtoFilter;
use kanidm_proto::v1::{OperationError, SchemaError};
use tracing::trace;

use crate::be::dbentry::{DbEntry, DbEntryV1, DbEntryVers};
use crate::be::{IdxKey, IdxSlope};

use ldap3_server::simple::{LdapPartialAttribute, LdapSearchResultEntry};
use std::collections::BTreeMap as Map;
pub use std::collections::BTreeSet as Set;
use std::collections::BTreeSet;
// use hashbrown::HashMap as Map;
use hashbrown::HashMap;
use smartstring::alias::String as AttrString;
use time::OffsetDateTime;
use uuid::Uuid;

// use std::convert::TryFrom;
// use std::str::FromStr;

// make a trait entry for everything to adhere to?
//  * How to get indexes out?
//  * How to track pending diffs?

// Entry is really similar to serde Value, but limits the possibility
// of what certain types could be.
//
// The idea of an entry is that we have
// an entry that looks like:
//
// {
//    'class': ['object', ...],
//    'attr': ['value', ...],
//    'attr': ['value', ...],
//    ...
// }
//
// When we send this as a result to clients, we could embed other objects as:
//
// {
//    'attr': [
//        'value': {
//        },
//    ],
// }
//

lazy_static! {
    static ref CLASS_EXTENSIBLE: PartialValue = PartialValue::new_class("extensibleobject");
    static ref PVCLASS_TOMBSTONE: PartialValue = PartialValue::new_class("tombstone");
    static ref PVCLASS_RECYCLED: PartialValue = PartialValue::new_class("recycled");
}

pub type EntrySealedCommitted = Entry<EntrySealed, EntryCommitted>;
pub type EntryInvalidCommitted = Entry<EntryInvalid, EntryCommitted>;
pub type EntryTuple = (EntrySealedCommitted, EntryInvalidCommitted);

// Entry should have a lifecycle of types. This is Raw (modifiable) and Entry (verified).
// This way, we can move between them, but only certain actions are possible on either
// This means modifications happen on Raw, but to move to Entry, you schema normalise.
// Vice versa, you can for free, move to Raw, but you lose the validation.

// Because this is type system it's "free" in the end, and means we force validation
// at the correct and required points of the entries life.

// This is specifically important for the commit to the backend, as we only want to
// commit validated types.

#[derive(Clone, Debug)]
pub struct EntryNew; // new
#[derive(Clone, Debug)]
pub struct EntryCommitted {
    id: u64,
} // It's been in the DB, so it has an id
  // pub struct EntryPurged;

#[derive(Clone, Debug)]
pub struct EntryInit;

/*  |
 *  | Init comes from a proto entry, it's new.
 *  | We add the current Cid before we allow mods.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryInvalid {
    cid: Cid,
}

/*  |
 *  | The changes made within this entry are validated by the schema.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryValid {
    // Asserted with schema, so we know it has a UUID now ...
    uuid: Uuid,
    cid: Cid,
}

/*  |
 *  | The changes are extracted into the changelog as needed, creating a
 *  | stable database entry.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntrySealed {
    uuid: Uuid,
}

#[derive(Clone, Debug)]
pub struct EntryReduced {
    uuid: Uuid,
}

fn compare_attrs(left: &Map<AttrString, ValueSet>, right: &Map<AttrString, ValueSet>) -> bool {
    // We can't shortcut based on len because cid mod may not be present.
    // Build the set of all keys between both.
    let allkeys: Set<&str> = left
        .keys()
        .filter(|k| k != &"last_modified_cid")
        .chain(right.keys().filter(|k| k != &"last_modified_cid"))
        .map(|s| s.as_str())
        .collect();

    allkeys.into_iter().all(|k| {
        // Both must be Some, and both must have the same interiors.
        left.get(k) == right.get(k)
    })
}

/// Entry is the core data storage type of the server. Almost every aspect of the server is
/// designed to read, handle and manipulate entries.
///
/// Entries store attribute value assertions, or AVA. These are sets of key-values.
///
/// Entries have a lifecycle within a single operation, and as part of replication.
/// The lifecycle for operations is defined through state and valid types. Each entry has a pair
/// Of these types at anytime. The first is the AVA [`schema`] and [`access`] control assertion
/// state. This is represented by the type `VALID` as one of `EntryValid`, `EntryInvalid` or
/// `EntryReduced`. Every entry starts as `EntryInvalid`, and when checked by the schema for
/// correctness, transitions to `EntryValid`. While an entry is `EntryValid` it can not be
/// altered - you must invalidate it to `EntryInvalid`, then modify, then check again.
/// An entry that has had access controls applied moves from `EntryValid` to `EntryReduced`,
/// to show that the AVAs have reduced to the valid read set of the current [`event`] user.
///
/// The second type of `STATE` represents the database commit state and internal db ID's. A
/// new entry that has never been committed is `EntryNew`, but an entry that has been retrieved
/// from the database is `EntryCommitted`. This affects the operations you can apply IE modify
/// or delete.
///
/// These types exist to prevent at compile time, mishandling of Entries, to ensure they are always
/// handled with the correct lifecycles and processes.
///
/// [`schema`]: ../schema/index.html
/// [`access`]: ../access/index.html
/// [`event`]: ../event/index.html
///
pub struct Entry<VALID, STATE> {
    valid: VALID,
    state: STATE,
    // We may need to change this to Set to allow borrow of Value -> PartialValue for lookups.
    attrs: Map<AttrString, ValueSet>,
}

impl<VALID, STATE> std::fmt::Debug for Entry<VALID, STATE>
where
    STATE: std::fmt::Debug,
    VALID: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Entry<EntrySealed, _>")
            .field("state", &self.state)
            .field("valid", &self.valid)
            .finish()
    }
}

impl<STATE> std::fmt::Display for Entry<EntrySealed, STATE> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.get_uuid())
    }
}

impl<STATE> std::fmt::Display for Entry<EntryInit, STATE> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Entry in initial state")
    }
}

impl<STATE> Entry<EntryInit, STATE> {
    /// Get the uuid of this entry.
    pub(crate) fn get_uuid(&self) -> Option<&Uuid> {
        self.attrs.get("uuid").and_then(|vs| vs.to_uuid_single())
    }
}

impl Default for Entry<EntryInit, EntryNew> {
    fn default() -> Self {
        Self::new()
    }
}

impl Entry<EntryInit, EntryNew> {
    pub fn new() -> Self {
        Entry {
            // This means NEVER COMMITED
            valid: EntryInit,
            state: EntryNew,
            attrs: Map::new(),
            // attrs: Map::with_capacity(32),
        }
    }

    /// Consume a Protocol Entry from JSON, and validate and process the data into an internal
    /// [`Entry`] type.
    pub fn from_proto_entry(
        audit: &mut AuditScope,
        e: &ProtoEntry,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        trace!("from_proto_entry");
        // Why not the trait? In the future we may want to extend
        // this with server aware functions for changes of the
        // incoming data.

        // Somehow we need to take the tree of e attrs, and convert
        // all ref types to our types ...
        let map2: Result<Map<AttrString, ValueSet>, OperationError> = e
            .attrs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                trace!(?k, ?v, "k, v");
                let nk = qs.get_schema().normalise_attr_name(k);
                let nv = ValueSet::from_result_value_iter(
                    v.iter().map(|vr| qs.clone_value(audit, &nk, vr)),
                );
                trace!(?nv, "nv");
                match nv {
                    Ok(nvi) => Ok((nk, nvi)),
                    Err(e) => Err(e),
                }
            })
            .collect();

        let x = map2?;

        Ok(Entry {
            // For now, we do a straight move, and we sort the incoming data
            // sets so that BST works.
            state: EntryNew,
            valid: EntryInit,
            attrs: x,
        })
    }

    /// Given a proto entry in JSON formed as a serialised string, processed that string
    /// into an Entry.
    pub fn from_proto_entry_str(
        audit: &mut AuditScope,
        es: &str,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        trace!("from_proto_entry_str");
        if cfg!(test) {
            if es.len() > 256 {
                let (dsp_es, _) = es.split_at(255);
                ltrace!(audit, "Parsing -> {}...", dsp_es);
            } else {
                ltrace!(audit, "Parsing -> {}", es);
            }
        }
        // str -> Proto entry
        let pe: ProtoEntry = serde_json::from_str(es).map_err(|e| {
            ladmin_error!(audit, "SerdeJson Failure -> {:?}", e);
            admin_error!(?e, "SerdeJson Failure");
            OperationError::SerdeJsonError
        })?;
        // now call from_proto_entry
        Self::from_proto_entry(audit, &pe, qs)
    }

    #[cfg(test)]
    pub(crate) fn unsafe_from_entry_str(es: &str) -> Self {
        // Just use log directly here, it's testing
        // str -> proto entry
        let pe: ProtoEntry = serde_json::from_str(es).expect("Invalid Proto Entry");
        // use a const map to convert str -> ava
        let x: Map<AttrString, ValueSet> = pe.attrs.into_iter()
            .filter_map(|(k, vs)| {
                if vs.is_empty() {
                    None
                } else {
                let attr = AttrString::from(k.to_lowercase());
                let vv: ValueSet = match attr.as_str() {
                    "attributename" | "classname" | "domain" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_iutf8(&v)).collect();
                        vs.unwrap()
                    }
                    "name" | "domain_name" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_iname(&v)).collect();
                        vs.unwrap()
                    }
                    "userid" | "uidnumber" => {
                        warn!("WARNING: Use of unstabilised attributes userid/uidnumber");
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_iutf8(&v)).collect();
                        vs.unwrap()
                    }
                    "class" | "acp_create_class" | "acp_modify_class"  => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_class(v.as_str())).collect();
                        vs.unwrap()
                    }
                    "acp_create_attr" | "acp_search_attr" | "acp_modify_removedattr" | "acp_modify_presentattr" |
                    "systemmay" | "may" | "systemmust" | "must"
                    => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_attr(v.as_str())).collect();
                        vs.unwrap()
                    }
                    "uuid" | "domain_uuid" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_uuids(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect();
                        vs.unwrap()
                    }
                    "member" | "memberof" | "directmemberof" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_refer_s(v.as_str()).unwrap() ).collect();
                        vs.unwrap()
                    }
                    "acp_enable" | "multivalue" | "unique" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_bools(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                            ).collect();
                        vs.unwrap()
                    }
                    "syntax" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_syntaxs(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect();
                        vs.unwrap()
                    }
                    "index" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_indexs(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect();
                        vs.unwrap()
                    }
                    "acp_targetscope" | "acp_receiver" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_json_filter_s(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect();
                        vs.unwrap()
                    }
                    "displayname" | "description" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_utf8(v)).collect();
                        vs.unwrap()
                    }
                    "spn" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| {
                            Value::new_spn_parse(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect SPN attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        }).collect();
                        vs.unwrap()
                    }
                    "gidnumber" | "version" => {
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| {
                            Value::new_uint32_str(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect UINT32 attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        }).collect();
                        vs.unwrap()
                    }
                    ia => {
                        warn!("WARNING: Allowing invalid attribute {} to be interpretted as UTF8 string. YOU MAY ENCOUNTER ODD BEHAVIOUR!!!", ia);
                        let vs: Option<ValueSet> = vs.into_iter().map(|v| Value::new_utf8(v)).collect();
                        vs.unwrap()
                    }
                };
                Some((attr, vv))
                }
            })
            .collect();

        // return the entry!
        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs: x,
        }
    }

    /// Assign the Change Identifier to this Entry, allowing it to be modified and then
    /// written to the `Backend`
    pub fn assign_cid(mut self, cid: Cid) -> Entry<EntryInvalid, EntryNew> {
        /* setup our last changed time */
        self.set_last_changed(cid.clone());

        Entry {
            valid: EntryInvalid { cid },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// Compare this entry to another.
    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

    #[cfg(test)]
    pub unsafe fn into_invalid_new(mut self) -> Entry<EntryInvalid, EntryNew> {
        self.set_last_changed(Cid::new_zero());
        Entry {
            valid: EntryInvalid {
                cid: Cid::new_zero(),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    #[cfg(test)]
    pub unsafe fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        Entry {
            valid: EntryValid {
                cid: Cid::new_zero(),
                uuid: self.get_uuid().expect("Invalid uuid").clone(),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    #[cfg(test)]
    pub unsafe fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self
            .get_uuid()
            .and_then(|u| Some(u.clone()))
            .unwrap_or_else(|| Uuid::new_v4());
        Entry {
            valid: EntrySealed { uuid },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    #[cfg(test)]
    pub unsafe fn into_sealed_new(self) -> Entry<EntrySealed, EntryNew> {
        Entry {
            valid: EntrySealed {
                uuid: self.get_uuid().expect("Invalid uuid").clone(),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// Add an attribute-value-assertion to this Entry.
    pub fn add_ava(&mut self, attr: &str, value: Value) {
        self.add_ava_int(attr, value)
    }

    /// Replace the existing content of an attribute set of this Entry, with a new set of Values.
    // pub fn set_ava(&mut self, attr: &str, values: Set<Value>) {
    pub fn set_ava<T>(&mut self, attr: &str, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        self.set_ava_int(attr, iter)
    }

    pub fn get_ava_mut(&mut self, attr: &str) -> Option<&mut ValueSet> {
        self.attrs.get_mut(attr)
    }
}

impl<STATE> Entry<EntryInvalid, STATE> {
    // This is only used in tests today, but I don't want to cfg test it.
    pub(crate) fn get_uuid(&self) -> Option<&Uuid> {
        self.attrs.get("uuid").and_then(|vs| vs.to_uuid_single())
    }

    /// Validate that this entry and it's attribute-value sets are conformant to the systems
    /// schema and the releant syntaxes.
    pub fn validate(
        self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let schema_classes = schema.get_classes();
        let schema_attributes = schema.get_attributes();

        let uuid: Uuid = self
            .attrs
            .get("uuid")
            .ok_or_else(|| SchemaError::MissingMustAttribute(vec!["uuid".to_string()]))
            .and_then(|vs| {
                vs.to_uuid_single()
                    .copied()
                    .ok_or_else(|| SchemaError::MissingMustAttribute(vec!["uuid".to_string()]))
            })?;

        // Build the new valid entry ...
        let ne = Entry {
            valid: EntryValid {
                uuid,
                cid: self.valid.cid,
            },
            state: self.state,
            attrs: self.attrs,
        };
        // Now validate it!
        trace!(?ne.attrs, "Entry::validate -> target");

        // We scope here to limit the time of borrow of ne.
        {
            // First, check we have class on the object ....
            if !ne.attribute_pres("class") {
                // lrequest_error!("Missing attribute class");
                return Err(SchemaError::NoClassFound);
            }

            // Do we have extensible?
            let extensible = ne.attribute_equality("class", &CLASS_EXTENSIBLE);

            let entry_classes = ne.get_ava_set("class").ok_or(SchemaError::NoClassFound)?;
            let mut invalid_classes = Vec::with_capacity(0);

            let mut classes: Vec<&SchemaClass> = Vec::with_capacity(entry_classes.len());

            match entry_classes.as_classname_iter() {
                Some(cls_iter) => cls_iter.for_each(|s| match schema_classes.get(s) {
                    Some(x) => classes.push(x),
                    None => invalid_classes.push(s.to_string()),
                }),
                None => invalid_classes.push("corrupt class attribute".to_string()),
            };

            if !invalid_classes.is_empty() {
                // lrequest_error!("Class on entry not found in schema?");
                return Err(SchemaError::InvalidClass(invalid_classes));
            };

            // What this is really doing is taking a set of classes, and building an
            // "overall" class that describes this exact object for checking. IE we
            // build a super must/may set from the small class must/may sets.

            //   for each class
            //      add systemmust/must and systemmay/may to their lists
            //      add anything from must also into may

            // Now from the set of valid classes make a list of must/may
            //
            // NOTE: We still need this on extensible, because we still need to satisfy
            // our other must conditions as well!
            let must: Result<Vec<&SchemaAttribute>, _> = classes
                .iter()
                // Join our class systemmmust + must into one iter
                .flat_map(|cls| cls.systemmust.iter().chain(cls.must.iter()))
                .map(|s| {
                    // This should NOT fail - if it does, it means our schema is
                    // in an invalid state!
                    schema_attributes.get(s).ok_or(SchemaError::Corrupted)
                })
                .collect();

            let must = must?;

            // Check that all must are inplace
            //   for each attr in must, check it's present on our ent
            let mut missing_must = Vec::with_capacity(0);
            must.iter().for_each(|attr| {
                let avas = ne.get_ava_set(&attr.name);
                if avas.is_none() {
                    missing_must.push(attr.name.to_string());
                }
            });

            if !missing_must.is_empty() {
                return Err(SchemaError::MissingMustAttribute(missing_must));
            }

            if extensible {
                // ladmin_warning!("Extensible Object In Use!");
                ne.attrs.iter().try_for_each(|(attr_name, avas)| {
                    match schema_attributes.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            if a_schema.phantom {
                                /*
                                lrequest_error!(
                                    "Attempt to add phantom attribute to extensible: {}",
                                    attr_name
                                );
                                */
                                Err(SchemaError::PhantomAttribute(attr_name.to_string()))
                            } else {
                                a_schema.validate_ava(attr_name.as_str(), avas)
                                // .map_err(|e| lrequest_error!("Failed to validate: {}", attr_name);)
                            }
                        }
                        None => {
                            // lrequest_error!("Invalid Attribute {} for extensible object", attr_name);
                            trace!(?attr_name, "extensible -> SchemaError::InvalidAttribute");
                            Err(SchemaError::InvalidAttribute(attr_name.to_string()))
                        }
                    }
                })?;
            } else {
                // Note - we do NOT need to check phantom attributes here because they are
                // not allowed to exist in the class, which means a phantom attribute can't
                // be in the may/must set, and would FAIL our normal checks anyway.

                // We clone string here, but it's so we can check all
                // the values in "may" ar here - so we can't avoid this look up. What we
                // could do though, is have &String based on the schemaattribute though?;
                let may: Result<Map<&AttrString, &SchemaAttribute>, _> = classes
                    .iter()
                    // Join our class systemmmust + must + systemmay + may into one.
                    .flat_map(|cls| {
                        cls.systemmust
                            .iter()
                            .chain(cls.must.iter())
                            .chain(cls.systemmay.iter())
                            .chain(cls.may.iter())
                    })
                    .map(|s| {
                        // This should NOT fail - if it does, it means our schema is
                        // in an invalid state!
                        Ok((s, schema_attributes.get(s).ok_or(SchemaError::Corrupted)?))
                    })
                    .collect();

                let may = may?;

                // TODO #70: Error needs to say what is missing
                // We need to return *all* missing attributes, not just the first error
                // we find. This will probably take a rewrite of the function definition
                // to return a result<_, vec<schemaerror>> and for the schema errors to take
                // information about what is invalid. It's pretty nontrivial.

                // Check that any other attributes are in may
                //   for each attr on the object, check it's in the may+must set
                ne.attrs.iter().try_for_each(|(attr_name, avas)| {
                    match may.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            a_schema.validate_ava(attr_name.as_str(), avas)
                            // .map_err(|e| lrequest_error!("Failed to validate: {}", attr_name);
                        }
                        None => {
                            // lrequest_error!("Invalid Attribute {} for may+must set", attr_name);
                            trace!(?attr_name, "SchemaError::InvalidAttribute");
                            Err(SchemaError::InvalidAttribute(attr_name.to_string()))
                        }
                    }
                })?;
            }
        } // unborrow ne.

        // Well, we got here, so okay!
        Ok(ne)
    }
}

impl<VALID, STATE> Clone for Entry<VALID, STATE>
where
    VALID: Clone,
    STATE: Clone,
{
    // Dirty modifiable state. Works on any other state to dirty them.
    fn clone(&self) -> Entry<VALID, STATE> {
        Entry {
            valid: self.valid.clone(),
            state: self.state.clone(),
            attrs: self.attrs.clone(),
        }
    }
}

/*
 * A series of unsafe transitions allowing entries to skip certain steps in
 * the process to facilitate eq/checks.
 */
impl Entry<EntryInvalid, EntryCommitted> {
    #[cfg(test)]
    pub unsafe fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        let uuid = self.get_uuid().expect("Invalid uuid").clone();
        Entry {
            valid: EntryValid {
                cid: self.valid.cid,
                uuid,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// Convert this entry into a recycled entry, that is "in the recycle bin".
    pub fn into_recycled(mut self) -> Self {
        self.add_ava("class", Value::new_class("recycled"));

        Entry {
            valid: self.valid.clone(),
            state: self.state,
            attrs: self.attrs,
        }
    }
}
// Both invalid states can be reached from "entry -> invalidate"

impl Entry<EntryInvalid, EntryNew> {
    #[cfg(test)]
    pub unsafe fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        let uuid = self.get_uuid().expect("Invalid uuid").clone();
        Entry {
            valid: EntryValid {
                cid: self.valid.cid,
                uuid,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    #[cfg(test)]
    pub unsafe fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self
            .get_uuid()
            .and_then(|u| Some(u.clone()))
            .unwrap_or_else(|| Uuid::new_v4());
        Entry {
            valid: EntrySealed { uuid },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /*
    #[cfg(test)]
    pub unsafe fn into_valid_normal(self) -> Entry<EntryNormalised, EntryNew> {
        Entry {
            valid: EntryNormalised,
            state: EntryNew,
            attrs: self
                .attrs
                .into_iter()
                .map(|(k, mut v)| {
                    v.sort_unstable();
                    (k, v)
                })
                .collect(),
        }
    }
    */

    #[cfg(test)]
    pub unsafe fn into_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        let uuid = self
            .get_uuid()
            .and_then(|u| Some(u.clone()))
            .unwrap_or_else(|| Uuid::new_v4());
        Entry {
            valid: EntryValid {
                cid: self.valid.cid,
                uuid,
            },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryInvalid, EntryCommitted> {
    #[cfg(test)]
    pub unsafe fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self
            .get_uuid()
            .and_then(|u| Some(u.clone()))
            .unwrap_or_else(|| Uuid::new_v4());
        Entry {
            valid: EntrySealed { uuid },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntrySealed, EntryNew> {
    #[cfg(test)]
    pub unsafe fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// Given this validated and sealed entry, process it with a `Backend` ID number so that it
    /// can be then serialised to the database.
    pub fn into_sealed_committed_id(self, id: u64) -> Entry<EntrySealed, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id },
            attrs: self.attrs,
        }
    }

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryNew>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }
}

type IdxDiff<'a> =
    Vec<Result<(&'a AttrString, &'a IndexType, String), (&'a AttrString, &'a IndexType, String)>>;

impl<VALID> Entry<VALID, EntryCommitted> {
    /// If this entry has ever been commited to disk, retrieve it's database id number.
    pub fn get_id(&self) -> u64 {
        self.state.id
    }
}

impl<STATE> Entry<EntrySealed, STATE> {
    pub fn into_init(self) -> Entry<EntryInit, STATE> {
        Entry {
            valid: EntryInit,
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntrySealed, EntryCommitted> {
    #[cfg(test)]
    pub unsafe fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        // NO-OP to satisfy macros.
        self
    }

    /// Insert a claim to this entry. This claim can NOT be persisted to disk, this is only
    /// used during a single Event session.
    pub fn insert_claim(&mut self, value: &str) {
        self.add_ava_int("claim", Value::new_iutf8(value));
    }

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

    /// Serialise this entry to it's Database format ready for storage.
    pub fn to_dbentry(&self) -> DbEntry {
        // In the future this will do extra work to process uuid
        // into "attributes" suitable for dbentry storage.

        // How will this work with replication?
        //
        // Alternately, we may have higher-level types that translate entry
        // into proper structures, and they themself emit/modify entries?

        DbEntry {
            ent: DbEntryVers::V1(DbEntryV1 {
                attrs: self
                    .attrs
                    .iter()
                    .map(|(k, vs)| {
                        let dbvs: Vec<_> = vs.to_db_valuev1_iter().collect();
                        (k.clone(), dbvs)
                    })
                    .collect(),
            }),
        }
    }

    #[inline]
    /// Given this entry, extract the set of strings that can uniquely identify this for authentication
    /// purposes. These strings are then indexed.
    fn get_name2uuid_cands(&self) -> Set<String> {
        // The cands are:
        // * spn
        // * name
        // * gidnumber

        let cands = ["spn", "name", "gidnumber"];
        cands
            .iter()
            .filter_map(|c| self.attrs.get(*c).map(|vs| vs.to_proto_string_clone_iter()))
            .flatten()
            .collect()
    }

    #[inline]
    /// Given this entry, extract it's primary security prinicple name, or if not present
    /// extract it's name, and if that's not present, extract it's uuid.
    pub(crate) fn get_uuid2spn(&self) -> Value {
        self.attrs
            .get("spn")
            .and_then(|vs| vs.to_value_single())
            .or_else(|| self.attrs.get("name").and_then(|vs| vs.to_value_single()))
            .unwrap_or_else(|| Value::new_uuidr(self.get_uuid()))
    }

    #[inline]
    /// Given this entry, determine it's relative distinguished named for LDAP compatability.
    pub(crate) fn get_uuid2rdn(&self) -> String {
        self.attrs
            .get("spn")
            .and_then(|vs| vs.to_proto_string_single().map(|v| format!("spn={}", v)))
            .or_else(|| {
                self.attrs
                    .get("name")
                    .and_then(|vs| vs.to_proto_string_single().map(|v| format!("name={}", v)))
            })
            .unwrap_or_else(|| format!("uuid={}", self.get_uuid().to_hyphenated_ref()))
    }

    #[inline]
    /// Determine if this entry is recycled or a tombstone, and map that to "None". This allows
    /// filter_map to effectively remove entries that should not be considered as "alive".
    pub(crate) fn mask_recycled_ts(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else lways Some(self).
        match self.attrs.get("class") {
            Some(cls) => {
                if cls.contains(&PVCLASS_TOMBSTONE as &PartialValue)
                    || cls.contains(&PVCLASS_RECYCLED as &PartialValue)
                {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }

    /// Generate the required values for a name2uuid index. IE this is
    /// ALL possible names this entry COULD be known uniquely by!
    pub(crate) fn idx_name2uuid_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> (
        // Add
        Option<Set<String>>,
        // Remove
        Option<Set<String>>,
    ) {
        // needs to return gid for posix conversion
        match (pre, post) {
            (None, None) => {
                // No action required
                (None, None)
            }
            (None, Some(b)) => {
                // We are adding this entry (or restoring it),
                // so we need to add the values.
                (Some(b.get_name2uuid_cands()), None)
            }
            (Some(a), None) => {
                // Removing the entry, remove all values.
                (None, Some(a.get_name2uuid_cands()))
            }
            (Some(a), Some(b)) => {
                let pre_set = a.get_name2uuid_cands();
                let post_set = b.get_name2uuid_cands();

                // what is in post, but not pre (added)
                let add_set: Set<_> = post_set.difference(&pre_set).cloned().collect();
                // what is in pre, but not post (removed)
                let rem_set: Set<_> = pre_set.difference(&post_set).cloned().collect();
                (Some(add_set), Some(rem_set))
            }
        }
    }

    /// Generate a differential between a previous and current entry state, and what changes this
    /// means for the current set of spn's for this uuid.
    pub(crate) fn idx_uuid2spn_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> Option<Result<Value, ()>> {
        match (pre, post) {
            (None, None) => {
                // no action
                None
            }
            (None, Some(b)) => {
                // add
                Some(Ok(b.get_uuid2spn()))
            }
            (Some(_a), None) => {
                // remove
                Some(Err(()))
            }
            (Some(a), Some(b)) => {
                let ia = a.get_uuid2spn();
                let ib = b.get_uuid2spn();
                if ia != ib {
                    // Add (acts as replace)
                    Some(Ok(ib))
                } else {
                    // no action
                    None
                }
            }
        }
    }

    /// Generate a differential between a previous and current entry state, and what changes this
    /// means for the current set of LDAP relative distinguished names.
    pub(crate) fn idx_uuid2rdn_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> Option<Result<String, ()>> {
        match (pre, post) {
            (None, None) => {
                // no action
                None
            }
            (None, Some(b)) => {
                // add
                Some(Ok(b.get_uuid2rdn()))
            }
            (Some(_a), None) => {
                // remove
                Some(Err(()))
            }
            (Some(a), Some(b)) => {
                let ia = a.get_uuid2rdn();
                let ib = b.get_uuid2rdn();
                if ia != ib {
                    // Add (acts as replace)
                    Some(Ok(ib))
                } else {
                    // no action
                    None
                }
            }
        }
    }

    /// Given the previous and current state of this entry, determine the indexing differential
    /// that needs to be applied. i.e. what indexes must be created, modified and removed.
    pub(crate) fn idx_diff<'a>(
        idxmeta: &'a HashMap<IdxKey, IdxSlope>,
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> IdxDiff<'a> {
        // We yield a list of Result, where Ok() means "add",
        // and Err() means "remove".
        // the value inside the result, is a tuple of attr, itype, idx_key

        match (pre, post) {
            (None, None) => {
                // if both are none, yield empty list.
                Vec::new()
            }
            (Some(pre_e), None) => {
                // If we are none (?), yield our pre-state as removals.
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        match pre_e.get_ava_set(ikey.attr.as_str()) {
                            None => Vec::new(),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // We generate these keys out of the valueset now.
                                        vs.generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, &ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Err((&ikey.attr, &ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                changes
                            }
                        }
                    })
                    .collect()
            }
            (None, Some(post_e)) => {
                // If the pre-state is none, yield our additions.
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        match post_e.get_ava_set(ikey.attr.as_str()) {
                            None => Vec::new(),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => vs
                                        .generate_idx_eq_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, &ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Presence => {
                                        vec![Ok((&ikey.attr, &ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                // For each value
                                //
                                changes
                            }
                        }
                    })
                    .collect()
            }
            (Some(pre_e), Some(post_e)) => {
                assert!(pre_e.state.id == post_e.state.id);
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        match (
                            pre_e.get_ava_set(ikey.attr.as_str()),
                            post_e.get_ava_set(ikey.attr.as_str()),
                        ) {
                            (None, None) => {
                                // Neither have it, do nothing.
                                Vec::new()
                            }
                            (Some(pre_vs), None) => {
                                // It existed before, but not anymore
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // Turn each idx_key to the tuple of
                                        // changes.
                                        pre_vs
                                            .generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, &ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Err((&ikey.attr, &ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                changes
                            }
                            (None, Some(post_vs)) => {
                                // It was added now.
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // Turn each idx_key to the tuple of
                                        // changes.
                                        post_vs
                                            .generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Ok((&ikey.attr, &ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Ok((&ikey.attr, &ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                changes
                            }
                            (Some(pre_vs), Some(post_vs)) => {
                                // it exists in both, we need to work out the differents within the attr.
                                let removed_vs = pre_vs.idx_eq_key_difference(&post_vs);
                                let added_vs = post_vs.idx_eq_key_difference(&pre_vs);

                                let mut diff = Vec::with_capacity(
                                    removed_vs.as_ref().map(|v| v.len()).unwrap_or(0)
                                        + added_vs.as_ref().map(|v| v.len()).unwrap_or(0),
                                );

                                match ikey.itype {
                                    IndexType::Equality => {
                                        if let Some(removed_vs) = removed_vs {
                                            removed_vs
                                                .generate_idx_eq_keys()
                                                .into_iter()
                                                .map(|idx_key| {
                                                    Err((&ikey.attr, &ikey.itype, idx_key))
                                                })
                                                .for_each(|v| diff.push(v));
                                        }
                                        if let Some(added_vs) = added_vs {
                                            added_vs
                                                .generate_idx_eq_keys()
                                                .into_iter()
                                                .map(|idx_key| {
                                                    Ok((&ikey.attr, &ikey.itype, idx_key))
                                                })
                                                .for_each(|v| diff.push(v));
                                        }
                                    }
                                    IndexType::Presence => {
                                        // No action - we still are "present", so nothing to do!
                                    }
                                    IndexType::SubString => {}
                                };
                                // Return the diff
                                diff
                            }
                        }
                    })
                    .collect()
                // End diff of the entries
            }
        }
    }

    // ! TRACING INTEGRATED
    pub fn from_dbentry(db_e: DbEntry, id: u64) -> Option<Self> {
        // Convert attrs from db format to value
        let r_attrs: Result<Map<AttrString, ValueSet>, ()> = match db_e.ent {
            DbEntryVers::V1(v1) => v1
                .attrs
                .into_iter()
                .map(|(k, vs)| {
                    let vv: Result<Option<ValueSet>, ()> =
                        vs.into_iter().map(Value::from_db_valuev1).collect();
                    match vv {
                        Ok(Some(vv)) => Ok((k, vv)),
                        _ => {
                            admin_error!(value = ?k, "from_dbentry failed");
                            Err(())
                        }
                    }
                })
                .collect(),
        };

        let attrs = r_attrs.ok()?;

        let uuid = attrs
            .get("uuid")
            .and_then(|vs| vs.to_uuid_single().copied())?;

        Some(Entry {
            valid: EntrySealed { uuid },
            state: EntryCommitted { id },
            attrs,
        })
    }

    /// # Safety
    /// This function bypasses the access control validation logic and should NOT
    /// be used without special care and attention to ensure that no private data
    /// is leaked incorrectly to clients. Generally this is ONLY used inside of
    /// the access control processing functions which correctly applies the reduction
    /// steps.
    pub unsafe fn into_reduced(self) -> Entry<EntryReduced, EntryCommitted> {
        Entry {
            valid: EntryReduced {
                uuid: self.valid.uuid,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    /// Given a set of attributes that are allowed to be seen on this entry, process and remove
    /// all other values that are NOT allowed in this query.
    pub fn reduce_attributes(
        self,
        allowed_attrs: &BTreeSet<&str>,
    ) -> Entry<EntryReduced, EntryCommitted> {
        // Remove all attrs from our tree that are NOT in the allowed set.

        let Entry {
            valid: s_valid,
            state: s_state,
            attrs: s_attrs,
        } = self;

        let f_attrs: Map<_, _> = s_attrs
            .into_iter()
            .filter_map(|(k, v)| {
                if allowed_attrs.contains(k.as_str()) {
                    Some((k, v))
                } else {
                    None
                }
            })
            .collect();

        Entry {
            valid: EntryReduced { uuid: s_valid.uuid },
            state: s_state,
            attrs: f_attrs,
        }
    }

    /// Convert this recycled entry, into a tombstone ready for reaping.
    pub fn to_tombstone(&self, cid: Cid) -> Entry<EntryInvalid, EntryCommitted> {
        // Duplicate this to a tombstone entry
        let class_ava =
            unsafe { valueset![Value::new_class("object"), Value::new_class("tombstone")] };
        let last_mod_ava = ValueSet::new(Value::new_cid(cid.clone()));

        let mut attrs_new: Map<AttrString, ValueSet> = Map::new();

        attrs_new.insert(
            AttrString::from("uuid"),
            ValueSet::new(Value::new_uuidr(&self.get_uuid())),
        );
        attrs_new.insert(AttrString::from("class"), class_ava);
        attrs_new.insert(AttrString::from("last_modified_cid"), last_mod_ava);

        Entry {
            valid: EntryInvalid { cid },
            state: self.state.clone(),
            attrs: attrs_new,
        }
    }

    /// Given a current transaction change identifier, mark this entry as valid and committed.
    pub fn into_valid(self, cid: Cid) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self.valid.uuid,
                cid,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl<STATE> Entry<EntryValid, STATE> {
    // Returns the entry in the latest DbEntry format we are aware of.
    pub fn invalidate(self) -> Entry<EntryInvalid, STATE> {
        Entry {
            valid: EntryInvalid {
                cid: self.valid.cid,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn seal(self) -> Entry<EntrySealed, STATE> {
        Entry {
            valid: EntrySealed {
                uuid: self.valid.uuid,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn get_uuid(&self) -> &Uuid {
        &self.valid.uuid
    }
}

impl<STATE> Entry<EntrySealed, STATE> {
    // Returns the entry in the latest DbEntry format we are aware of.
    pub fn invalidate(mut self, cid: Cid) -> Entry<EntryInvalid, STATE> {
        /* Setup our last changed time. */
        self.set_last_changed(cid.clone());

        Entry {
            valid: EntryInvalid { cid },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn get_uuid(&self) -> &Uuid {
        &self.valid.uuid
    }

    #[cfg(test)]
    pub unsafe fn into_invalid(mut self) -> Entry<EntryInvalid, STATE> {
        self.set_last_changed(Cid::new_zero());
        Entry {
            valid: EntryInvalid {
                cid: Cid::new_zero(),
            },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryReduced, EntryCommitted> {
    pub fn get_uuid(&self) -> &Uuid {
        &self.valid.uuid
    }

    /// Transform this reduced entry into a JSON protocol form that can be sent to clients.
    // ! TRACING INTEGRATED
    pub fn to_pe(
        &self,
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Result<ProtoEntry, OperationError> {
        // Turn values -> Strings.
        let attrs: Result<_, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| {
                qs.resolve_valueset(audit, vs)
                    .map(|pvs| (k.to_string(), pvs))
            })
            .collect();
        Ok(ProtoEntry { attrs: attrs? })
    }

    /// Transform this reduced entry into an LDAP form that can be sent to clients.
    pub fn to_ldap(
        &self,
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        basedn: &str,
        // Did the client request all attributes?
        all_attrs: bool,
        // Did the ldap client request any sperific attribute names? If so,
        // we need to remap everything to match.
        l_attrs: &[String],
    ) -> Result<LdapSearchResultEntry, OperationError> {
        let rdn = qs.uuid_to_rdn(audit, self.get_uuid())?;

        let dn = format!("{},{}", rdn, basedn);

        // Everything in our attrs set is "what was requested". So we can transform that now
        // so they are all in "ldap forms" which makes our next stage a bit easier.

        // Stage 1 - transform our results to a map of kani attr -> ldap value.
        let attr_map: Result<Map<&str, Vec<String>>, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| {
                qs.resolve_valueset_ldap(audit, vs, basedn)
                    .map(|pvs| (k.as_str(), pvs))
            })
            .collect();

        let attr_map = attr_map?;
        // Stage 2 - transform and get all our attr - names out that we need to return.
        //                  ldap a, kani a
        let attr_names: Vec<(&str, &str)> = if all_attrs {
            // Join the set of attr keys, and our requested attrs.
            self.attrs
                .keys()
                .map(|k| (k.as_str(), k.as_str()))
                .chain(
                    l_attrs
                        .iter()
                        .map(|k| (k.as_str(), ldap_vattr_map(k.as_str()))),
                )
                .collect()
        } else {
            // Just get the requested ones.
            l_attrs
                .iter()
                .map(|k| (k.as_str(), ldap_vattr_map(k.as_str())))
                .collect()
        };

        // Stage 3 - given our map, generate the final result.
        let attributes: Vec<_> = attr_names
            .into_iter()
            .filter_map(|(ldap_a, kani_a)| {
                // In some special cases, we may need to transform or rewrite the values.
                match ldap_a {
                    "entrydn" => Some(LdapPartialAttribute {
                        atype: "entrydn".to_string(),
                        vals: vec![dn.clone()],
                    }),
                    _ => attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                        atype: ldap_a.to_string(),
                        vals: pvs.clone(),
                    }),
                }
            })
            .collect();

        Ok(LdapSearchResultEntry { dn, attributes })
    }
}

// impl<STATE> Entry<EntryValid, STATE> {
impl<VALID, STATE> Entry<VALID, STATE> {
    /// This internally adds an AVA to the entry.
    fn add_ava_int(&mut self, attr: &str, value: Value) {
        // How do we make this turn into an ok / err?

        if let Some(vs) = self.attrs.get_mut(attr) {
            let r = vs.insert_checked(value);
            debug_assert!(r.is_ok());
        } else {
            self.attrs
                .insert(AttrString::from(attr), ValueSet::new(value));
        }
        // Doesn't matter if it already exists, equality will replace.
    }

    /// Overwrite the current set of values for an attribute, with this new set.
    // pub fn set_ava_int(&mut self, attr: &str, values: Set<Value>) {
    pub fn set_ava_int<T>(&mut self, attr: &str, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        // Overwrite the existing value, build a tree from the list.
        let values: Option<ValueSet> = iter.into_iter().collect();
        if let Some(vs) = values {
            let _ = self.attrs.insert(AttrString::from(attr), vs);
        } else {
            self.attrs.remove(attr);
        }
    }

    /// Update the last_changed flag of this entry to the given change identifier.
    fn set_last_changed(&mut self, cid: Cid) {
        let cv = valueset![Value::new_cid(cid)];
        let _ = self.attrs.insert(AttrString::from("last_modified_cid"), cv);
    }

    #[inline(always)]
    /// Get an iterator over the current set of attribute names that this entry contains.
    pub fn get_ava_names(&self) -> impl Iterator<Item = &str> {
        // Get the set of all attribute names in the entry
        self.attrs.keys().map(|a| a.as_str())
    }

    /*
    #[inline(always)]
    /// Get an iterator over the current set of values for an attribute name.
    pub fn get_ava(&self, attr: &str) -> Option<impl Iterator<Item = &Value>> {
        self.attrs.get(attr).map(|vs| vs.iter())
    }
    */

    #[inline(always)]
    /// Return a reference to the current set of values that are associated to this attribute.
    pub fn get_ava_set(&self, attr: &str) -> Option<&ValueSet> {
        self.attrs.get(attr)
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of values transformed into a `&str`.
    pub fn get_ava_as_str(&self, attr: &str) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_str_iter())
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of values transformed into a `&Uuid`.
    pub fn get_ava_as_refuuid(&self, attr: &str) -> Option<impl Iterator<Item = &Uuid>> {
        // If any value is NOT a reference, it's filtered out.
        self.get_ava_set(attr).and_then(|vs| vs.as_ref_uuid_iter())
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of ssh key values transformed into a `&str`.
    pub fn get_ava_iter_sshpubkeys(&self, attr: &str) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_sshpubkey_str_iter())
    }

    // These are special types to allow returning typed values from
    // an entry, if we "know" what we expect to receive.

    /// This returns an array of IndexTypes, when the type is an Optional
    /// multivalue in schema - IE this will *not* fail if the attribute is
    /// empty, yielding and empty array instead.
    ///
    /// However, the converstion to IndexType is fallaible, so in case of a failure
    /// to convert, an Err is returned.
    #[inline(always)]
    pub(crate) fn get_ava_opt_index(&self, attr: &str) -> Option<Vec<IndexType>> {
        if let Some(vs) = self.get_ava_set(attr) {
            vs.as_indextype_set().map(|i| i.cloned().collect())
        } else {
            // Empty, but consider as valid.
            Some(vec![])
        }
    }

    /// Return a single value of this attributes name, or `None` if it is NOT present, or
    /// there are multiple values present (ambiguous).
    #[inline(always)]
    pub fn get_ava_single(&self, attr: &str) -> Option<Value> {
        self.attrs.get(attr).and_then(|vs| vs.to_value_single())
    }

    #[inline(always)]
    /// Return a single bool, if valid to transform this value into a boolean.
    pub fn get_ava_single_bool(&self, attr: &str) -> Option<bool> {
        self.attrs.get(attr).and_then(|vs| vs.to_bool_single())
    }

    #[inline(always)]
    /// Return a single uint32, if valid to transform this value.
    pub fn get_ava_single_uint32(&self, attr: &str) -> Option<u32> {
        self.attrs.get(attr).and_then(|vs| vs.to_uint32_single())
    }

    #[inline(always)]
    /// Return a single syntax type, if valid to transform this value.
    pub fn get_ava_single_syntax(&self, attr: &str) -> Option<&SyntaxType> {
        self.attrs
            .get(attr)
            .and_then(|vs| vs.to_syntaxtype_single())
    }

    #[inline(always)]
    /// Return a single credential, if valid to transform this value.
    pub fn get_ava_single_credential(&self, attr: &str) -> Option<&Credential> {
        self.attrs
            .get(attr)
            .and_then(|vs| vs.to_credential_single())
    }

    #[inline(always)]
    /// Return a single secret value, if valid to transform this value.
    pub fn get_ava_single_secret(&self, attr: &str) -> Option<&str> {
        self.attrs.get(attr).and_then(|vs| vs.to_secret_single())
    }

    #[inline(always)]
    /// Return a single datetime, if valid to transform this value.
    pub fn get_ava_single_datetime(&self, attr: &str) -> Option<OffsetDateTime> {
        self.attrs.get(attr).and_then(|vs| vs.to_datetime_single())
    }

    #[inline(always)]
    /// Return a single `&str`, if valid to transform this value.
    pub fn get_ava_single_str(&self, attr: &str) -> Option<&str> {
        self.attrs.get(attr).and_then(|vs| vs.to_str_single())
    }

    #[inline(always)]
    /// Return a single `&Url`, if valid to transform this value.
    pub fn get_ava_single_url(&self, attr: &str) -> Option<&Url> {
        self.attrs.get(attr).and_then(|vs| vs.to_url_single())
    }

    pub fn get_ava_single_uuid(&self, attr: &str) -> Option<&Uuid> {
        self.attrs.get(attr).and_then(|vs| vs.to_uuid_single())
    }

    #[inline(always)]
    /// Return a single protocol filter, if valid to transform this value.
    pub fn get_ava_single_protofilter(&self, attr: &str) -> Option<&ProtoFilter> {
        self.attrs
            .get(attr)
            .and_then(|vs| vs.to_json_filter_single())
    }

    #[inline(always)]
    /// Return a single security principle name, if valid to transform this value.
    pub(crate) fn generate_spn(&self, domain_name: &str) -> Option<Value> {
        self.get_ava_single_str("name")
            .map(|name| Value::new_spn_str(name, domain_name))
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present on this entry.
    pub fn attribute_pres(&self, attr: &str) -> bool {
        self.attrs.contains_key(attr)
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of it's values contains
    /// the an exact match of this partial value.
    pub fn attribute_equality(&self, attr: &str, value: &PartialValue) -> bool {
        // we assume based on schema normalisation on the way in
        // that the equality here of the raw values MUST be correct.
        // We also normalise filters, to ensure that their values are
        // syntax valid and will correctly match here with our indexes.
        match self.attrs.get(attr) {
            Some(v_list) => v_list.contains(value),
            None => false,
        }
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of it's values contains
    /// the following substring, if possible to perform the substring comparison.
    pub fn attribute_substring(&self, attr: &str, subvalue: &PartialValue) -> bool {
        self.attrs
            .get(attr)
            .map(|vset| vset.substring(subvalue))
            .unwrap_or(false)
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of it's values is less than
    /// the following partial value
    pub fn attribute_lessthan(&self, attr: &str, subvalue: &PartialValue) -> bool {
        self.attrs
            .get(attr)
            .map(|vset| vset.lessthan(subvalue))
            .unwrap_or(false)
    }

    // Since EntryValid/Invalid is just about class adherenece, not Value correctness, we
    // can now apply filters to invalid entries - why? Because even if they aren't class
    // valid, we still have strict typing checks between the filter -> entry to guarantee
    // they should be functional. We'll never match something that isn't syntactially valid.
    #[inline(always)]
    /// Test if the following filter applies to and matches this entry.
    pub fn entry_match_no_index(&self, filter: &Filter<FilterValidResolved>) -> bool {
        self.entry_match_no_index_inner(filter.to_inner())
    }

    // This is private, but exists on all types, so that valid and normal can then
    // expose the simpler wrapper for entry_match_no_index only.
    // Assert if this filter matches the entry (no index)
    fn entry_match_no_index_inner(&self, filter: &FilterResolved) -> bool {
        // Go through the filter components and check them in the entry.
        // This is recursive!!!!
        match filter {
            FilterResolved::Eq(attr, value, _) => self.attribute_equality(attr.as_str(), value),
            FilterResolved::Sub(attr, subvalue, _) => {
                self.attribute_substring(attr.as_str(), subvalue)
            }
            FilterResolved::Pres(attr, _) => {
                // Given attr, is is present in the entry?
                self.attribute_pres(attr.as_str())
            }
            FilterResolved::LessThan(attr, subvalue, _) => {
                self.attribute_lessthan(attr.as_str(), subvalue)
            }
            // Check with ftweedal about or filter zero len correctness.
            FilterResolved::Or(l, _) => l.iter().any(|f| self.entry_match_no_index_inner(f)),
            // Check with ftweedal about and filter zero len correctness.
            FilterResolved::And(l, _) => l.iter().all(|f| self.entry_match_no_index_inner(f)),
            FilterResolved::Inclusion(_, _) => {
                // An inclusion doesn't make sense on an entry in isolation!
                // Inclusions are part of exists queries, on search they mean
                // nothing!
                false
            }
            FilterResolved::AndNot(f, _) => !self.entry_match_no_index_inner(f),
        }
    }

    /// Given this entry, generate a filter containing the requested attributes strings as
    /// equality components.
    pub fn filter_from_attrs(&self, attrs: &[AttrString]) -> Option<Filter<FilterInvalid>> {
        // Because we are a valid entry, a filter we create still may not
        // be valid because the internal server entry templates are still
        // created by humans! Plus double checking something already valid
        // is not bad ...
        //
        // Generate a filter from the attributes requested and defined.
        // Basically, this is a series of nested and's (which will be
        // optimised down later: but if someone wants to solve flatten() ...)

        // Take name: (a, b), name: (c, d) -> (name, a), (name, b), (name, c), (name, d)

        let mut pairs: Vec<(&str, PartialValue)> = Vec::new();

        for attr in attrs {
            match self.attrs.get(attr) {
                Some(values) => values
                    .to_partialvalue_iter()
                    .for_each(|pv| pairs.push((attr, pv))),
                None => return None,
            }
        }

        Some(filter_all!(f_and(
            pairs
                .into_iter()
                .map(|(attr, pv)| {
                    // We use FC directly here instead of f_eq to avoid an excess clone.
                    FC::Eq(attr, pv)
                })
                .collect()
        )))
    }

    /// Given this entry, generate a modification list that would "assert"
    /// another entry is in the same/identical attribute state.
    pub fn gen_modlist_assert(
        &self,
        schema: &dyn SchemaTransaction,
    ) -> Result<ModifyList<ModifyInvalid>, SchemaError> {
        // Create a modlist from this entry. We make this assuming we want the entry
        // to have this one as a subset of values. This means if we have single
        // values, we'll replace, if they are multivalue, we present them.
        let mut mods = ModifyList::new();

        for (k, vs) in self.attrs.iter() {
            // WHY?! We skip uuid here because it is INVALID for a UUID
            // to be in a modlist, and the base.rs plugin will fail if it
            // is there. This actually doesn't matter, because to apply the
            // modlist in these situations we already know the entry MUST
            // exist with that UUID, we only need to conform it's other
            // attributes into the same state.
            //
            // In the future, if we make uuid a real entry type, then this
            // check can "go away" because uuid will never exist as an ava.
            //
            // NOTE: Remove this check when uuid becomes a real attribute.
            // UUID is now a real attribute, but it also has an ava for db_entry
            // conversion - so what do? If we remove it here, we could have CSN issue with
            // repl on uuid conflict, but it probably shouldn't be an ava either ...
            // as a result, I think we need to keep this continue line to not cause issues.
            if k == "uuid" {
                continue;
            }
            // Get the schema attribute type out.
            match schema.is_multivalue(k) {
                Ok(r) => {
                    if !r {
                        // As this is single value, purge then present to maintain this
                        // invariant
                        mods.push_mod(Modify::Purged(k.clone()));
                    }
                }
                // A schema error happened, fail the whole operation.
                Err(e) => return Err(e),
            }
            for v in vs.to_value_iter() {
                mods.push_mod(Modify::Present(k.clone(), v.clone()));
            }
        }

        Ok(mods)
    }
}

impl<STATE> Entry<EntryInvalid, STATE>
where
    STATE: Clone,
{
    // This should always work? It's only on validate that we'll build
    // a list of syntax violations ...
    // If this already exists, we silently drop the event? Is that an
    // acceptable interface?
    //
    // TODO: This should take Value not &Value, would save a lot of clones
    // around the codebase.
    pub fn add_ava(&mut self, attr: &str, value: Value) {
        self.add_ava_int(attr, value)
    }

    /// Merge an existing value set into this attributes value set. If they are not
    /// the same type, an error is returned. If no attribute exists, then this valueset is
    /// cloned "as is".
    pub fn merge_ava(&mut self, attr: &str, valueset: &ValueSet) -> Result<(), OperationError> {
        if let Some(vs) = self.attrs.get_mut(attr) {
            vs.merge(valueset)
        } else {
            self.attrs.insert(AttrString::from(attr), valueset.clone());
            Ok(())
        }
    }

    /// Remove an attribute-value pair from this entry.
    fn remove_ava(&mut self, attr: &str, value: &PartialValue) {
        // It would be great to remove these extra allocations, but they
        // really don't cost much :(
        self.attrs.entry(AttrString::from(attr)).and_modify(|v| {
            // Here we need to actually do a check/binary search ...
            v.remove(value);
        });
    }

    // Need something that can remove by difference?
    pub(crate) fn remove_avas(&mut self, attr: &str, values: &BTreeSet<PartialValue>) {
        if let Some(vs) = self.attrs.get_mut(attr) {
            values.iter().for_each(|k| {
                vs.remove(k);
            })
        }
    }

    /// Remove all values of this attribute from the entry.
    pub fn purge_ava(&mut self, attr: &str) {
        self.attrs.remove(attr);
    }

    /// Remove all values of this attribute from the entry, and return their content.
    pub fn pop_ava(&mut self, attr: &str) -> Option<ValueSet> {
        self.attrs.remove(attr)
    }

    /// Replace the content of this attribute with a new value set.
    // pub fn set_ava(&mut self, attr: &str, values: Set<Value>) {
    pub fn set_ava<T>(&mut self, attr: &str, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        self.set_ava_int(attr, iter)
    }

    pub fn get_ava_mut(&mut self, attr: &str) -> Option<&mut ValueSet> {
        self.attrs.get_mut(attr)
    }

    /*
    pub fn avas_mut(&mut self) -> EntryAvasMut {
        EntryAvasMut {
            inner: self.attrs.iter_mut(),
        }
    }
    */

    /// Apply the content of this modlist to this entry, enforcing the expressed state.
    pub fn apply_modlist(&mut self, modlist: &ModifyList<ModifyValid>) {
        // -> Result<Entry<EntryInvalid, STATE>, OperationError> {
        // Apply a modlist, generating a new entry that conforms to the changes.
        // This is effectively clone-and-transform

        // mutate
        for modify in modlist {
            match modify {
                Modify::Present(a, v) => self.add_ava(a.as_str(), v.clone()),
                Modify::Removed(a, v) => self.remove_ava(a.as_str(), v),
                Modify::Purged(a) => self.purge_ava(a.as_str()),
            }
        }
    }
}

impl<VALID, STATE> PartialEq for Entry<VALID, STATE> {
    fn eq(&self, rhs: &Entry<VALID, STATE>) -> bool {
        // This may look naive - but it is correct. This is because
        // all items that end up in an item MUST have passed through
        // schema validation and normalisation so we can assume that
        // all rules were applied correctly. Thus we can just simply
        // do a char-compare like this.
        //
        // Of course, this is only true on the "Valid" types ... the others
        // are not guaranteed to support this ... but more likely that will
        // just end in eager false-results. We'll never say something is true
        // that should NOT be.
        compare_attrs(&self.attrs, &rhs.attrs)
    }
}

impl From<&SchemaAttribute> for Entry<EntryInit, EntryNew> {
    fn from(s: &SchemaAttribute) -> Self {
        // Convert an Attribute to an entry ... make it good!
        let uuid_v = ValueSet::new(Value::new_uuidr(&s.uuid));
        let name_v = ValueSet::new(Value::new_iutf8(s.name.as_str()));
        let desc_v = ValueSet::new(Value::new_utf8(s.description.clone()));

        let multivalue_v = ValueSet::new(Value::from(s.multivalue));
        let unique_v = ValueSet::new(Value::from(s.unique));

        let index_v: Option<ValueSet> = s.index.iter().cloned().map(Value::from).collect();

        let syntax_v = ValueSet::new(Value::from(s.syntax.clone()));

        // Build the Map of the attributes relevant
        // let mut attrs: Map<AttrString, Set<Value>> = Map::with_capacity(8);
        let mut attrs: Map<AttrString, ValueSet> = Map::new();
        attrs.insert(AttrString::from("attributename"), name_v);
        attrs.insert(AttrString::from("description"), desc_v);
        attrs.insert(AttrString::from("uuid"), uuid_v);
        attrs.insert(AttrString::from("multivalue"), multivalue_v);
        attrs.insert(AttrString::from("unique"), unique_v);
        if let Some(vs) = index_v {
            attrs.insert(AttrString::from("index"), vs);
        }
        attrs.insert(AttrString::from("syntax"), syntax_v);
        attrs.insert(AttrString::from("class"), unsafe {
            valueset![
                Value::new_class("object"),
                Value::new_class("system"),
                Value::new_class("attributetype")
            ]
        });

        // Insert stuff.

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

impl From<&SchemaClass> for Entry<EntryInit, EntryNew> {
    fn from(s: &SchemaClass) -> Self {
        let uuid_v = ValueSet::new(Value::new_uuidr(&s.uuid));
        let name_v = ValueSet::new(Value::new_iutf8(s.name.as_str()));
        let desc_v = ValueSet::new(Value::new_utf8(s.description.clone()));

        // let mut attrs: Map<AttrString, Set<Value>> = Map::with_capacity(8);
        let mut attrs: Map<AttrString, ValueSet> = Map::new();
        attrs.insert(AttrString::from("classname"), name_v);
        attrs.insert(AttrString::from("description"), desc_v);
        attrs.insert(AttrString::from("uuid"), uuid_v);
        attrs.insert(AttrString::from("class"), unsafe {
            valueset![
                Value::new_class("object"),
                Value::new_class("system"),
                Value::new_class("classtype")
            ]
        });

        let vs_systemmay: Option<ValueSet> = s
            .systemmay
            .iter()
            .map(|sm| Value::new_attr(sm.as_str()))
            .collect();
        if let Some(vs) = vs_systemmay {
            attrs.insert(AttrString::from("systemmay"), vs);
        }

        let vs_systemmust: Option<ValueSet> = s
            .systemmust
            .iter()
            .map(|sm| Value::new_attr(sm.as_str()))
            .collect();
        if let Some(vs) = vs_systemmust {
            attrs.insert(AttrString::from("systemmust"), vs);
        }

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::be::{IdxKey, IdxSlope};
    use crate::entry::{Entry, EntryInit, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::value::{IndexType, PartialValue, Value};
    use hashbrown::HashMap;
    use smartstring::alias::String as AttrString;
    use std::collections::BTreeSet as Set;

    #[test]
    fn test_entry_basic() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava("userid", Value::from("william"));
    }

    #[test]
    fn test_entry_dup_value() {
        // Schema doesn't matter here because we are duplicating a value
        // it should fail!

        // We still probably need schema here anyway to validate what we
        // are adding ... Or do we validate after the changes are made in
        // total?
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava("userid", Value::from("william"));
        e.add_ava("userid", Value::from("william"));

        let values = e.get_ava_set("userid").expect("Failed to get ava");
        // Should only be one value!
        assert_eq!(values.len(), 1)
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava("userid", Value::from("william"));

        assert!(e.attribute_pres("userid"));
        assert!(!e.attribute_pres("name"));
    }

    #[test]
    fn test_entry_equality() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava("userid", Value::from("william"));

        assert!(e.attribute_equality("userid", &PartialValue::new_utf8s("william")));
        assert!(!e.attribute_equality("userid", &PartialValue::new_utf8s("test")));
        assert!(!e.attribute_equality("nonexist", &PartialValue::new_utf8s("william")));
        // Also test non-matching attr syntax
        assert!(!e.attribute_equality("userid", &PartialValue::new_class("william")));
    }

    #[test]
    fn test_entry_substring() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava("userid", Value::from("william"));

        assert!(e.attribute_substring("userid", &PartialValue::new_utf8s("william")));
        assert!(e.attribute_substring("userid", &PartialValue::new_utf8s("will")));
        assert!(e.attribute_substring("userid", &PartialValue::new_utf8s("liam")));
        assert!(e.attribute_substring("userid", &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_substring("userid", &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_substring("userid", &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_substring("userid", &PartialValue::new_utf8s("wl")));
    }

    #[test]
    fn test_entry_lessthan() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();

        let pv2 = PartialValue::new_uint32(2);
        let pv8 = PartialValue::new_uint32(8);
        let pv10 = PartialValue::new_uint32(10);
        let pv15 = PartialValue::new_uint32(15);

        e1.add_ava("a", Value::new_uint32(10));

        assert!(e1.attribute_lessthan("a", &pv2) == false);
        assert!(e1.attribute_lessthan("a", &pv8) == false);
        assert!(e1.attribute_lessthan("a", &pv10) == false);
        assert!(e1.attribute_lessthan("a", &pv15) == true);

        e1.add_ava("a", Value::new_uint32(8));

        assert!(e1.attribute_lessthan("a", &pv2) == false);
        assert!(e1.attribute_lessthan("a", &pv8) == false);
        assert!(e1.attribute_lessthan("a", &pv10) == true);
        assert!(e1.attribute_lessthan("a", &pv15) == true);
    }

    #[test]
    fn test_entry_apply_modlist() {
        // Test application of changes to an entry.
        let mut e: Entry<EntryInvalid, EntryNew> = unsafe { Entry::new().into_invalid_new() };

        e.add_ava("userid", Value::from("william"));

        let present_single_mods = unsafe {
            ModifyList::new_valid_list(vec![Modify::Present(
                AttrString::from("attr"),
                Value::new_iutf8("value"),
            )])
        };

        e.apply_modlist(&present_single_mods);

        // Assert the changes are there
        assert!(e.attribute_equality("userid", &PartialValue::new_utf8s("william")));
        assert!(e.attribute_equality("attr", &PartialValue::new_iutf8("value")));

        // Assert present for multivalue
        let present_multivalue_mods = unsafe {
            ModifyList::new_valid_list(vec![
                Modify::Present(AttrString::from("class"), Value::new_iutf8("test")),
                Modify::Present(AttrString::from("class"), Value::new_iutf8("multi_test")),
            ])
        };

        e.apply_modlist(&present_multivalue_mods);

        assert!(e.attribute_equality("class", &PartialValue::new_iutf8("test")));
        assert!(e.attribute_equality("class", &PartialValue::new_iutf8("multi_test")));

        // Assert purge on single/multi/empty value
        let purge_single_mods =
            unsafe { ModifyList::new_valid_list(vec![Modify::Purged(AttrString::from("attr"))]) };

        e.apply_modlist(&purge_single_mods);

        assert!(!e.attribute_pres("attr"));

        let purge_multi_mods =
            unsafe { ModifyList::new_valid_list(vec![Modify::Purged(AttrString::from("class"))]) };

        e.apply_modlist(&purge_multi_mods);

        assert!(!e.attribute_pres("class"));

        let purge_empty_mods = purge_single_mods;

        e.apply_modlist(&purge_empty_mods);

        // Assert removed on value that exists and doesn't exist
        let remove_mods = unsafe {
            ModifyList::new_valid_list(vec![Modify::Removed(
                AttrString::from("attr"),
                PartialValue::new_iutf8("value"),
            )])
        };

        e.apply_modlist(&present_single_mods);
        assert!(e.attribute_equality("attr", &PartialValue::new_iutf8("value")));
        e.apply_modlist(&remove_mods);
        assert!(e.attrs.get("attr").unwrap().is_empty());

        let remove_empty_mods = remove_mods;

        e.apply_modlist(&remove_empty_mods);

        assert!(e.attrs.get("attr").unwrap().is_empty());
    }

    #[test]
    fn test_entry_idx_diff() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava("userid", Value::from("william"));
        let mut e1_mod = e1.clone();
        e1_mod.add_ava("extra", Value::from("test"));

        let e1 = unsafe { e1.into_sealed_committed() };
        let e1_mod = unsafe { e1_mod.into_sealed_committed() };

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("userid", Value::from("claire"));
        let e2 = unsafe { e2.into_sealed_committed() };

        let mut idxmeta = HashMap::with_capacity(8);
        idxmeta.insert(
            IdxKey {
                attr: AttrString::from("userid"),
                itype: IndexType::Equality,
            },
            IdxSlope::MAX,
        );
        idxmeta.insert(
            IdxKey {
                attr: AttrString::from("userid"),
                itype: IndexType::Presence,
            },
            IdxSlope::MAX,
        );
        idxmeta.insert(
            IdxKey {
                attr: AttrString::from("extra"),
                itype: IndexType::Equality,
            },
            IdxSlope::MAX,
        );

        // When we do None, None, we get nothing back.
        let r1 = Entry::idx_diff(&idxmeta, None, None);
        eprintln!("{:?}", r1);
        assert!(r1 == Vec::new());

        // Check generating a delete diff
        let mut del_r = Entry::idx_diff(&idxmeta, Some(&e1), None);
        del_r.sort_unstable();
        eprintln!("del_r {:?}", del_r);
        assert!(
            del_r[0]
                == Err((
                    &AttrString::from("userid"),
                    &IndexType::Equality,
                    "william".to_string()
                ))
        );
        assert!(
            del_r[1]
                == Err((
                    &AttrString::from("userid"),
                    &IndexType::Presence,
                    "_".to_string()
                ))
        );

        // Check generating an add diff
        let mut add_r = Entry::idx_diff(&idxmeta, None, Some(&e1));
        add_r.sort_unstable();
        eprintln!("{:?}", add_r);
        assert!(
            add_r[0]
                == Ok((
                    &AttrString::from("userid"),
                    &IndexType::Equality,
                    "william".to_string()
                ))
        );
        assert!(
            add_r[1]
                == Ok((
                    &AttrString::from("userid"),
                    &IndexType::Presence,
                    "_".to_string()
                ))
        );

        // Check the mod cases now

        // Check no changes
        let no_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1));
        assert!(no_r.len() == 0);

        // Check "adding" an attribute.
        let add_a_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1_mod));
        assert!(
            add_a_r[0]
                == Ok((
                    &AttrString::from("extra"),
                    &IndexType::Equality,
                    "test".to_string()
                ))
        );

        // Check "removing" an attribute.
        let del_a_r = Entry::idx_diff(&idxmeta, Some(&e1_mod), Some(&e1));
        assert!(
            del_a_r[0]
                == Err((
                    &AttrString::from("extra"),
                    &IndexType::Equality,
                    "test".to_string()
                ))
        );

        // Change an attribute.
        let mut chg_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e2));
        chg_r.sort_unstable();
        eprintln!("{:?}", chg_r);
        assert!(
            chg_r[1]
                == Err((
                    &AttrString::from("userid"),
                    &IndexType::Equality,
                    "william".to_string()
                ))
        );

        assert!(
            chg_r[0]
                == Ok((
                    &AttrString::from("userid"),
                    &IndexType::Equality,
                    "claire".to_string()
                ))
        );
    }

    #[test]
    fn test_entry_mask_recycled_ts() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava("class", Value::new_class("person"));
        let e1 = unsafe { e1.into_sealed_committed() };
        assert!(e1.mask_recycled_ts().is_some());

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("class", Value::new_class("person"));
        e2.add_ava("class", Value::new_class("recycled"));
        let e2 = unsafe { e2.into_sealed_committed() };
        assert!(e2.mask_recycled_ts().is_none());

        let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
        e3.add_ava("class", Value::new_class("tombstone"));
        let e3 = unsafe { e3.into_sealed_committed() };
        assert!(e3.mask_recycled_ts().is_none());
    }

    #[test]
    fn test_entry_idx_name2uuid_diff() {
        // none, none,
        let r = Entry::idx_name2uuid_diff(None, None);
        assert!(r == (None, None));

        // none, some - test adding an entry gives back add sets
        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("class", Value::new_class("person"));
            let e = unsafe { e.into_sealed_committed() };

            assert!(Entry::idx_name2uuid_diff(None, Some(&e)) == (Some(Set::new()), None));
        }

        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("class", Value::new_class("person"));
            e.add_ava("gidnumber", Value::new_uint32(1300));
            e.add_ava("name", Value::new_iname("testperson"));
            e.add_ava("spn", Value::new_spn_str("testperson", "example.com"));
            e.add_ava(
                "uuid",
                Value::new_uuids("9fec0398-c46c-4df4-9df5-b0016f7d563f").unwrap(),
            );
            let e = unsafe { e.into_sealed_committed() };

            // Note the uuid isn't present!
            assert!(
                Entry::idx_name2uuid_diff(None, Some(&e))
                    == (
                        Some(btreeset![
                            "1300".to_string(),
                            "testperson".to_string(),
                            "testperson@example.com".to_string()
                        ]),
                        None
                    )
            );
            // some, none,
            // Check delete, swap the order of args
            assert!(
                Entry::idx_name2uuid_diff(Some(&e), None)
                    == (
                        None,
                        Some(btreeset![
                            "1300".to_string(),
                            "testperson".to_string(),
                            "testperson@example.com".to_string()
                        ])
                    )
            );

            // some, some (same), should be empty changes.
            assert!(
                Entry::idx_name2uuid_diff(Some(&e), Some(&e))
                    == (Some(Set::new()), Some(Set::new()))
            );
        }
        // some, some (diff)

        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("class", Value::new_class("person"));
            e1.add_ava("spn", Value::new_spn_str("testperson", "example.com"));
            let e1 = unsafe { e1.into_sealed_committed() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("class", Value::new_class("person"));
            e2.add_ava("name", Value::new_iname("testperson"));
            e2.add_ava("spn", Value::new_spn_str("testperson", "example.com"));
            let e2 = unsafe { e2.into_sealed_committed() };

            // One attr added
            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (Some(btreeset!["testperson".to_string()]), Some(Set::new()))
            );

            // One removed
            assert!(
                Entry::idx_name2uuid_diff(Some(&e2), Some(&e1))
                    == (Some(Set::new()), Some(btreeset!["testperson".to_string()]))
            );
        }

        // Value changed, remove old, add new.
        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("class", Value::new_class("person"));
            e1.add_ava("spn", Value::new_spn_str("testperson", "example.com"));
            let e1 = unsafe { e1.into_sealed_committed() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("class", Value::new_class("person"));
            e2.add_ava("spn", Value::new_spn_str("renameperson", "example.com"));
            let e2 = unsafe { e2.into_sealed_committed() };

            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (
                        Some(btreeset!["renameperson@example.com".to_string()]),
                        Some(btreeset!["testperson@example.com".to_string()])
                    )
            );
        }
    }

    #[test]
    fn test_entry_idx_uuid2spn_diff() {
        assert!(Entry::idx_uuid2spn_diff(None, None) == None);

        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava("spn", Value::new_spn_str("testperson", "example.com"));
        let e1 = unsafe { e1.into_sealed_committed() };

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("spn", Value::new_spn_str("renameperson", "example.com"));
        let e2 = unsafe { e2.into_sealed_committed() };

        assert!(
            Entry::idx_uuid2spn_diff(None, Some(&e1))
                == Some(Ok(Value::new_spn_str("testperson", "example.com")))
        );
        assert!(Entry::idx_uuid2spn_diff(Some(&e1), None) == Some(Err(())));
        assert!(Entry::idx_uuid2spn_diff(Some(&e1), Some(&e1)) == None);
        assert!(
            Entry::idx_uuid2spn_diff(Some(&e1), Some(&e2))
                == Some(Ok(Value::new_spn_str("renameperson", "example.com")))
        );
    }

    #[test]
    fn test_entry_idx_uuid2rdn_diff() {
        assert!(Entry::idx_uuid2rdn_diff(None, None) == None);

        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava("spn", Value::new_spn_str("testperson", "example.com"));
        let e1 = unsafe { e1.into_sealed_committed() };

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("spn", Value::new_spn_str("renameperson", "example.com"));
        let e2 = unsafe { e2.into_sealed_committed() };

        assert!(
            Entry::idx_uuid2rdn_diff(None, Some(&e1))
                == Some(Ok("spn=testperson@example.com".to_string()))
        );
        assert!(Entry::idx_uuid2rdn_diff(Some(&e1), None) == Some(Err(())));
        assert!(Entry::idx_uuid2rdn_diff(Some(&e1), Some(&e1)) == None);
        assert!(
            Entry::idx_uuid2rdn_diff(Some(&e1), Some(&e2))
                == Some(Ok("spn=renameperson@example.com".to_string()))
        );
    }
}

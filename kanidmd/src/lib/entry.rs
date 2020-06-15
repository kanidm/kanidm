//! Entries are the base unit of object storage in the server. This is one of the three foundational
//! concepts along with [`filter`]s and [`schema`] that everything else builds upon.
//!
//! An [`Entry`] is a collection of attribute-value sets. There are sometimes called attribute value
//! assertions, or avas. The attribute is a "key" and it holds 1 to infinitite associtade values
//! with no ordering. An entry has many avas. A pseudo example, minus schema and typing:
//!
//! ```
//! /*
//! Entry {
//!   "name": ["william"],
//!   "uuid": ["..."],
//!   "mail": ["maila@example.com", "mailb@example.com"],
//! }
//! */
//! ```
//!
//! There are three rules for entries:
//! * Must have an ava for UUID containing a single value.
//! * Any ava with zero values will be removed.
//! * Avas are stored with no sorting.
//!
//! For more, see the [`Entry`] type.
//!
//! [`Entry`]: struct.Entry.html
//! [`filter`]: ../filter/index.html
//! [`schema`]: ../schema/index.html

// use serde_json::{Error, Value};
use crate::audit::AuditScope;
use crate::credential::Credential;
use crate::filter::{Filter, FilterInvalid, FilterResolved, FilterValidResolved};
use crate::ldap::ldap_attr_entry_map;
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::repl::cid::Cid;
use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use crate::value::{IndexType, SyntaxType};
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::Filter as ProtoFilter;
use kanidm_proto::v1::{OperationError, SchemaError};

use crate::be::dbentry::{DbEntry, DbEntryV1, DbEntryVers};

use ldap3_server::simple::{LdapPartialAttribute, LdapSearchResultEntry};
use std::collections::btree_map::Iter as BTreeIter;
use std::collections::btree_set::Iter as BTreeSetIter;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::iter::ExactSizeIterator;
use uuid::Uuid;

// use std::convert::TryFrom;
// use std::str::FromStr;

// make a trait entry for everything to adhere to?
//  * How to get indexs out?
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

pub struct EntryClasses<'a> {
    size: usize,
    inner: Option<BTreeSetIter<'a, Value>>,
    // _p: &'a PhantomData<()>,
}

impl<'a> Iterator for EntryClasses<'a> {
    type Item = &'a Value;

    #[inline]
    fn next(&mut self) -> Option<&'a Value> {
        match self.inner.iter_mut().next() {
            Some(i) => i.next(),
            None => None,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.inner.iter().next() {
            Some(i) => i.size_hint(),
            None => (0, None),
        }
    }
}

impl<'a> ExactSizeIterator for EntryClasses<'a> {
    fn len(&self) -> usize {
        self.size
    }
}

pub struct EntryAvas<'a> {
    inner: BTreeIter<'a, String, BTreeSet<Value>>,
}

impl<'a> Iterator for EntryAvas<'a> {
    type Item = (&'a String, &'a BTreeSet<Value>);

    #[inline]
    fn next(&mut self) -> Option<(&'a String, &'a BTreeSet<Value>)> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/*
pub struct EntryAvasMut<'a> {
    inner: BTreeIterMut<'a, String, BTreeSet<Value>>,
}

impl<'a> Iterator for EntryAvasMut<'a> {
    type Item = (&'a String, &'a mut BTreeSet<Value>);

    #[inline]
    fn next(&mut self) -> Option<(&'a String, &'a mut BTreeSet<Value>)> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}
*/

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

fn compare_attrs(
    left: &BTreeMap<String, BTreeSet<Value>>,
    right: &BTreeMap<String, BTreeSet<Value>>,
) -> bool {
    left.iter()
        .filter(|(k, _v)| k != &"last_modified_cid")
        .zip(right.iter().filter(|(k, _v)| k != &"last_modified_cid"))
        .all(|((ka, va), (kb, vb))| ka == kb && va == vb)
}

/// Entry is the core data storage type of the server. Almost every aspect of the server is
/// designed to read, handle and manipulate entries.
///
/// Entries store attribute value assertions, or ava. These are sets of key-values.
///
/// Entries have a lifecycle within a single operation, and as part of replication.
/// The lifecycle for operations is defined through state and valid types. Each entry has a pair
/// Of these types at anytime. The first is the ava [`schema`] and [`access`] control assertion
/// state. This is represented by the type `VALID` as one of `EntryValid`, `EntryInvalid` or
/// `EntryReduced`. Every entry starts as `EntryInvalid`, and when checked by the schema for
/// correctness, transitions to `EntryValid`. While an entry is `EntryValid` it can not be
/// altered - you must invalidate it to `EntryInvalid`, then modify, then check again.
/// An entry that has had access controls applied moves from `EntryValid` to `EntryReduced`,
/// to show that the avas have reduced to the valid read set of the current [`event`] user.
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
    // We may need to change this to BTreeSet to allow borrow of Value -> PartialValue for lookups.
    attrs: BTreeMap<String, BTreeSet<Value>>,
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
    pub(crate) fn get_uuid(&self) -> Option<&Uuid> {
        match self.attrs.get("uuid") {
            Some(vs) => match vs.iter().take(1).next() {
                // Uv is a value that might contain uuid - we hope it does!
                Some(uv) => uv.to_uuid(),
                _ => None,
            },
            None => None,
        }
    }
}

impl Entry<EntryInit, EntryNew> {
    #[cfg(test)]
    pub fn new() -> Self {
        Entry {
            // This means NEVER COMMITED
            valid: EntryInit,
            state: EntryNew,
            attrs: BTreeMap::new(),
        }
    }

    // Could we consume protoentry?
    //
    // I think we could, but that would limit us to how protoentry works,
    // where we are likely to actually change the Entry type here and how
    // we store and represent types and data.
    pub fn from_proto_entry(
        audit: &mut AuditScope,
        e: &ProtoEntry,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        // Why not the trait? In the future we may want to extend
        // this with server aware functions for changes of the
        // incoming data.

        // Somehow we need to take the tree of e attrs, and convert
        // all ref types to our types ...
        let map2: Result<BTreeMap<String, BTreeSet<Value>>, OperationError> = e
            .attrs
            .iter()
            .map(|(k, v)| {
                let nk = qs.get_schema().normalise_attr_name(k);
                let nv: Result<BTreeSet<Value>, _> =
                    v.iter().map(|vr| qs.clone_value(audit, &nk, vr)).collect();
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

    pub fn from_proto_entry_str(
        audit: &mut AuditScope,
        es: &str,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        if cfg!(test) {
            if es.len() > 256 {
                let (dsp_es, _) = es.split_at(255);
                ltrace!(audit, "Parsing -> {}...", dsp_es);
            } else {
                ltrace!(audit, "Parsing -> {}", es);
            }
        }
        // str -> Proto entry
        let pe: ProtoEntry = try_audit!(
            audit,
            serde_json::from_str(es).map_err(|e| {
                ladmin_error!(audit, "SerdeJson Failure -> {:?}", e);
                OperationError::SerdeJsonError
            })
        );
        // now call from_proto_entry
        Self::from_proto_entry(audit, &pe, qs)
    }

    #[cfg(test)]
    pub(crate) fn unsafe_from_entry_str(es: &str) -> Self {
        // Just use log directly here, it's testing
        // str -> proto entry
        let pe: ProtoEntry = serde_json::from_str(es).expect("Invalid Proto Entry");
        // use a const map to convert str -> ava
        let x: BTreeMap<String, BTreeSet<Value>> = pe.attrs.into_iter()
            .map(|(k, vs)| {
                let attr = k.to_lowercase();
                let vv: BTreeSet<Value> = match attr.as_str() {
                    "attributename" | "classname" | "domain" => {
                        vs.into_iter().map(|v| Value::new_iutf8(v)).collect()
                    }
                    "name" | "domain_name" => {
                        vs.into_iter().map(|v| Value::new_iname(v)).collect()
                    }
                    "userid" | "uidnumber" => {
                        warn!("WARNING: Use of unstabilised attributes userid/uidnumber");
                        vs.into_iter().map(|v| Value::new_iutf8(v)).collect()
                    }
                    "class" | "acp_create_class" | "acp_modify_class"  => {
                        vs.into_iter().map(|v| Value::new_class(v.as_str())).collect()
                    }
                    "acp_create_attr" | "acp_search_attr" | "acp_modify_removedattr" | "acp_modify_presentattr" |
                    "systemmay" | "may" | "systemmust" | "must"
                    => {
                        vs.into_iter().map(|v| Value::new_attr(v.as_str())).collect()
                    }
                    "uuid" | "domain_uuid" => {
                        vs.into_iter().map(|v| Value::new_uuids(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect()
                    }
                    "member" | "memberof" | "directmemberof" => {
                        vs.into_iter().map(|v| Value::new_refer_s(v.as_str()).unwrap() ).collect()
                    }
                    "acp_enable" | "multivalue" | "unique" => {
                        vs.into_iter().map(|v| Value::new_bools(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                            ).collect()
                    }
                    "syntax" => {
                        vs.into_iter().map(|v| Value::new_syntaxs(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect()
                    }
                    "index" => {
                        vs.into_iter().map(|v| Value::new_indexs(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect()
                    }
                    "acp_targetscope" | "acp_receiver" => {
                        vs.into_iter().map(|v| Value::new_json_filter(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        ).collect()
                    }
                    "displayname" | "description" => {
                        vs.into_iter().map(|v| Value::new_utf8(v)).collect()
                    }
                    "spn" => {
                        vs.into_iter().map(|v| {
                            Value::new_spn_parse(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect SPN attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        }).collect()
                    }
                    "gidnumber" | "version" => {
                        vs.into_iter().map(|v| {
                            Value::new_uint32_str(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect UINT32 attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        }).collect()
                    }
                    ia => {
                        warn!("WARNING: Allowing invalid attribute {} to be interpretted as UTF8 string. YOU MAY ENCOUNTER ODD BEHAVIOUR!!!", ia);
                        vs.into_iter().map(|v| Value::new_utf8(v)).collect()
                    }
                };
                (attr, vv)
            })
            .collect();

        // return the entry!
        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs: x,
        }
    }

    pub fn assign_cid(mut self, cid: Cid) -> Entry<EntryInvalid, EntryNew> {
        /* setup our last changed time */
        self.set_last_changed(cid.clone());

        Entry {
            valid: EntryInvalid { cid },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

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

    #[cfg(test)]
    pub fn add_ava(&mut self, attr: &str, value: &Value) {
        self.add_ava_int(attr, value)
    }
}

impl<STATE> Entry<EntryInvalid, STATE> {
    // This is only used in tests today, but I don't want to cfg test it.
    pub(crate) fn get_uuid(&self) -> Option<&Uuid> {
        match self.attrs.get("uuid") {
            Some(vs) => match vs.iter().take(1).next() {
                // Uv is a value that might contain uuid - we hope it does!
                Some(uv) => uv.to_uuid(),
                _ => None,
            },
            None => None,
        }
    }

    pub fn validate(
        self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let schema_classes = schema.get_classes();
        let schema_attributes = schema.get_attributes();

        let uuid: Uuid = match &self.attrs.get("uuid") {
            Some(vs) => match vs.iter().take(1).next() {
                Some(uuid_v) => match uuid_v.to_uuid() {
                    Some(uuid) => *uuid,
                    None => return Err(SchemaError::InvalidAttribute("uuid".to_string())),
                },
                None => return Err(SchemaError::MissingMustAttribute(vec!["uuid".to_string()])),
            },
            None => return Err(SchemaError::MissingMustAttribute(vec!["uuid".to_string()])),
        };

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

        // We scope here to limit the time of borrow of ne.
        {
            // First, check we have class on the object ....
            if !ne.attribute_pres("class") {
                // lrequest_error!("Missing attribute class");
                return Err(SchemaError::NoClassFound);
            }

            // Do we have extensible?
            let extensible = ne.attribute_value_pres("class", &CLASS_EXTENSIBLE);

            let entry_classes = ne.classes().ok_or(SchemaError::NoClassFound)?;
            let mut invalid_classes = Vec::with_capacity(0);

            let mut classes: Vec<&SchemaClass> = Vec::with_capacity(entry_classes.len());
            entry_classes.for_each(|c: &Value| {
                // we specify types here to help me clarify a few things in the
                // development process :)
                match c.as_string() {
                    Some(s) => match schema_classes.get(s) {
                        Some(x) => classes.push(x),
                        None => invalid_classes.push(s.clone()),
                    },
                    None => invalid_classes.push("corrupt classname".to_string()),
                }
            });

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
                    Ok(schema_attributes.get(s).ok_or(SchemaError::Corrupted)?)
                })
                .collect();

            let must = must?;

            // Check that all must are inplace
            //   for each attr in must, check it's present on our ent
            let mut missing_must = Vec::with_capacity(0);
            must.iter().for_each(|attr| {
                let avas = ne.get_ava(&attr.name);
                if avas.is_none() {
                    missing_must.push(attr.name.clone());
                }
            });

            if !missing_must.is_empty() {
                return Err(SchemaError::MissingMustAttribute(missing_must));
            }

            if extensible {
                // ladmin_warning!("Extensible Object In Use!");
                for (attr_name, avas) in ne.avas() {
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
                                return Err(SchemaError::PhantomAttribute(attr_name.clone()));
                            }

                            let r = a_schema.validate_ava(attr_name.as_str(), avas);
                            match r {
                                Ok(_) => {}
                                Err(e) => {
                                    // lrequest_error!("Failed to validate: {}", attr_name);
                                    return Err(e);
                                }
                            }
                        }
                        None => {
                            // lrequest_error!("Invalid Attribute {} for extensible object", attr_name);
                            return Err(SchemaError::InvalidAttribute(attr_name.clone()));
                        }
                    }
                }
            } else {
                // Note - we do NOT need to check phantom attributes here because they are
                // not allowed to exist in the class, which means a phantom attribute can't
                // be in the may/must set, and would FAIL our normal checks anyway.

                // We clone string here, but it's so we can check all
                // the values in "may" ar here - so we can't avoid this look up. What we
                // could do though, is have &String based on the schemaattribute though?;
                let may: Result<HashMap<&String, &SchemaAttribute>, _> = classes
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
                for (attr_name, avas) in ne.avas() {
                    match may.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            let r = a_schema.validate_ava(attr_name.as_str(), avas);
                            match r {
                                Ok(_) => {}
                                Err(e) => {
                                    // lrequest_error!("Failed to validate: {}", attr_name);
                                    return Err(e);
                                }
                            }
                        }
                        None => {
                            // lrequest_error!("Invalid Attribute {} for may+must set", attr_name);
                            return Err(SchemaError::InvalidAttribute(attr_name.clone()));
                        }
                    }
                }
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

    pub fn into_recycled(mut self) -> Self {
        self.add_ava("class", &Value::new_class("recycled"));

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
    Vec<Result<(&'a String, &'a IndexType, String), (&'a String, &'a IndexType, String)>>;

impl<VALID> Entry<VALID, EntryCommitted> {
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

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

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
                        let dbvs: Vec<_> = vs.iter().map(|v| v.to_db_valuev1()).collect();
                        (k.clone(), dbvs)
                    })
                    .collect(),
            }),
        }
    }

    #[inline]
    fn get_name2uuid_cands(&self) -> BTreeSet<String> {
        // The cands are:
        // * spn
        // * name
        // * gidnumber

        let cands = ["spn", "name", "gidnumber"];
        cands
            .iter()
            .filter_map(|c| {
                self.attrs
                    .get(*c)
                    .map(|avs| avs.iter().map(|v| v.to_proto_string_clone()))
            })
            .flatten()
            .collect()
    }

    #[inline]
    pub(crate) fn get_uuid2spn(&self) -> Value {
        self.attrs
            .get("spn")
            .and_then(|vs| vs.iter().take(1).next().cloned())
            .or_else(|| {
                self.attrs
                    .get("name")
                    .and_then(|vs| vs.iter().take(1).next().cloned())
            })
            .unwrap_or_else(|| Value::new_uuidr(self.get_uuid()))
    }

    #[inline]
    fn get_uuid2rdn(&self) -> String {
        self.attrs
            .get("spn")
            .and_then(|vs| {
                vs.iter()
                    .take(1)
                    .next()
                    .map(|v| format!("spn={}", v.to_proto_string_clone()))
            })
            .or_else(|| {
                self.attrs.get("name").and_then(|vs| {
                    vs.iter()
                        .take(1)
                        .next()
                        .map(|v| format!("name={}", v.to_proto_string_clone()))
                })
            })
            .unwrap_or_else(|| format!("uuid={}", self.get_uuid().to_hyphenated_ref()))
    }

    #[inline]
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
        Option<BTreeSet<String>>,
        // Remove
        Option<BTreeSet<String>>,
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
                let add_set: BTreeSet<_> = post_set.difference(&pre_set).cloned().collect();
                // what is in pre, but not post (removed)
                let rem_set: BTreeSet<_> = pre_set.difference(&post_set).cloned().collect();
                (Some(add_set), Some(rem_set))
            }
        }
    }

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

    // This is an associated method, not on & self so we can take options on
    // both sides.
    pub(crate) fn idx_diff<'a>(
        idxmeta: &'a BTreeSet<(String, IndexType)>,
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
                    .iter()
                    .flat_map(|(attr, itype)| {
                        match pre_e.get_ava(attr.as_str()) {
                            None => Vec::new(),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match itype {
                                    IndexType::EQUALITY => {
                                        vs.iter()
                                            .flat_map(|v| {
                                                // Turn each idx_key to the tuple of
                                                // changes.
                                                v.generate_idx_eq_keys()
                                                    .into_iter()
                                                    .map(|idx_key| Err((attr, itype, idx_key)))
                                            })
                                            .collect()
                                    }
                                    IndexType::PRESENCE => {
                                        vec![Err((attr, itype, "_".to_string()))]
                                    }
                                    IndexType::SUBSTRING => Vec::new(),
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
                    .iter()
                    .flat_map(|(attr, itype)| {
                        match post_e.get_ava(attr.as_str()) {
                            None => Vec::new(),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match itype {
                                    IndexType::EQUALITY => {
                                        vs.iter()
                                            .flat_map(|v| {
                                                // Turn each idx_key to the tuple of
                                                // changes.
                                                v.generate_idx_eq_keys()
                                                    .into_iter()
                                                    .map(|idx_key| Ok((attr, itype, idx_key)))
                                            })
                                            .collect()
                                    }
                                    IndexType::PRESENCE => vec![Ok((attr, itype, "_".to_string()))],
                                    IndexType::SUBSTRING => Vec::new(),
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
                    .iter()
                    .flat_map(|(attr, itype)| {
                        match (
                            pre_e.get_ava_set(attr.as_str()),
                            post_e.get_ava_set(attr.as_str()),
                        ) {
                            (None, None) => {
                                // Neither have it, do nothing.
                                Vec::new()
                            }
                            (Some(pre_vs), None) => {
                                // It existed before, but not anymore
                                let changes: Vec<Result<_, _>> = match itype {
                                    IndexType::EQUALITY => {
                                        pre_vs
                                            .iter()
                                            .flat_map(|v| {
                                                // Turn each idx_key to the tuple of
                                                // changes.
                                                v.generate_idx_eq_keys()
                                                    .into_iter()
                                                    .map(|idx_key| Err((attr, itype, idx_key)))
                                            })
                                            .collect()
                                    }
                                    IndexType::PRESENCE => {
                                        vec![Err((attr, itype, "_".to_string()))]
                                    }
                                    IndexType::SUBSTRING => Vec::new(),
                                };
                                changes
                            }
                            (None, Some(post_vs)) => {
                                // It was added now.
                                let changes: Vec<Result<_, _>> = match itype {
                                    IndexType::EQUALITY => {
                                        post_vs
                                            .iter()
                                            .flat_map(|v| {
                                                // Turn each idx_key to the tuple of
                                                // changes.
                                                v.generate_idx_eq_keys()
                                                    .into_iter()
                                                    .map(|idx_key| Ok((attr, itype, idx_key)))
                                            })
                                            .collect()
                                    }
                                    IndexType::PRESENCE => vec![Ok((attr, itype, "_".to_string()))],
                                    IndexType::SUBSTRING => Vec::new(),
                                };
                                changes
                            }
                            (Some(pre_vs), Some(post_vs)) => {
                                // it exists in both, we need to work out the differents within the attr.
                                pre_vs
                                    .difference(&post_vs)
                                    .map(|pre_v| {
                                        // Was in pre, now not in post
                                        match itype {
                                            IndexType::EQUALITY => {
                                                // Remove the v
                                                pre_v
                                                    .generate_idx_eq_keys()
                                                    .into_iter()
                                                    .map(|idx_key| Err((attr, itype, idx_key)))
                                                    .collect()
                                            }
                                            IndexType::PRESENCE => {
                                                // No action - we still are "present", so nothing to do!
                                                Vec::new()
                                            }
                                            IndexType::SUBSTRING => Vec::new(),
                                        }
                                    })
                                    .chain(post_vs.difference(&pre_vs).map(|post_v| {
                                        // is in post, but not in pre (add)
                                        match itype {
                                            IndexType::EQUALITY => {
                                                // Remove the v
                                                post_v
                                                    .generate_idx_eq_keys()
                                                    .into_iter()
                                                    .map(|idx_key| Ok((attr, itype, idx_key)))
                                                    .collect()
                                            }
                                            IndexType::PRESENCE => {
                                                // No action - we still are "present", so nothing to do!
                                                Vec::new()
                                            }
                                            IndexType::SUBSTRING => Vec::new(),
                                        }
                                    }))
                                    .flatten() // flatten all the inner vecs
                                    .collect() // now collect to an array of changes.
                            }
                        }
                    })
                    .collect()
                // End diff of the entries
            }
        }
    }

    pub fn from_dbentry(au: &mut AuditScope, db_e: DbEntry, id: u64) -> Result<Self, ()> {
        // Convert attrs from db format to value
        let r_attrs: Result<BTreeMap<String, BTreeSet<Value>>, ()> = match db_e.ent {
            DbEntryVers::V1(v1) => v1
                .attrs
                .into_iter()
                .map(|(k, vs)| {
                    let vv: Result<BTreeSet<Value>, ()> =
                        vs.into_iter().map(Value::from_db_valuev1).collect();
                    match vv {
                        Ok(vv) => Ok((k, vv)),
                        Err(()) => {
                            ladmin_error!(au, "from_dbentry failed on value {:?}", k);
                            Err(())
                        }
                    }
                })
                .collect(),
        };

        let attrs = r_attrs?;

        let uuid: Uuid = *match attrs.get("uuid") {
            Some(vs) => vs.iter().take(1).next(),
            None => None,
        }
        .ok_or(())?
        // Now map value -> uuid
        .to_uuid()
        .ok_or(())?;

        Ok(Entry {
            valid: EntrySealed { uuid },
            state: EntryCommitted { id },
            attrs,
        })
    }

    pub unsafe fn into_reduced(self) -> Entry<EntryReduced, EntryCommitted> {
        Entry {
            valid: EntryReduced {
                uuid: self.valid.uuid,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn reduce_attributes(
        self,
        allowed_attrs: BTreeSet<&str>,
    ) -> Entry<EntryReduced, EntryCommitted> {
        // Remove all attrs from our tree that are NOT in the allowed set.

        let Entry {
            valid: s_valid,
            state: s_state,
            attrs: s_attrs,
        } = self;

        let f_attrs: BTreeMap<_, _> = s_attrs
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

    pub fn to_tombstone(&self, cid: Cid) -> Entry<EntryInvalid, EntryCommitted> {
        // Duplicate this to a tombstone entry
        let class_ava = btreeset![Value::new_class("object"), Value::new_class("tombstone")];
        let last_mod_ava = btreeset![Value::new_cid(cid.clone())];

        let mut attrs_new: BTreeMap<String, BTreeSet<Value>> = BTreeMap::new();

        attrs_new.insert(
            "uuid".to_string(),
            btreeset![Value::new_uuidr(&self.get_uuid())],
        );
        attrs_new.insert("class".to_string(), class_ava);
        attrs_new.insert("last_modified_cid".to_string(), last_mod_ava);

        Entry {
            valid: EntryInvalid { cid },
            state: self.state.clone(),
            attrs: attrs_new,
        }
    }

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

    pub fn to_pe(
        &self,
        audit: &mut AuditScope,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<ProtoEntry, OperationError> {
        // Turn values -> Strings.
        let attrs: Result<_, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| {
                let pvs: Result<Vec<String>, _> =
                    vs.iter().map(|v| qs.resolve_value(audit, v)).collect();
                let pvs = pvs?;
                Ok((k.clone(), pvs))
            })
            .collect();
        Ok(ProtoEntry { attrs: attrs? })
    }

    pub fn to_ldap(
        &self,
        audit: &mut AuditScope,
        qs: &mut QueryServerReadTransaction,
        basedn: &str,
    ) -> Result<LdapSearchResultEntry, OperationError> {
        let rdn = qs.uuid_to_rdn(audit, self.get_uuid())?;

        let dn = format!("{},{}", rdn, basedn);

        let attributes: Result<Vec<_>, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| {
                let pvs: Result<Vec<String>, _> = vs
                    .iter()
                    .map(|v| qs.resolve_value_ldap(audit, v, basedn))
                    .collect();
                let pvs = pvs?;
                let ks = ldap_attr_entry_map(k.as_str());
                Ok(LdapPartialAttribute {
                    atype: ks,
                    vals: pvs,
                })
            })
            .collect();
        let attributes = attributes?;
        Ok(LdapSearchResultEntry { dn, attributes })
    }
}

// impl<STATE> Entry<EntryValid, STATE> {
impl<VALID, STATE> Entry<VALID, STATE> {
    fn add_ava_int(&mut self, attr: &str, value: &Value) {
        // How do we make this turn into an ok / err?
        self.attrs
            .entry(attr.to_string())
            .and_modify(|v| {
                // Here we need to actually do a check/binary search ...
                if v.contains(value) {
                    // It already exists, done!
                } else {
                    v.insert(value.clone());
                }
            })
            .or_insert(btreeset![value.clone()]);
    }

    fn set_last_changed(&mut self, cid: Cid) {
        let cv = btreeset![Value::new_cid(cid)];
        let _ = self.attrs.insert("last_modified_cid".to_string(), cv);
    }

    pub fn get_ava(&self, attr: &str) -> Option<Vec<&Value>> {
        match self.attrs.get(attr) {
            Some(vs) => {
                let x: Vec<_> = vs.iter().collect();
                Some(x)
            }
            None => None,
        }
    }

    pub fn get_ava_set(&self, attr: &str) -> Option<BTreeSet<&Value>> {
        self.attrs.get(attr).map(|vs| vs.iter().collect())
    }

    pub fn get_ava_set_str(&self, attr: &str) -> Option<BTreeSet<&str>> {
        self.attrs.get(attr).and_then(|vs| {
            let x: Option<BTreeSet<_>> = vs.iter().map(|s| s.to_str()).collect();
            x
        })
    }

    // Returns NONE if there is more than ONE!!!!
    pub fn get_ava_single(&self, attr: &str) -> Option<&Value> {
        match self.attrs.get(attr) {
            Some(vs) => {
                if vs.len() != 1 {
                    None
                } else {
                    vs.iter().take(1).next()
                }
            }
            None => None,
        }
    }

    pub fn get_ava_names(&self) -> BTreeSet<&str> {
        // Get the set of all attribute names in the entry
        let r: BTreeSet<&str> = self.attrs.keys().map(|a| a.as_str()).collect();
        r
    }

    pub fn get_ava_reference_uuid(&self, attr: &str) -> Option<Vec<&Uuid>> {
        // If any value is NOT a reference, return none!
        match self.attrs.get(attr) {
            Some(av) => {
                let v: Option<Vec<&Uuid>> = av.iter().map(|e| e.to_ref_uuid()).collect();
                v
            }
            None => None,
        }
    }

    // These are special types to allow returning typed values from
    // an entry, if we "know" what we expect to receive.

    /// This returns an array of IndexTypes, when the type is an Optional
    /// multivalue in schema - IE this will *not* fail if the attribute is
    /// empty, yielding and empty array instead.
    ///
    /// However, the converstion to IndexType is fallaible, so in case of a failure
    /// to convert, an Err is returned.
    pub(crate) fn get_ava_opt_index(&self, attr: &str) -> Result<Vec<&IndexType>, ()> {
        match self.attrs.get(attr) {
            Some(av) => {
                let r: Result<Vec<_>, _> = av.iter().map(|v| v.to_indextype().ok_or(())).collect();
                r
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get a bool from an ava
    pub fn get_ava_single_bool(&self, attr: &str) -> Option<bool> {
        match self.get_ava_single(attr) {
            Some(a) => a.to_bool(),
            None => None,
        }
    }

    pub fn get_ava_single_uint32(&self, attr: &str) -> Option<u32> {
        match self.get_ava_single(attr) {
            Some(a) => a.to_uint32(),
            None => None,
        }
    }

    pub fn get_ava_single_syntax(&self, attr: &str) -> Option<&SyntaxType> {
        match self.get_ava_single(attr) {
            Some(a) => a.to_syntaxtype(),
            None => None,
        }
    }

    pub fn get_ava_single_credential(&self, attr: &str) -> Option<&Credential> {
        self.get_ava_single(attr).and_then(|a| a.to_credential())
    }

    pub fn get_ava_single_radiuscred(&self, attr: &str) -> Option<&str> {
        self.get_ava_single(attr)
            .and_then(|a| a.get_radius_secret())
    }

    pub fn get_ava_ssh_pubkeys(&self, attr: &str) -> Vec<String> {
        match self.attrs.get(attr) {
            Some(ava) => ava.iter().filter_map(|v| v.get_sshkey()).collect(),
            None => Vec::new(),
        }
    }

    /*
    /// This interface will get &str (if possible).
    pub(crate) fn get_ava_opt_str(&self, attr: &str) -> Option<Vec<&str>> {
        match self.attrs.get(attr) {
            Some(a) => {
                let r: Vec<_> = a.iter().filter_map(|v| v.to_str()).collect();
                if r.len() == 0 {
                    None
                } else {
                    Some(r)
                }
            }
            None => Some(Vec::new()),
        }
    }
    */

    pub(crate) fn get_ava_opt_string(&self, attr: &str) -> Option<Vec<String>> {
        match self.attrs.get(attr) {
            Some(a) => {
                let r: Vec<String> = a.iter().filter_map(|v| v.as_string().cloned()).collect();
                if r.is_empty() {
                    // Corrupt?
                    None
                } else {
                    Some(r)
                }
            }
            None => Some(Vec::new()),
        }
    }

    /*
    pub(crate) fn get_ava_string(&self, attr: &str) -> Option<Vec<String>> {
        match self.attrs.get(attr) {
            Some(a) => {
                let r: Vec<String> = a
                    .iter()
                    .filter_map(|v| v.as_string().map(|s| s.clone()))
                    .collect();
                if r.len() == 0 {
                    // Corrupt?
                    None
                } else {
                    Some(r)
                }
            }
            None => None,
        }
    }
    */

    pub(crate) fn get_ava_set_string(&self, attr: &str) -> Option<BTreeSet<String>> {
        match self.attrs.get(attr) {
            Some(a) => {
                let r: BTreeSet<String> = a.iter().filter_map(|v| v.as_string().cloned()).collect();
                if r.is_empty() {
                    // Corrupt?
                    None
                } else {
                    Some(r)
                }
            }
            None => None,
        }
    }

    pub fn get_ava_single_str(&self, attr: &str) -> Option<&str> {
        self.get_ava_single(attr).and_then(|v| v.to_str())
    }

    pub fn get_ava_single_string(&self, attr: &str) -> Option<String> {
        self.get_ava_single(attr)
            .and_then(|v: &Value| v.as_string())
            .map(|s: &String| (*s).clone())
    }

    pub fn get_ava_single_protofilter(&self, attr: &str) -> Option<ProtoFilter> {
        self.get_ava_single(attr)
            .and_then(|v: &Value| v.as_json_filter())
            .map(|f: &ProtoFilter| (*f).clone())
    }

    pub(crate) fn generate_spn(&self, domain_name: &str) -> Option<Value> {
        self.get_ava_single_str("name")
            .map(|name| Value::new_spn_str(name, domain_name))
    }

    pub fn attribute_pres(&self, attr: &str) -> bool {
        // Note, we don't normalise attr name, but I think that's not
        // something we should over-optimise on.
        self.attrs.contains_key(attr)
    }

    #[inline]
    pub fn attribute_value_pres(&self, attr: &str, value: &PartialValue) -> bool {
        // Yeah, this is techdebt, but both names of this fn are valid - we are
        // checking if an attribute-value is equal to, or asserting it's present
        // as a pair. So I leave both, and let the compiler work it out.
        self.attribute_equality(attr, value)
    }

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

    pub fn attribute_substring(&self, attr: &str, subvalue: &PartialValue) -> bool {
        match self.attrs.get(attr) {
            Some(v_list) => v_list
                .iter()
                .fold(false, |acc, v| if acc { acc } else { v.contains(subvalue) }),
            None => false,
        }
    }

    /// Confirm if at least one value in the ava is less than subvalue.
    pub fn attribute_lessthan(&self, attr: &str, subvalue: &PartialValue) -> bool {
        match self.attrs.get(attr) {
            Some(v_list) => v_list
                .iter()
                .fold(false, |acc, v| if acc { acc } else { v.lessthan(subvalue) }),
            None => false,
        }
    }

    pub fn classes(&self) -> Option<EntryClasses> {
        // Get the class vec, if any?
        // How do we indicate "empty?"
        let v = self.attrs.get("class").map(|c| c.len())?;
        let c = self.attrs.get("class").map(|c| c.iter());
        Some(EntryClasses { size: v, inner: c })
    }

    pub fn avas(&self) -> EntryAvas {
        EntryAvas {
            inner: self.attrs.iter(),
        }
    }

    // Since EntryValid/Invalid is just about class adherenece, not Value correctness, we
    // can now apply filters to invalid entries - why? Because even if they aren't class
    // valid, we still have strict typing checks between the filter -> entry to guarantee
    // they should be functional. We'll never match something that isn't syntactially valid.
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
            FilterResolved::Or(l) => l.iter().fold(false, |acc, f| {
                // Check with ftweedal about or filter zero len correctness.
                if acc {
                    acc
                } else {
                    self.entry_match_no_index_inner(f)
                }
            }),
            FilterResolved::And(l) => l.iter().fold(true, |acc, f| {
                // Check with ftweedal about and filter zero len correctness.
                if acc {
                    self.entry_match_no_index_inner(f)
                } else {
                    acc
                }
            }),
            FilterResolved::AndNot(f) => !self.entry_match_no_index_inner(f),
        }
    }

    pub fn filter_from_attrs(&self, attrs: &[String]) -> Option<Filter<FilterInvalid>> {
        // Because we are a valid entry, a filter we create still may not
        // be valid because the internal server entry templates are still
        // created by humans! Plus double checking something already valid
        // is not bad ...
        //
        // Generate a filter from the attributes requested and defined.
        // Basically, this is a series of nested and's (which will be
        // optimised down later: but if someone wants to solve flatten() ...)

        // Take name: (a, b), name: (c, d) -> (name, a), (name, b), (name, c), (name, d)

        let mut pairs: Vec<(&str, &Value)> = Vec::new();

        for attr in attrs {
            match self.attrs.get(attr) {
                Some(values) => {
                    for v in values {
                        pairs.push((attr, v))
                    }
                }
                None => return None,
            }
        }

        Some(filter_all!(f_and(
            pairs
                .into_iter()
                .map(|(attr, value)| {
                    // We use FC directly here instead of f_eq to avoid an excess clone.
                    FC::Eq(attr, value.to_partialvalue())
                })
                .collect()
        )))
    }

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
            for v in vs {
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
    pub fn add_ava(&mut self, attr: &str, value: &Value) {
        self.add_ava_int(attr, value)
    }

    fn remove_ava(&mut self, attr: &str, value: &PartialValue) {
        // It would be great to remove these extra allocations, but they
        // really don't cost much :(
        self.attrs.entry(attr.to_string()).and_modify(|v| {
            // Here we need to actually do a check/binary search ...
            v.remove(value);
        });
    }

    pub fn purge_ava(&mut self, attr: &str) {
        self.attrs.remove(attr);
    }

    pub fn pop_ava(&mut self, attr: &str) -> Option<BTreeSet<Value>> {
        self.attrs.remove(attr)
    }

    /// Overwrite the existing avas.
    pub fn set_avas(&mut self, attr: &str, values: Vec<Value>) {
        // Overwrite the existing value, build a tree from the list.
        let x: BTreeSet<_> = values.into_iter().collect();
        let _ = self.attrs.insert(attr.to_string(), x);
    }

    /// Provide a true ava set.
    pub fn set_ava(&mut self, attr: &str, values: BTreeSet<Value>) {
        // Overwrite the existing value, build a tree from the list.
        let _ = self.attrs.insert(attr.to_string(), values);
    }

    /*
    pub fn avas_mut(&mut self) -> EntryAvasMut {
        EntryAvasMut {
            inner: self.attrs.iter_mut(),
        }
    }
    */

    // Should this be schemaless, relying on checks of the modlist, and the entry validate after?
    // YES. Makes it very cheap.
    pub fn apply_modlist(&mut self, modlist: &ModifyList<ModifyValid>) {
        // -> Result<Entry<EntryInvalid, STATE>, OperationError> {
        // Apply a modlist, generating a new entry that conforms to the changes.
        // This is effectively clone-and-transform

        // mutate
        for modify in modlist {
            match modify {
                Modify::Present(a, v) => self.add_ava(a.as_str(), v),
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
        let uuid_v = btreeset![Value::new_uuidr(&s.uuid)];

        let name_v = btreeset![Value::new_iutf8(s.name.clone())];
        let desc_v = btreeset![Value::new_utf8(s.description.clone())];

        let multivalue_v = btreeset![Value::from(s.multivalue)];
        let unique_v = btreeset![Value::from(s.unique)];

        let index_v: BTreeSet<_> = s.index.iter().map(|i| Value::from(i.clone())).collect();

        let syntax_v = btreeset![Value::from(s.syntax.clone())];

        // Build the BTreeMap of the attributes relevant
        let mut attrs: BTreeMap<String, BTreeSet<Value>> = BTreeMap::new();
        attrs.insert("attributename".to_string(), name_v);
        attrs.insert("description".to_string(), desc_v);
        attrs.insert("uuid".to_string(), uuid_v);
        attrs.insert("multivalue".to_string(), multivalue_v);
        attrs.insert("unique".to_string(), unique_v);
        attrs.insert("index".to_string(), index_v);
        attrs.insert("syntax".to_string(), syntax_v);
        attrs.insert(
            "class".to_string(),
            btreeset![
                Value::new_class("object"),
                Value::new_class("system"),
                Value::new_class("attributetype")
            ],
        );

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
        let uuid_v = btreeset![Value::new_uuidr(&s.uuid)];

        let name_v = btreeset![Value::new_iutf8(s.name.clone())];
        let desc_v = btreeset![Value::new_utf8(s.description.clone())];

        let mut attrs: BTreeMap<String, BTreeSet<Value>> = BTreeMap::new();
        attrs.insert("classname".to_string(), name_v);
        attrs.insert("description".to_string(), desc_v);
        attrs.insert("uuid".to_string(), uuid_v);
        attrs.insert(
            "class".to_string(),
            btreeset![
                Value::new_class("object"),
                Value::new_class("system"),
                Value::new_class("classtype")
            ],
        );

        if !s.systemmay.is_empty() {
            attrs.insert(
                "systemmay".to_string(),
                s.systemmay
                    .iter()
                    .map(|sm| Value::new_attr(sm.as_str()))
                    .collect(),
            );
        }

        if !s.systemmust.is_empty() {
            attrs.insert(
                "systemmust".to_string(),
                s.systemmust
                    .iter()
                    .map(|sm| Value::new_attr(sm.as_str()))
                    .collect(),
            );
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
    use crate::entry::{Entry, EntryInit, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::value::{IndexType, PartialValue, Value};
    use std::collections::BTreeSet;

    #[test]
    fn test_entry_basic() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava("userid", &Value::from("william"));
    }

    #[test]
    fn test_entry_dup_value() {
        // Schema doesn't matter here because we are duplicating a value
        // it should fail!

        // We still probably need schema here anyway to validate what we
        // are adding ... Or do we validate after the changes are made in
        // total?
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava("userid", &Value::from("william"));
        e.add_ava("userid", &Value::from("william"));

        let values = e.get_ava("userid").expect("Failed to get ava");
        // Should only be one value!
        assert_eq!(values.len(), 1)
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava("userid", &Value::from("william"));

        assert!(e.attribute_pres("userid"));
        assert!(!e.attribute_pres("name"));
    }

    #[test]
    fn test_entry_equality() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava("userid", &Value::from("william"));

        assert!(e.attribute_equality("userid", &PartialValue::new_utf8s("william")));
        assert!(!e.attribute_equality("userid", &PartialValue::new_utf8s("test")));
        assert!(!e.attribute_equality("nonexist", &PartialValue::new_utf8s("william")));
        // Also test non-matching attr syntax
        assert!(!e.attribute_equality("userid", &PartialValue::new_class("william")));
    }

    #[test]
    fn test_entry_substring() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava("userid", &Value::from("william"));

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

        e1.add_ava("a", &Value::new_uint32(10));

        assert!(e1.attribute_lessthan("a", &pv2) == false);
        assert!(e1.attribute_lessthan("a", &pv8) == false);
        assert!(e1.attribute_lessthan("a", &pv10) == false);
        assert!(e1.attribute_lessthan("a", &pv15) == true);

        e1.add_ava("a", &Value::new_uint32(8));

        assert!(e1.attribute_lessthan("a", &pv2) == false);
        assert!(e1.attribute_lessthan("a", &pv8) == false);
        assert!(e1.attribute_lessthan("a", &pv10) == true);
        assert!(e1.attribute_lessthan("a", &pv15) == true);
    }

    #[test]
    fn test_entry_apply_modlist() {
        // Test application of changes to an entry.
        let mut e: Entry<EntryInvalid, EntryNew> = unsafe { Entry::new().into_invalid_new() };

        e.add_ava("userid", &Value::from("william"));

        let present_single_mods = unsafe {
            ModifyList::new_valid_list(vec![Modify::Present(
                String::from("attr"),
                Value::new_iutf8s("value"),
            )])
        };

        e.apply_modlist(&present_single_mods);

        // Assert the changes are there
        assert!(e.attribute_equality("userid", &PartialValue::new_utf8s("william")));
        assert!(e.attribute_equality("attr", &PartialValue::new_iutf8s("value")));

        // Assert present for multivalue
        let present_multivalue_mods = unsafe {
            ModifyList::new_valid_list(vec![
                Modify::Present(String::from("class"), Value::new_iutf8s("test")),
                Modify::Present(String::from("class"), Value::new_iutf8s("multi_test")),
            ])
        };

        e.apply_modlist(&present_multivalue_mods);

        assert!(e.attribute_equality("class", &PartialValue::new_iutf8s("test")));
        assert!(e.attribute_equality("class", &PartialValue::new_iutf8s("multi_test")));

        // Assert purge on single/multi/empty value
        let purge_single_mods =
            unsafe { ModifyList::new_valid_list(vec![Modify::Purged(String::from("attr"))]) };

        e.apply_modlist(&purge_single_mods);

        assert!(!e.attribute_pres("attr"));

        let purge_multi_mods =
            unsafe { ModifyList::new_valid_list(vec![Modify::Purged(String::from("class"))]) };

        e.apply_modlist(&purge_multi_mods);

        assert!(!e.attribute_pres("class"));

        let purge_empty_mods = purge_single_mods;

        e.apply_modlist(&purge_empty_mods);

        // Assert removed on value that exists and doesn't exist
        let remove_mods = unsafe {
            ModifyList::new_valid_list(vec![Modify::Removed(
                String::from("attr"),
                PartialValue::new_iutf8s("value"),
            )])
        };

        e.apply_modlist(&present_single_mods);
        assert!(e.attribute_equality("attr", &PartialValue::new_iutf8s("value")));
        e.apply_modlist(&remove_mods);
        assert!(e.attrs.get("attr").unwrap().is_empty());

        let remove_empty_mods = remove_mods;

        e.apply_modlist(&remove_empty_mods);

        assert!(e.attrs.get("attr").unwrap().is_empty());
    }

    #[test]
    fn test_entry_idx_diff() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava("userid", &Value::from("william"));
        let mut e1_mod = e1.clone();
        e1_mod.add_ava("extra", &Value::from("test"));

        let e1 = unsafe { e1.into_sealed_committed() };
        let e1_mod = unsafe { e1_mod.into_sealed_committed() };

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("userid", &Value::from("claire"));
        let e2 = unsafe { e2.into_sealed_committed() };

        let mut idxmeta = BTreeSet::new();
        idxmeta.insert(("userid".to_string(), IndexType::EQUALITY));
        idxmeta.insert(("userid".to_string(), IndexType::PRESENCE));
        idxmeta.insert(("extra".to_string(), IndexType::EQUALITY));

        // When we do None, None, we get nothing back.
        let r1 = Entry::idx_diff(&idxmeta, None, None);
        debug!("{:?}", r1);
        assert!(r1 == Vec::new());

        // Check generating a delete diff
        let del_r = Entry::idx_diff(&idxmeta, Some(&e1), None);
        debug!("{:?}", del_r);
        assert!(
            del_r[0]
                == Err((
                    &"userid".to_string(),
                    &IndexType::EQUALITY,
                    "william".to_string()
                ))
        );
        assert!(del_r[1] == Err((&"userid".to_string(), &IndexType::PRESENCE, "_".to_string())));

        // Check generating an add diff
        let add_r = Entry::idx_diff(&idxmeta, None, Some(&e1));
        debug!("{:?}", add_r);
        assert!(
            add_r[0]
                == Ok((
                    &"userid".to_string(),
                    &IndexType::EQUALITY,
                    "william".to_string()
                ))
        );
        assert!(add_r[1] == Ok((&"userid".to_string(), &IndexType::PRESENCE, "_".to_string())));

        // Check the mod cases now

        // Check no changes
        let no_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1));
        assert!(no_r.len() == 0);

        // Check "adding" an attribute.
        let add_a_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1_mod));
        assert!(
            add_a_r[0]
                == Ok((
                    &"extra".to_string(),
                    &IndexType::EQUALITY,
                    "test".to_string()
                ))
        );

        // Check "removing" an attribute.
        let del_a_r = Entry::idx_diff(&idxmeta, Some(&e1_mod), Some(&e1));
        assert!(
            del_a_r[0]
                == Err((
                    &"extra".to_string(),
                    &IndexType::EQUALITY,
                    "test".to_string()
                ))
        );

        // Change an attribute.
        let chg_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e2));
        assert!(
            chg_r[0]
                == Err((
                    &"userid".to_string(),
                    &IndexType::EQUALITY,
                    "william".to_string()
                ))
        );

        assert!(
            chg_r[1]
                == Ok((
                    &"userid".to_string(),
                    &IndexType::EQUALITY,
                    "claire".to_string()
                ))
        );
        debug!("{:?}", chg_r);
    }

    #[test]
    fn test_entry_mask_recycled_ts() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava("class", &Value::new_class("person"));
        let e1 = unsafe { e1.into_sealed_committed() };
        assert!(e1.mask_recycled_ts().is_some());

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("class", &Value::new_class("person"));
        e2.add_ava("class", &Value::new_class("recycled"));
        let e2 = unsafe { e2.into_sealed_committed() };
        assert!(e2.mask_recycled_ts().is_none());

        let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
        e3.add_ava("class", &Value::new_class("tombstone"));
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
            e.add_ava("class", &Value::new_class("person"));
            let e = unsafe { e.into_sealed_committed() };

            assert!(Entry::idx_name2uuid_diff(None, Some(&e)) == (Some(BTreeSet::new()), None));
        }

        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("class", &Value::new_class("person"));
            e.add_ava("gidnumber", &Value::new_uint32(1300));
            e.add_ava("name", &Value::new_iname_s("testperson"));
            e.add_ava("spn", &Value::new_spn_str("testperson", "example.com"));
            e.add_ava(
                "uuid",
                &Value::new_uuids("9fec0398-c46c-4df4-9df5-b0016f7d563f").unwrap(),
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
                    == (Some(BTreeSet::new()), Some(BTreeSet::new()))
            );
        }
        // some, some (diff)

        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("class", &Value::new_class("person"));
            e1.add_ava("spn", &Value::new_spn_str("testperson", "example.com"));
            let e1 = unsafe { e1.into_sealed_committed() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("class", &Value::new_class("person"));
            e2.add_ava("name", &Value::new_iname_s("testperson"));
            e2.add_ava("spn", &Value::new_spn_str("testperson", "example.com"));
            let e2 = unsafe { e2.into_sealed_committed() };

            // One attr added
            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (
                        Some(btreeset!["testperson".to_string()]),
                        Some(BTreeSet::new())
                    )
            );

            // One removed
            assert!(
                Entry::idx_name2uuid_diff(Some(&e2), Some(&e1))
                    == (
                        Some(BTreeSet::new()),
                        Some(btreeset!["testperson".to_string()])
                    )
            );
        }

        // Value changed, remove old, add new.
        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("class", &Value::new_class("person"));
            e1.add_ava("spn", &Value::new_spn_str("testperson", "example.com"));
            let e1 = unsafe { e1.into_sealed_committed() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("class", &Value::new_class("person"));
            e2.add_ava("spn", &Value::new_spn_str("renameperson", "example.com"));
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
        e1.add_ava("spn", &Value::new_spn_str("testperson", "example.com"));
        let e1 = unsafe { e1.into_sealed_committed() };

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("spn", &Value::new_spn_str("renameperson", "example.com"));
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
        e1.add_ava("spn", &Value::new_spn_str("testperson", "example.com"));
        let e1 = unsafe { e1.into_sealed_committed() };

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava("spn", &Value::new_spn_str("renameperson", "example.com"));
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

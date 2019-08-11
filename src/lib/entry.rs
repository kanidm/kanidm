// use serde_json::{Error, Value};
use crate::audit::AuditScope;
use crate::error::{OperationError, SchemaError};
use crate::filter::{Filter, FilterInvalid, FilterResolved, FilterValidResolved};
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::proto::v1::Entry as ProtoEntry;
use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};
use crate::server::QueryServerWriteTransaction;
use crate::value::{IndexType, SyntaxType};
use crate::value::{PartialValue, Value};

use crate::be::dbentry::{DbEntry, DbEntryV1, DbEntryVers};

use std::collections::btree_map::{Iter as BTreeIter, IterMut as BTreeIterMut};
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
    static ref CLASS_EXTENSIBLE: PartialValue = PartialValue::new_utf8s("extensibleobject");
}

pub struct EntryClasses<'a> {
    size: usize,
    inner: Option<BTreeSetIter<'a, Value>>,
    // _p: &'a PhantomData<()>,
}

impl<'a> Iterator for EntryClasses<'a> {
    type Item = &'a Value;

    #[inline]
    fn next(&mut self) -> Option<(&'a Value)> {
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

// This is a BE concept, so move it there!

// Entry should have a lifecycle of types. THis is Raw (modifiable) and Entry (verified).
// This way, we can move between them, but only certain actions are possible on either
// This means modifications happen on Raw, but to move to Entry, you schema normalise.
// Vice versa, you can for free, move to Raw, but you lose the validation.

// Because this is type system it's "free" in the end, and means we force validation
// at the correct and required points of the entries life.

// This is specifically important for the commit to the backend, as we only want to
// commit validated types.

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EntryNew; // new
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EntryCommitted {
    id: u64,
} // It's been in the DB, so it has an id
  // pub struct EntryPurged;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EntryValid {
    // Asserted with schema, so we know it has a UUID now ...
    uuid: Uuid,
}

// Modified, can't be sure of it's content! We therefore disregard the UUID
// and on validate, we check it again.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EntryInvalid;

// This state can't exist because everything is normalised now with Value types
// #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
// pub struct EntryNormalised;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EntryReduced;

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry<VALID, STATE> {
    valid: VALID,
    state: STATE,
    // We may need to change this to BTreeSet to allow borrow of Value -> PartialValue for lookups.
    attrs: BTreeMap<String, BTreeSet<Value>>,
}

impl<STATE> std::fmt::Display for Entry<EntryValid, STATE> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.get_uuid())
    }
}

impl Entry<EntryInvalid, EntryNew> {
    #[cfg(test)]
    pub fn new() -> Self {
        Entry {
            // This means NEVER COMMITED
            valid: EntryInvalid,
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
        qs: &QueryServerWriteTransaction,
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
                let nv: Result<BTreeSet<Value>, _> = v
                    .iter()
                    .map(|vr| Value::from_attr(audit, qs, &k, vr))
                    .collect();
                match nv {
                    Ok(mut nvi) => Ok((k.clone(), nvi)),
                    Err(e) => Err(e),
                }
            })
            .collect();

        let x = map2?;

        Ok(Entry {
            // For now, we do a straight move, and we sort the incoming data
            // sets so that BST works.
            state: EntryNew,
            valid: EntryInvalid,
            attrs: x,
        })
    }
}

impl<STATE> Entry<EntryInvalid, STATE> {
    // This is only used in tests today, but I don't want to cfg test it.
    #[allow(dead_code)]
    fn get_uuid(&self) -> Option<&Uuid> {
        match self.attrs.get("uuid") {
            Some(vs) => match vs.iter().take(1).next() {
                Some(uv) => match uv {
                    Value::Uuid(u) => Some(&u),
                    _ => None,
                },
                _ => None,
            },
            None => None,
        }
    }

    /*
    pub fn normalise(
        self,
        schema: &SchemaTransaction,
    ) -> Result<Entry<EntryNormalised, STATE>, SchemaError> {
        let Entry {
            valid: _,
            state,
            attrs,
        } = self;

        let schema_attributes = schema.get_attributes();

        // This should never fail!
        let schema_attr_name = match schema_attributes.get("name") {
            Some(v) => v,
            None => {
                return Err(SchemaError::Corrupted);
            }
        };

        let mut new_attrs = BTreeMap::new();

        // First normalise - this checks and fixes our UUID format
        // but should not remove multiple values.
        for (attr_name, avas) in attrs.iter() {
            let attr_name_normal: String = schema_attr_name.normalise_value(attr_name);
            // Get the needed schema type
            let schema_a_r = schema_attributes.get(&attr_name_normal);

            let mut avas_normal: Vec<String> = match schema_a_r {
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

            // Ensure they are ordered property, with no dupes.
            avas_normal.sort_unstable();
            avas_normal.dedup();

            // Should never fail!
            let _ = new_attrs.insert(attr_name_normal, avas_normal);
        }

        Ok(Entry {
            valid: EntryNormalised,
            state: state,
            attrs: new_attrs,
        })
    }

    pub fn validate(
        self,
        schema: &SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        // We need to clone before we start, as well be mutating content.
        // We destructure:

        // self.normalise(schema).and_then(|e| e.validate(schema))
        e.validate(schema)
    }
    */

    pub fn validate(
        self,
        schema: &SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let schema_classes = schema.get_classes();
        let schema_attributes = schema.get_attributes();

        let uuid: Uuid = match &self.attrs.get("uuid") {
            Some(vs) => match vs.iter().take(1).next() {
                Some(uuid_v) => match uuid_v {
                    Value::Uuid(uuid) => uuid.clone(),
                    _ => return Err(SchemaError::InvalidAttribute),
                },
                None => return Err(SchemaError::MissingMustAttribute("uuid".to_string())),
            },
            None => return Err(SchemaError::MissingMustAttribute("uuid".to_string())),
        };

        // Build the new valid entry ...
        let ne = Entry {
            valid: EntryValid { uuid },
            state: self.state,
            attrs: self.attrs,
        };
        // Now validate it!

        // We scope here to limit the time of borrow of ne.
        {
            // First, check we have class on the object ....
            if !ne.attribute_pres("class") {
                debug!("Missing attribute class");
                return Err(SchemaError::InvalidClass);
            }

            // Do we have extensible?
            let extensible = ne.attribute_value_pres("class", &CLASS_EXTENSIBLE);

            let entry_classes = ne.classes().ok_or(SchemaError::InvalidClass)?;
            let entry_classes_size = entry_classes.len();

            let classes: Vec<&SchemaClass> = entry_classes
                // we specify types here to help me clarify a few things in the
                // development process :)
                .filter_map(|c: &Value| {
                    let x: Option<&SchemaClass> = c.as_string().and_then(|s| schema_classes.get(s));
                    x
                })
                .collect();

            if classes.len() != entry_classes_size {
                debug!("Class on entry not found in schema?");
                return Err(SchemaError::InvalidClass);
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
            for attr in must {
                let avas = ne.get_ava(&attr.name);
                if avas.is_none() {
                    return Err(SchemaError::MissingMustAttribute(attr.name.clone()));
                }
            }

            if extensible {
                for (attr_name, avas) in ne.avas() {
                    match schema_attributes.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            let r = a_schema.validate_ava(avas);
                            match r {
                                Ok(_) => {}
                                Err(e) => {
                                    debug!("Failed to validate: {}", attr_name);
                                    return Err(e);
                                }
                            }
                        }
                        None => {
                            debug!("Invalid Attribute for extensible object");
                            return Err(SchemaError::InvalidAttribute);
                        }
                    }
                }
            } else {
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
                    debug!("Checking {}", attr_name);
                    match may.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            let r = a_schema.validate_ava(avas);
                            match r {
                                Ok(_) => {}
                                Err(e) => {
                                    debug!("Failed to validate: {}", attr_name);
                                    return Err(e);
                                }
                            }
                        }
                        None => {
                            debug!("Invalid Attribute for may+must set");
                            return Err(SchemaError::InvalidAttribute);
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
    STATE: Copy,
{
    // Dirty modifiable state. Works on any other state to dirty them.
    fn clone(&self) -> Entry<VALID, STATE> {
        Entry {
            valid: self.valid.clone(),
            state: self.state,
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
    pub unsafe fn to_valid_new(self) -> Entry<EntryValid, EntryNew> {
        Entry {
            valid: EntryValid {
                uuid: self.get_uuid().expect("Invalid uuid").clone(),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }
}
// Both invalid states can be reached from "entry -> invalidate"

impl Entry<EntryInvalid, EntryNew> {
    #[cfg(test)]
    pub unsafe fn to_valid_new(self) -> Entry<EntryValid, EntryNew> {
        Entry {
            valid: EntryValid {
                uuid: self.get_uuid().expect("Invalid uuid").clone(),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /*
    #[cfg(test)]
    pub unsafe fn to_valid_normal(self) -> Entry<EntryNormalised, EntryNew> {
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
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self
                    .get_uuid()
                    .and_then(|u| Some(u.clone()))
                    .unwrap_or_else(|| Uuid::new_v4()),
            },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryInvalid, EntryCommitted> {
    #[cfg(test)]
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self.get_uuid().expect("Missing UUID!").clone(),
            },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryValid, EntryNew> {
    #[cfg(test)]
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    pub fn compare(&self, rhs: &Entry<EntryValid, EntryCommitted>) -> bool {
        self.attrs == rhs.attrs
    }
}

impl Entry<EntryValid, EntryCommitted> {
    #[cfg(test)]
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        // NO-OP to satisfy macros.
        self
    }

    pub fn compare(&self, rhs: &Entry<EntryValid, EntryNew>) -> bool {
        self.attrs == rhs.attrs
    }

    pub fn to_tombstone(&self) -> Self {
        // Duplicate this to a tombstone entry
        let class_ava = btreeset![Value::from("object"), Value::from("tombstone")];

        let mut attrs_new: BTreeMap<String, BTreeSet<Value>> = BTreeMap::new();

        attrs_new.insert("uuid".to_string(), btreeset![Value::from(&self.valid.uuid)]);
        attrs_new.insert("class".to_string(), class_ava);

        Entry {
            valid: self.valid.clone(),
            state: self.state,
            attrs: attrs_new,
        }
    }

    pub fn get_id(&self) -> u64 {
        self.state.id
    }

    pub fn from_dbentry(db_e: DbEntry, id: u64) -> Option<Self> {
        // Convert attrs from db format to value
        let attrs: BTreeMap<String, BTreeSet<Value>> = match db_e.ent {
            DbEntryVers::V1(v1) => v1
                .attrs
                .into_iter()
                .map(|(k, vs)| {
                    let vv: BTreeSet<Value> =
                        vs.into_iter().map(|v| Value::from_db_valuev1(v)).collect();
                    (k, vv)
                })
                .collect(),
        };

        let uuid: Uuid = match attrs.get("uuid") {
            Some(vs) => vs.iter().take(1).next(),
            None => None,
        }?
        // Now map value -> uuid
        .to_uuid()?
        .clone();

        Some(Entry {
            valid: EntryValid { uuid: uuid },
            state: EntryCommitted { id },
            attrs: attrs,
        })
    }

    #[cfg(test)]
    pub fn to_reduced(self) -> Entry<EntryReduced, EntryCommitted> {
        Entry {
            valid: EntryReduced,
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
            valid: _s_valid,
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
            valid: EntryReduced,
            state: s_state,
            attrs: f_attrs,
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

    pub fn get_ava_single_syntax(&self, attr: &str) -> Option<&SyntaxType> {
        match self.get_ava_single(attr) {
            Some(a) => a.to_syntaxtype(),
            None => None,
        }
    }

    /// This interface will get &str (if possible), and then any caller is
    /// responsible to clone.
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
            None => None,
        }
    }
}

impl<STATE> Entry<EntryValid, STATE> {
    // Returns the entry in the latest DbEntry format we are aware of.
    pub fn into_dbentry(&self) -> DbEntry {
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

    pub fn invalidate(self) -> Entry<EntryInvalid, STATE> {
        Entry {
            valid: EntryInvalid,
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn get_uuid(&self) -> &Uuid {
        &self.valid.uuid
    }

    pub fn entry_match_no_index(&self, filter: &Filter<FilterValidResolved>) -> bool {
        self.entry_match_no_index_inner(filter.to_inner())
    }

    pub fn filter_from_attrs(&self, attrs: &Vec<String>) -> Option<Filter<FilterInvalid>> {
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
        schema: &SchemaTransaction,
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

impl Entry<EntryReduced, EntryCommitted> {
    pub fn into_pe(&self) -> ProtoEntry {
        // Turn values -> Strings.
        ProtoEntry {
            attrs: self
                .attrs
                .iter()
                .map(|(k, vs)| {
                    let pvs: Vec<_> = vs.iter().map(|v| v.to_proto_string_clone()).collect();
                    (k.clone(), pvs)
                })
                .collect(),
        }
    }
}

// impl<STATE> Entry<EntryValid, STATE> {
impl<VALID, STATE> Entry<VALID, STATE> {
    /*
     * WARNING: Should these TODO move to EntryValid only?
     * I've tried to do this once, but the issue is that there
     * is a lot of code in normalised and other states that
     * relies on the ability to get ava. I think we may not be
     * able to do so "easily".
     */
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
        self.attrs
            .get(attr)
            .and_then(|vs| Some(vs.iter().collect()))
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

    // This is private, but exists on all types, so that valid and normal can then
    // expose the simpler wrapper for entry_match_no_index only.
    // Assert if this filter matches the entry (no index)
    fn entry_match_no_index_inner(&self, filter: &FilterResolved) -> bool {
        // Go through the filter components and check them in the entry.
        // This is recursive!!!!
        match filter {
            FilterResolved::Eq(attr, value) => self.attribute_equality(attr.as_str(), value),
            FilterResolved::Sub(attr, subvalue) => {
                self.attribute_substring(attr.as_str(), subvalue)
            }
            FilterResolved::Pres(attr) => {
                // Given attr, is is present in the entry?
                self.attribute_pres(attr.as_str())
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
}

impl<STATE> Entry<EntryInvalid, STATE>
where
    STATE: Copy,
{
    // This should always work? It's only on validate that we'll build
    // a list of syntax violations ...
    // If this already exists, we silently drop the event? Is that an
    // acceptable interface?
    pub fn add_ava(&mut self, attr: &str, value: &Value) {
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

    /// Overwrite the existing avas.
    pub fn set_avas(&mut self, attr: &str, values: Vec<Value>) {
        // Overwrite the existing value, build a tree from the list.
        let x: BTreeSet<_> = values.into_iter().collect();
        let _ = self.attrs.insert(attr.to_string(), x);
    }

    pub fn avas_mut(&mut self) -> EntryAvasMut {
        EntryAvasMut {
            inner: self.attrs.iter_mut(),
        }
    }

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
        self.attrs == rhs.attrs
    }
}

impl From<&SchemaAttribute> for Entry<EntryValid, EntryNew> {
    fn from(s: &SchemaAttribute) -> Self {
        // Convert an Attribute to an entry ... make it good!
        let uuid = s.uuid.clone();
        let uuid_v = btreeset![Value::from(&uuid)];

        let name_v = btreeset![Value::new_insensitive_utf8(s.name.clone())];
        let desc_v = btreeset![Value::from(s.description.clone())];

        let multivalue_v = btreeset![Value::from(s.multivalue)];

        let index_v: BTreeSet<_> = s.index.iter().map(|i| Value::from(i)).collect();

        let syntax_v = btreeset![Value::from(s.syntax)];

        // Build the BTreeMap of the attributes relevant
        let mut attrs: BTreeMap<String, BTreeSet<Value>> = BTreeMap::new();
        attrs.insert("name".to_string(), name_v);
        attrs.insert("description".to_string(), desc_v);
        attrs.insert("uuid".to_string(), uuid_v);
        attrs.insert("multivalue".to_string(), multivalue_v);
        attrs.insert("index".to_string(), index_v);
        attrs.insert("syntax".to_string(), syntax_v);
        attrs.insert(
            "class".to_string(),
            btreeset![
                Value::new_insensitive_utf8("object".to_string()),
                Value::new_insensitive_utf8("system".to_string()),
                Value::new_insensitive_utf8("attributetype".to_string())
            ],
        );

        // Insert stuff.

        Entry {
            valid: EntryValid { uuid: uuid },
            state: EntryNew,
            attrs: attrs,
        }
    }
}

impl From<&SchemaClass> for Entry<EntryValid, EntryNew> {
    fn from(s: &SchemaClass) -> Self {
        let uuid = s.uuid.clone();
        let uuid_v = btreeset![Value::from(&uuid)];

        let name_v = btreeset![Value::new_insensitive_utf8(s.name.clone())];
        let desc_v = btreeset![Value::from(s.description.clone())];

        let mut attrs: BTreeMap<String, BTreeSet<Value>> = BTreeMap::new();
        attrs.insert("name".to_string(), name_v);
        attrs.insert("description".to_string(), desc_v);
        attrs.insert("uuid".to_string(), uuid_v);
        attrs.insert(
            "class".to_string(),
            btreeset![
                Value::new_insensitive_utf8("object".to_string()),
                Value::new_insensitive_utf8("system".to_string()),
                Value::new_insensitive_utf8("classtype".to_string())
            ],
        );
        attrs.insert(
            "systemmay".to_string(),
            s.systemmay
                .iter()
                .map(|sm| Value::new_insensitive_utf8(sm.clone()))
                .collect(),
        );
        attrs.insert(
            "systemmust".to_string(),
            s.systemmust
                .iter()
                .map(|sm| Value::new_insensitive_utf8(sm.clone()))
                .collect(),
        );

        Entry {
            valid: EntryValid { uuid: uuid },
            state: EntryNew,
            attrs: attrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::value::Value;

    #[test]
    fn test_entry_basic() {
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();

        e.add_ava("userid", "william");
    }

    #[test]
    fn test_entry_dup_value() {
        // Schema doesn't matter here because we are duplicating a value
        // it should fail!

        // We still probably need schema here anyway to validate what we
        // are adding ... Or do we validate after the changes are made in
        // total?
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();
        e.add_ava("userid", "william");
        e.add_ava("userid", "william");

        let values = e.get_ava("userid").expect("Failed to get ava");
        // Should only be one value!
        assert_eq!(values.len(), 1)
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();
        e.add_ava("userid", "william");

        assert!(e.attribute_pres("userid"));
        assert!(!e.attribute_pres("name"));
    }

    #[test]
    fn test_entry_equality() {
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();

        e.add_ava("userid", Value::from("william"));

        assert!(e.attribute_equality("userid", Value::from("william")));
        assert!(!e.attribute_equality("userid", Value::from("test")));
        assert!(!e.attribute_equality("nonexist", Value::from("william")));
    }

    #[test]
    fn test_entry_substring() {
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();

        e.add_ava("userid", "william");

        assert!(e.attribute_substring("userid", "william"));
        assert!(e.attribute_substring("userid", "will"));
        assert!(e.attribute_substring("userid", "liam"));
        assert!(e.attribute_substring("userid", "lli"));
        assert!(!e.attribute_substring("userid", "llim"));
        assert!(!e.attribute_substring("userid", "bob"));
        assert!(!e.attribute_substring("userid", "wl"));
    }

    #[test]
    fn test_entry_apply_modlist() {
        // Test application of changes to an entry.
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new();
        e.add_ava("userid", "william");

        let mods = unsafe {
            ModifyList::new_valid_list(vec![Modify::Present(
                String::from("attr"),
                String::from("value"),
            )])
        };

        e.apply_modlist(&mods);

        // Assert the changes are there
        assert!(e.attribute_equality("attr", "value"));

        // Assert present for multivalue
        // Assert purge on single/multi/empty value
        // Assert removed on value that exists and doesn't exist
    }
}

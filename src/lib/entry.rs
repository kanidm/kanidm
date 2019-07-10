// use serde_json::{Error, Value};
use crate::audit::AuditScope;
use crate::error::{OperationError, SchemaError};
use crate::filter::{Filter, FilterInvalid, FilterResolved, FilterValidResolved};
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::proto::v1::Entry as ProtoEntry;
use crate::proto::v1::UserAuthToken;
use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};
use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};

use crate::be::dbentry::{DbEntry, DbEntryV1, DbEntryVers};

use std::collections::btree_map::{Iter as BTreeIter, IterMut as BTreeIterMut};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::iter::ExactSizeIterator;
use std::slice::Iter as SliceIter;

#[cfg(test)]
use uuid::Uuid;

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

pub struct EntryClasses<'a> {
    size: usize,
    inner: Option<SliceIter<'a, String>>,
    // _p: &'a PhantomData<()>,
}

impl<'a> Iterator for EntryClasses<'a> {
    type Item = &'a String;

    #[inline]
    fn next(&mut self) -> Option<(&'a String)> {
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
    inner: BTreeIter<'a, String, Vec<String>>,
}

impl<'a> Iterator for EntryAvas<'a> {
    type Item = (&'a String, &'a Vec<String>);

    #[inline]
    fn next(&mut self) -> Option<(&'a String, &'a Vec<String>)> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

pub struct EntryAvasMut<'a> {
    inner: BTreeIterMut<'a, String, Vec<String>>,
}

impl<'a> Iterator for EntryAvasMut<'a> {
    type Item = (&'a String, &'a mut Vec<String>);

    #[inline]
    fn next(&mut self) -> Option<(&'a String, &'a mut Vec<String>)> {
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
    uuid: String,
}

// Modified, can't be sure of it's content! We therefore disregard the UUID
// and on validate, we check it again.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EntryInvalid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EntryNormalised;

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry<VALID, STATE> {
    valid: VALID,
    state: STATE,
    attrs: BTreeMap<String, Vec<String>>,
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

    // FIXME: Can we consume protoentry?
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

        let map2: Result<BTreeMap<String, Vec<String>>, OperationError> = e
            .attrs
            .iter()
            .map(|(k, v)| {
                let nv: Result<Vec<_>, _> =
                    v.iter().map(|vr| qs.clone_value(audit, &k, vr)).collect();
                match nv {
                    Ok(mut nvi) => {
                        nvi.sort_unstable();
                        Ok((k.clone(), nvi))
                    }
                    Err(e) => Err(e),
                }
            })
            .collect();

        let x = match map2 {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        Ok(Entry {
            // For now, we do a straight move, and we sort the incoming data
            // sets so that BST works.
            state: EntryNew,
            valid: EntryInvalid,
            attrs: x,
        })
    }
}

impl<STATE> Entry<EntryNormalised, STATE> {
    pub fn validate(
        self,
        schema: &SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let schema_classes = schema.get_classes();
        let schema_attributes = schema.get_attributes();

        let uuid: String = match &self.attrs.get("uuid") {
            Some(vs) => match vs.first() {
                Some(uuid) => uuid.to_string(),
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

        // First look at the classes on the entry.
        // Now, check they are valid classes
        //
        // FIXME: We could restructure this to be a map that gets Some(class)
        // if found, then do a len/filter/check on the resulting class set?

        {
            // First, check we have class on the object ....
            if !ne.attribute_pres("class") {
                return Err(SchemaError::InvalidClass);
            }

            let entry_classes = ne.classes();
            let entry_classes_size = entry_classes.len();

            let classes: HashMap<String, &SchemaClass> = entry_classes
                .filter_map(|c| match schema_classes.get(c) {
                    Some(cls) => Some((c.clone(), cls)),
                    None => None,
                })
                .collect();

            if classes.len() != entry_classes_size {
                return Err(SchemaError::InvalidClass);
            };

            let extensible = classes.contains_key("extensibleobject");

            // What this is really doing is taking a set of classes, and building an
            // "overall" class that describes this exact object for checking

            //   for each class
            //      add systemmust/must and systemmay/may to their lists
            //      add anything from must also into may

            // Now from the set of valid classes make a list of must/may
            // FIXME: This is clone on read, which may be really slow. It also may
            // be inefficent on duplicates etc.
            let must: Result<HashMap<String, &SchemaAttribute>, _> = classes
                .iter()
                // Join our class systemmmust + must into one iter
                .flat_map(|(_, cls)| cls.systemmust.iter().chain(cls.must.iter()))
                .map(|s| {
                    // This should NOT fail - if it does, it means our schema is
                    // in an invalid state!
                    Ok((
                        s.clone(),
                        schema_attributes.get(s).ok_or(SchemaError::Corrupted)?,
                    ))
                })
                .collect();

            let must = must?;

            // FIXME: Error needs to say what is missing
            // We need to return *all* missing attributes.

            // Check that all must are inplace
            //   for each attr in must, check it's present on our ent
            // FIXME: Could we iter over only the attr_name
            for (attr_name, _attr) in must {
                let avas = ne.get_ava(&attr_name);
                if avas.is_none() {
                    return Err(SchemaError::MissingMustAttribute(String::from(attr_name)));
                }
            }

            // Check that any other attributes are in may
            //   for each attr on the object, check it's in the may+must set
            for (attr_name, avas) in ne.avas() {
                match schema_attributes.get(attr_name) {
                    Some(a_schema) => {
                        // Now, for each type we do a *full* check of the syntax
                        // and validity of the ava.
                        let r = a_schema.validate_ava(avas);
                        // We have to destructure here to make type checker happy
                        match r {
                            Ok(_) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    None => {
                        if !extensible {
                            return Err(SchemaError::InvalidAttribute);
                        }
                    }
                }
            }
        } // unborrow ne.

        // Well, we got here, so okay!
        Ok(ne)
    }

    pub fn invalidate(self) -> Entry<EntryInvalid, STATE> {
        Entry {
            valid: EntryInvalid,
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn entry_match_no_index(&self, filter: &Filter<FilterValidResolved>) -> bool {
        self.entry_match_no_index_inner(filter.to_inner())
    }
}

impl<STATE> Entry<EntryInvalid, STATE> {
    fn get_uuid(&self) -> Option<&String> {
        match self.attrs.get("uuid") {
            Some(vs) => vs.first(),
            None => None,
        }
    }

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

        self.normalise(schema).and_then(|e| e.validate(schema))
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
                uuid: self.get_uuid().expect("Invalid uuid").to_string(),
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
                uuid: self.get_uuid().expect("Invalid uuid").to_string(),
            },
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

    #[cfg(test)]
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self
                    .get_uuid()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| Uuid::new_v4().to_hyphenated().to_string()),
            },
            state: EntryCommitted { id: 0 },
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
}

impl Entry<EntryInvalid, EntryCommitted> {
    #[cfg(test)]
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self.get_uuid().expect("Invalid uuid").to_string(),
            },
            state: self.state,
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
}

impl Entry<EntryValid, EntryNew> {
    #[cfg(test)]
    pub unsafe fn to_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id: 0 },
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
        // Duplicate this to a tombstone entry.
        let class_ava = vec!["object".to_string(), "tombstone".to_string()];

        let mut attrs_new: BTreeMap<String, Vec<String>> = BTreeMap::new();

        attrs_new.insert("uuid".to_string(), vec![self.valid.uuid.clone()]);
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

    pub fn from_dbentry(db_e: DbEntry, id: u64) -> Self {
        let attrs = match db_e.ent {
            DbEntryVers::V1(v1) => v1.attrs,
        };

        // TODO: Tidy this!
        let uuid: String = match attrs.get("uuid") {
            Some(vs) => vs.first(),
            None => None,
        }
        .expect("NO UUID PRESENT CORRUPT")
        .clone();

        Entry {
            valid: EntryValid { uuid: uuid },
            state: EntryCommitted { id },
            attrs: attrs,
        }
    }

    pub fn reduce_attributes(self, allowed_attrs: BTreeSet<&str>) -> Self {
        // TODO: Make this inplace, not copying.
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
            valid: s_valid,
            state: s_state,
            attrs: f_attrs,
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
                attrs: self.attrs.clone(),
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

    pub fn get_uuid(&self) -> &String {
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

        let mut pairs: Vec<(&str, &str)> = Vec::new();

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
                .map(|(attr, value)| f_eq(attr, value))
                .collect()
        )))
    }

    // FIXME: This should probably have an entry state for "reduced"
    // and then only that state can provide the into_pe type, so that we
    // can guarantee that all entries must have been security checked.
    pub fn into_pe(&self) -> ProtoEntry {
        // It's very likely that at this stage we'll need to apply
        // access controls, dynamic attributes or more.
        // As a result, this may not even be the right place
        // for the conversion as algorithmically it may be
        // better to do this from the outside view. This can
        // of course be identified and changed ...
        ProtoEntry {
            attrs: self.attrs.clone(),
        }
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
            // TODO: Remove this check when uuid becomes a real attribute.
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

impl<VALID, STATE> Entry<VALID, STATE> {
    /* WARNING: Should these TODO move to EntryValid only? */
    // TODO: Should this be Vec<&str>?
    pub fn get_ava(&self, attr: &str) -> Option<&Vec<String>> {
        self.attrs.get(attr)
    }

    pub fn get_ava_set(&self, attr: &str) -> Option<BTreeSet<&str>> {
        self.get_ava(attr).map(|vs| {
            // Map the vec to a BTreeSet instead.
            let r: BTreeSet<&str> = vs.iter().map(|a| a.as_str()).collect();
            r
        })
    }

    // Returns NONE if there is more than ONE!!!!
    pub fn get_ava_single(&self, attr: &str) -> Option<&String> {
        match self.attrs.get(attr) {
            Some(vs) => {
                if vs.len() != 1 {
                    None
                } else {
                    vs.first()
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
        // FIXME: Do we need to normalise attr name?
        self.attrs.contains_key(attr)
    }

    pub fn attribute_value_pres(&self, attr: &str, value: &str) -> bool {
        match self.attrs.get(attr) {
            Some(v_list) => match v_list.binary_search(&value.to_string()) {
                Ok(_) => true,
                Err(_) => false,
            },
            None => false,
        }
    }

    pub fn attribute_equality(&self, attr: &str, value: &str) -> bool {
        // we assume based on schema normalisation on the way in
        // that the equality here of the raw values MUST be correct.
        // We also normalise filters, to ensure that their values are
        // syntax valid and will correctly match here with our indexes.

        // FIXME: Make this binary_search

        self.attrs.get(attr).map_or(false, |v| {
            v.iter()
                .fold(false, |acc, av| if acc { acc } else { value == av })
        })
    }

    pub fn attribute_substring(&self, _attr: &str, _subvalue: &str) -> bool {
        unimplemented!();
    }

    pub fn classes(&self) -> EntryClasses {
        // Get the class vec, if any?
        // How do we indicate "empty?"
        // FIXME: Actually handle this error ...
        let v = self
            .attrs
            .get("class")
            .map(|c| c.len())
            .expect("INVALID STATE, NO CLASS FOUND");
        let c = self.attrs.get("class").map(|c| c.iter());
        EntryClasses { size: v, inner: c }
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
            FilterResolved::Eq(attr, value) => {
                self.attribute_equality(attr.as_str(), value.as_str())
            }
            FilterResolved::Sub(attr, subvalue) => {
                self.attribute_substring(attr.as_str(), subvalue.as_str())
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
    // Should value here actually be a &str?
    pub fn add_ava(&mut self, attr: &str, value: &str) {
        // get_mut to access value
        // How do we make this turn into an ok / err?
        self.attrs
            .entry(attr.to_string())
            .and_modify(|v| {
                // Here we need to actually do a check/binary search ...
                // FIXME: Because map_err is lazy, this won't do anything on release
                // TODO: Is there a way to avoid the double to_string here?
                match v.binary_search(&value.to_string()) {
                    // It already exists, done!
                    Ok(_) => {}
                    Err(idx) => {
                        // This cloning is to fix a borrow issue with the or_insert below.
                        // Is there a better way?
                        v.insert(idx, value.to_string())
                    }
                }
            })
            .or_insert(vec![value.to_string()]);
    }

    pub fn remove_ava(&mut self, attr: &str, value: &str) {
        // TODO fix this to_string
        let mv = value.to_string();
        self.attrs
            // TODO: Fix this to_string
            .entry(attr.to_string())
            .and_modify(|v| {
                // Here we need to actually do a check/binary search ...
                // FIXME: Because map_err is lazy, this won't do anything on release
                match v.binary_search(&mv) {
                    // It exists, rm it.
                    Ok(idx) => {
                        v.remove(idx);
                    }
                    // It does not exist, move on.
                    Err(_) => {}
                }
            });
    }

    pub fn purge_ava(&mut self, attr: &str) {
        self.attrs.remove(attr);
    }

    // FIXME: Should this collect from iter instead?
    // TODO: Should this be a Vec<&str>
    /// Overwrite the existing avas.
    pub fn set_avas(&mut self, attr: &str, values: Vec<String>) {
        // Overwrite the existing value
        let _ = self.attrs.insert(attr.to_string(), values);
    }

    pub fn avas_mut(&mut self) -> EntryAvasMut {
        EntryAvasMut {
            inner: self.attrs.iter_mut(),
        }
    }

    // Should this be schemaless, relying on checks of the modlist, and the entry validate after?
    pub fn apply_modlist(&mut self, modlist: &ModifyList<ModifyValid>) {
        // -> Result<Entry<EntryInvalid, STATE>, OperationError> {
        // Apply a modlist, generating a new entry that conforms to the changes.
        // This is effectively clone-and-transform

        // mutate
        for modify in modlist {
            match modify {
                Modify::Present(a, v) => self.add_ava(a.as_str(), v.as_str()),
                Modify::Removed(a, v) => self.remove_ava(a.as_str(), v.as_str()),
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

#[derive(Serialize, Deserialize, Debug)]
enum Credential {
    Password {
        name: String,
        hash: String,
    },
    TOTPPassword {
        name: String,
        hash: String,
        totp_secret: String,
    },
    SshPublicKey {
        name: String,
        data: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    // Could this be derived from self? Do we even need schema?
    class: Vec<String>,
    displayname: String,
    legalname: Option<String>,
    email: Vec<String>,
    // uuid?
    // need to support deref later ...
    memberof: Vec<String>,
    sshpublickey: Vec<String>,

    credentials: Vec<Credential>,
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    // use serde_json;

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

        e.add_ava("userid", "william");

        assert!(e.attribute_equality("userid", "william"));
        assert!(!e.attribute_equality("userid", "test"));
        assert!(!e.attribute_equality("nonexist", "william"));
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

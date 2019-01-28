// use serde_json::{Error, Value};
use super::proto_v1::Entry as ProtoEntry;
use filter::Filter;
use std::collections::btree_map::{Iter as BTreeIter, IterMut as BTreeIterMut};
use std::collections::BTreeMap;
use std::slice::Iter as SliceIter;
use modify::{Modify, ModifyList};
use schema::SchemaReadTransaction;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub id: Option<i64>,
    // Flag if we have been schema checked or not.
    // pub schema_validated: bool,
    attrs: BTreeMap<String, Vec<String>>,
}

impl Entry {
    pub fn new() -> Self {
        Entry {
            // This means NEVER COMMITED
            id: None,
            // TODO: Make this only on cfg(test/debug_assertions) builds.
            // ALTERNATE: Convert to a different entry type on validate/normalise?
            // CONVERT TO A TYPE
            attrs: BTreeMap::new(),
        }
    }

    // This should always work? It's only on validate that we'll build
    // a list of syntax violations ...
    // If this already exists, we silently drop the event? Is that an
    // acceptable interface?
    // Should value here actually be a &str?
    pub fn add_ava(&mut self, attr: String, value: String) {
        // get_mut to access value
        // How do we make this turn into an ok / err?
        self.attrs
            .entry(attr)
            .and_modify(|v| {
                // Here we need to actually do a check/binary search ...
                // FIXME: Because map_err is lazy, this won't do anything on release
                match v.binary_search(&value) {
                    // It already exists, done!
                    Ok(_) => {}
                    Err(idx) => {
                        // This cloning is to fix a borrow issue with the or_insert below.
                        // Is there a better way?
                        v.insert(idx, value.clone())
                    }
                }
            })
            .or_insert(vec![value]);
    }

    pub fn remove_ava(&mut self, attr: &String, value: &String) {
        self.attrs
            // TODO: Fix this clone ...
            .entry(attr.clone())
            .and_modify(|v| {
                // Here we need to actually do a check/binary search ...
                // FIXME: Because map_err is lazy, this won't do anything on release
                match v.binary_search(&value) {
                    // It exists, rm it.
                    Ok(idx) => {
                        v.remove(idx);
                    }
                    // It does not exist, move on.
                    Err(_) => {
                    }
                }
            });
    }

    pub fn purge_ava(&mut self, attr: &String) {
        self.attrs.remove(attr);
    }

    // FIXME: Should this collect from iter instead?
    /// Overwrite the existing avas.
    pub fn set_avas(&mut self, attr: String, values: Vec<String>) {
        // Overwrite the existing value
        let _ = self.attrs.insert(attr, values);
    }

    pub fn get_ava(&self, attr: &String) -> Option<&Vec<String>> {
        self.attrs.get(attr)
    }

    pub fn attribute_pres(&self, attr: &str) -> bool {
        // FIXME: Do we need to normalise attr name?
        self.attrs.contains_key(attr)
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
        let c = self.attrs.get("class").map(|c| c.iter());
        EntryClasses { inner: c }
    }

    pub fn avas(&self) -> EntryAvas {
        EntryAvas {
            inner: self.attrs.iter(),
        }
    }

    pub fn avas_mut(&mut self) -> EntryAvasMut {
        EntryAvasMut {
            inner: self.attrs.iter_mut(),
        }
    }

    pub fn filter_from_attrs(&self, attrs: &Vec<String>) -> Option<Filter> {
        // Generate a filter from the attributes requested and defined.
        // Basically, this is a series of nested and's (which will be
        // optimised down later: but if someone wants to solve flatten() ...)

        // Take name: (a, b), name: (c, d) -> (name, a), (name, b), (name, c), (name, d)

        let mut pairs: Vec<(String, String)> = Vec::new();

        for attr in attrs {
            match self.attrs.get(attr) {
                Some(values) => {
                    for v in values {
                        pairs.push((attr.clone(), v.clone()))
                    }
                }
                None => return None,
            }
        }

        // Now make this a filter?

        let eq_filters = pairs
            .into_iter()
            .map(|(attr, value)| Filter::Eq(attr, value))
            .collect();

        Some(Filter::And(eq_filters))
    }

    // FIXME: Can we consume protoentry?
    pub fn from(e: &ProtoEntry) -> Self {
        // Why not the trait? In the future we may want to extend
        // this with server aware functions for changes of the
        // incoming data.
        Entry {
            // For now, we do a straight move, and we sort the incoming data
            // sets so that BST works.
            id: None,
            attrs: e
                .attrs
                .iter()
                .map(|(k, v)| {
                    let mut nv = v.clone();
                    nv.sort_unstable();
                    (k.clone(), nv)
                })
                .collect(),
        }
    }

    pub fn into(&self) -> ProtoEntry {
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

    pub fn gen_modlist_assert(&self, schema: &SchemaReadTransaction) -> Result<ModifyList, ()>
    {
        // Create a modlist from this entry. We make this assuming we want the entry
        // to have this one as a subset of values. This means if we have single
        // values, we'll replace, if they are multivalue, we present them.
        //
        // We assume the schema validaty of the entry is already checked, and
        // normalisation performed.
        let mut mods = ModifyList::new();

        for (k, vs) in self.attrs.iter() {
            // Get the schema attribute type out.
            match schema.is_multivalue(k) {
                Ok(r) => {
                    if !r {
                        // As this is single value, purge then present to maintain this
                        // invariant
                        mods.push_mod(Modify::Purged(k.clone()));
                    }
                }
                Err(e) => {
                    return Err(())
                }
            }
            for v in vs {
                mods.push_mod(Modify::Present(k.clone(), v.clone()));
            }
        }

        Ok(mods)
    }

    // Should this be schemaless, relying on checks of the modlist, and the entry validate after?
    pub fn apply_modlist(&self, modlist: &ModifyList) -> Result<Entry, ()> {
        // Apply a modlist, generating a new entry that conforms to the changes.
        // This is effectively clone-and-transform

        // clone the entry
        let mut ne = self.clone();

        // mutate
        for modify in modlist.mods.iter() {
            match modify {
                Modify::Present(a, v) => {
                    ne.add_ava(a.clone(), v.clone())
                }
                Modify::Removed(a, v) => {
                    ne.remove_ava(a, v)
                }
                Modify::Purged(a) => {
                    ne.purge_ava(a)
                }
            }
        }

        // return it
        Ok(ne)
    }

    pub fn clone_no_attrs(&self) -> Entry {
        Entry {
            id: self.id,
            attrs: BTreeMap::new(),
        }
    }
}

impl Clone for Entry {
    fn clone(&self) -> Entry {
        Entry {
            id: self.id,
            attrs: self.attrs.clone(),
        }
    }
}

impl PartialEq for Entry {
    fn eq(&self, rhs: &Entry) -> bool {
        // FIXME: This is naive. Later it should be schema
        // aware checking.
        self.attrs == rhs.attrs
    }
}

// pub trait Entry {
//fn to_json_str(&self) -> String;
// fn to_index_diff -> ???
// from_json_str() -> Self;
//
// Does this match a filter or not?a
// fn apply_filter -> Result<bool, ()>
// }

//enum Credential {
//?
//}

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
    use super::{Entry, User};
    use modify::{Modify, ModifyList};
    use serde_json;

    #[test]
    fn test_entry_basic() {
        let mut e: Entry = Entry::new();

        e.add_ava(String::from("userid"), String::from("william"));

        let _d = serde_json::to_string_pretty(&e).unwrap();
    }

    #[test]
    fn test_entry_dup_value() {
        // Schema doesn't matter here because we are duplicating a value
        // it should fail!

        // We still probably need schema here anyway to validate what we
        // are adding ... Or do we validate after the changes are made in
        // total?
        let mut e: Entry = Entry::new();
        e.add_ava(String::from("userid"), String::from("william"));
        e.add_ava(String::from("userid"), String::from("william"));

        let values = e.get_ava(&String::from("userid")).unwrap();
        // Should only be one value!
        assert_eq!(values.len(), 1)
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry = Entry::new();
        e.add_ava(String::from("userid"), String::from("william"));

        assert!(e.attribute_pres("userid"));
        assert!(!e.attribute_pres("name"));
    }

    #[test]
    fn test_entry_equality() {
        let mut e: Entry = Entry::new();

        e.add_ava(String::from("userid"), String::from("william"));

        assert!(e.attribute_equality("userid", "william"));
        assert!(!e.attribute_equality("userid", "test"));
        assert!(!e.attribute_equality("nonexist", "william"));
    }

    #[test]
    fn test_entry_apply_modlist() {
        // Test application of changes to an entry.
        let mut e: Entry = Entry::new();
        e.add_ava(String::from("userid"), String::from("william"));

        let mods = ModifyList::new_list(vec![
            Modify::Present(String::from("attr"), String::from("value")),
        ]);

        let ne = e.apply_modlist(&mods).unwrap();

        // Assert the changes are there
        assert!(ne.attribute_equality("attr", "value"));


        // Assert present for multivalue
        // Assert purge on single/multi/empty value
        // Assert removed on value that exists and doesn't exist
    }
}

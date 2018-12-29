// use serde_json::{Error, Value};
use super::proto_v1::Entry as ProtoEntry;
use std::collections::btree_map::{Iter as BTreeIter, IterMut as BTreeIterMut};
use std::collections::BTreeMap;
use std::slice::Iter as SliceIter;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    attrs: BTreeMap<String, Vec<String>>,
}

impl Entry {
    pub fn new() -> Self {
        Entry {
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

    pub fn attribute_substring(&self, attr: &str, subvalue: &str) -> bool {
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

    // FIXME: Can we consume protoentry?
    pub fn from(e: &ProtoEntry) -> Self {
        // Why not the trait? In the future we may want to extend
        // this with server aware functions for changes of the
        // incoming data.
        Entry {
            // For now, we do a straight move
            attrs: e.attrs.clone(),
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
}

impl Clone for Entry {
    fn clone(&self) -> Entry {
        Entry {
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

impl User {
    pub fn new(username: &str, displayname: &str) -> Self {
        // Build a blank value
        User {
            username: String::from(username),
            class: Vec::new(),
            displayname: String::from(displayname),
            legalname: None,
            email: Vec::new(),
            memberof: Vec::new(),
            sshpublickey: Vec::new(),
            credentials: Vec::new(),
        }
    }

    // We need a way to "diff" two User objects
    // as on a modification we want to track the set of changes
    // that is occuring -- needed for indexing to function.

    // Basically we just need to check if it changed, remove
    // the "former" and add the "newer" value.

    // We have to sort vecs ...

    // Is there a way to call this on serialise?
    fn validate(&self) -> Result<(), ()> {
        // Given a schema, validate our object is sane.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, User};
    use serde_json;

    #[test]
    fn test_user_basic() {
        let u: User = User::new("william", "William Brown");
        let d = serde_json::to_string_pretty(&u).unwrap();

        let _u2: User = serde_json::from_str(d.as_str()).unwrap();
    }

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
}

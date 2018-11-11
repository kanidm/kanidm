// use serde_json::{Error, Value};
use std::collections::BTreeMap;

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
    pub fn add_ava(&mut self, attr: String, value: String) -> Result<(), ()> {
        // get_mut to access value
        self.attrs
            .entry(attr)
            .and_modify(|v| v.push(value.clone()))
            .or_insert(vec![value]);

        Ok(())
    }

    pub fn validate(&self) -> bool {
        // We need access to the current system schema here now ...
        true
    }

    pub fn pres(&self, attr: &str) -> bool {
        self.attrs.contains_key(attr)
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
    fn validate() -> Result<(), ()> {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, User};
    use serde_json;

    #[test]
    fn test_user_basic() {
        let u: User = User::new("william", "William Brown");

        println!("u: {:?}", u);

        let d = serde_json::to_string_pretty(&u).unwrap();

        println!("d: {}", d.as_str());

        let u2: User = serde_json::from_str(d.as_str()).unwrap();

        println!("u2: {:?}", u2);
    }

    #[test]
    fn test_entry_basic() {
        let mut e: Entry = Entry::new();

        e.add_ava(String::from("userid"), String::from("william"))
            .unwrap();

        assert!(e.validate());

        let d = serde_json::to_string_pretty(&e).unwrap();

        println!("d: {}", d.as_str());
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry = Entry::new();

        e.add_ava(String::from("userid"), String::from("william"))
            .unwrap();

        assert!(e.validate());

        assert!(e.pres("userid"));
        assert!(!e.pres("name"));
    }
}

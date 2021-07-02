use crate::value::IndexType;
use smartstring::alias::String as AttrString;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

pub type IdxSlope = u8;

// Huge props to https://github.com/sunshowers/borrow-complex-key-example/blob/master/src/lib.rs

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdxKey {
    pub attr: AttrString,
    pub itype: IndexType,
}

impl IdxKey {
    pub fn new(attr: &str, itype: IndexType) -> Self {
        IdxKey {
            attr: attr.into(),
            itype,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdxKeyRef<'a> {
    pub attr: &'a str,
    pub itype: &'a IndexType,
}

impl<'a> IdxKeyRef<'a> {
    pub fn new(attr: &'a str, itype: &'a IndexType) -> Self {
        IdxKeyRef { attr, itype }
    }

    pub fn to_key(&self) -> IdxKey {
        IdxKey {
            attr: self.attr.into(),
            itype: self.itype.clone(),
        }
    }
}

pub trait IdxKeyToRef {
    fn keyref(&self) -> IdxKeyRef<'_>;
}

impl<'a> IdxKeyToRef for IdxKeyRef<'a> {
    fn keyref(&self) -> IdxKeyRef<'_> {
        // Copy the self.
        *self
    }
}

impl IdxKeyToRef for IdxKey {
    fn keyref(&self) -> IdxKeyRef<'_> {
        IdxKeyRef {
            attr: self.attr.as_str(),
            itype: &self.itype,
        }
    }
}

impl<'a> Borrow<dyn IdxKeyToRef + 'a> for IdxKey {
    fn borrow(&self) -> &(dyn IdxKeyToRef + 'a) {
        self
    }
}

impl<'a> PartialEq for (dyn IdxKeyToRef + 'a) {
    fn eq(&self, other: &Self) -> bool {
        self.keyref().eq(&other.keyref())
    }
}

impl<'a> Eq for (dyn IdxKeyToRef + 'a) {}

impl<'a> Hash for (dyn IdxKeyToRef + 'a) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keyref().hash(state)
    }
}

// ===== idlcachekey ======

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdlCacheKey {
    pub a: AttrString,
    pub i: IndexType,
    pub k: String,
}

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdlCacheKeyRef<'a> {
    pub a: &'a str,
    pub i: &'a IndexType,
    pub k: &'a str,
}

/*
impl<'a> IdlCacheKeyRef<'a> {
    pub fn new(a: &'a str, i: &'a IndexType, k: &'a str) -> Self {
        IdlCacheKeyRef { a, i, k }
    }
}
*/

pub trait IdlCacheKeyToRef {
    fn keyref(&self) -> IdlCacheKeyRef<'_>;
}

impl<'a> IdlCacheKeyToRef for IdlCacheKeyRef<'a> {
    fn keyref(&self) -> IdlCacheKeyRef<'_> {
        // Copy the self
        *self
    }
}

impl IdlCacheKeyToRef for IdlCacheKey {
    fn keyref(&self) -> IdlCacheKeyRef<'_> {
        IdlCacheKeyRef {
            a: self.a.as_str(),
            i: &self.i,
            k: &self.k.as_str(),
        }
    }
}

impl<'a> Borrow<dyn IdlCacheKeyToRef + 'a> for IdlCacheKey {
    fn borrow(&self) -> &(dyn IdlCacheKeyToRef + 'a) {
        self
    }
}

impl<'a> PartialEq for (dyn IdlCacheKeyToRef + 'a) {
    fn eq(&self, other: &Self) -> bool {
        self.keyref().eq(&other.keyref())
    }
}

impl<'a> Eq for (dyn IdlCacheKeyToRef + 'a) {}

impl<'a> Hash for (dyn IdlCacheKeyToRef + 'a) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keyref().hash(state)
    }
}

impl<'a> PartialOrd for (dyn IdlCacheKeyToRef + 'a) {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.keyref().partial_cmp(&other.keyref())
    }
}

impl<'a> Ord for (dyn IdlCacheKeyToRef + 'a) {
    fn cmp(&self, other: &Self) -> Ordering {
        self.keyref().cmp(&other.keyref())
    }
}

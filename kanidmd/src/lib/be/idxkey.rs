use crate::value::IndexType;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

// Huge props to https://github.com/sunshowers/borrow-complex-key-example/blob/master/src/lib.rs

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdxKey {
    pub attr: String,
    pub itype: IndexType,
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
}

pub trait IdxKeyToRef {
    fn keyref<'k>(&'k self) -> IdxKeyRef<'k>;
}

impl<'a> IdxKeyToRef for IdxKeyRef<'a> {
    fn keyref<'k>(&'k self) -> IdxKeyRef<'k> {
        // Copy the self.
        *self
    }
}

impl IdxKeyToRef for IdxKey {
    fn keyref<'a>(&'a self) -> IdxKeyRef<'a> {
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
    pub a: String,
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
    fn keyref<'k>(&'k self) -> IdlCacheKeyRef<'k>;
}

impl<'a> IdlCacheKeyToRef for IdlCacheKeyRef<'a> {
    fn keyref<'k>(&'k self) -> IdlCacheKeyRef<'k> {
        // Copy the self
        *self
    }
}

impl IdlCacheKeyToRef for IdlCacheKey {
    fn keyref<'k>(&'k self) -> IdlCacheKeyRef<'k> {
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

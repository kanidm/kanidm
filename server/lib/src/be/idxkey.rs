use crate::prelude::entries::Attribute;
use crate::value::IndexType;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

pub type IdxSlope = u8;

// Huge props to https://github.com/sunshowers/borrow-complex-key-example/blob/master/src/lib.rs

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdxKey {
    pub attr: Attribute,
    pub itype: IndexType,
}

impl IdxKey {
    pub fn new(attr: Attribute, itype: IndexType) -> Self {
        IdxKey { attr, itype }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdxKeyRef<'a> {
    pub attr: &'a Attribute,
    pub itype: &'a IndexType,
}

impl<'a> IdxKeyRef<'a> {
    pub fn new(attr: &'a Attribute, itype: &'a IndexType) -> Self {
        IdxKeyRef { attr, itype }
    }

    pub fn as_key(&self) -> IdxKey {
        IdxKey {
            attr: self.attr.clone(),
            itype: *self.itype,
        }
    }
}

pub trait IdxKeyToRef {
    fn keyref(&self) -> IdxKeyRef<'_>;
}

impl IdxKeyToRef for IdxKeyRef<'_> {
    fn keyref(&self) -> IdxKeyRef<'_> {
        // Copy the self.
        *self
    }
}

impl IdxKeyToRef for IdxKey {
    fn keyref(&self) -> IdxKeyRef<'_> {
        IdxKeyRef {
            attr: &self.attr,
            itype: &self.itype,
        }
    }
}

impl<'a> Borrow<dyn IdxKeyToRef + 'a> for IdxKey {
    fn borrow(&self) -> &(dyn IdxKeyToRef + 'a) {
        self
    }
}

impl PartialEq for (dyn IdxKeyToRef + '_) {
    fn eq(&self, other: &Self) -> bool {
        self.keyref().eq(&other.keyref())
    }
}

impl Eq for (dyn IdxKeyToRef + '_) {}

impl Hash for (dyn IdxKeyToRef + '_) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keyref().hash(state)
    }
}

// ===== idlcachekey ======

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdlCacheKey {
    pub a: Attribute,
    pub i: IndexType,
    pub k: String,
}

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdlCacheKeyRef<'a> {
    pub a: &'a Attribute,
    pub i: IndexType,
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

impl IdlCacheKeyToRef for IdlCacheKeyRef<'_> {
    fn keyref(&self) -> IdlCacheKeyRef<'_> {
        // Copy the self
        *self
    }
}

impl IdlCacheKeyToRef for IdlCacheKey {
    fn keyref(&self) -> IdlCacheKeyRef<'_> {
        IdlCacheKeyRef {
            a: &self.a,
            i: self.i,
            k: self.k.as_str(),
        }
    }
}

impl<'a> Borrow<dyn IdlCacheKeyToRef + 'a> for IdlCacheKey {
    fn borrow(&self) -> &(dyn IdlCacheKeyToRef + 'a) {
        self
    }
}

impl PartialEq for (dyn IdlCacheKeyToRef + '_) {
    fn eq(&self, other: &Self) -> bool {
        self.keyref().eq(&other.keyref())
    }
}

impl Eq for (dyn IdlCacheKeyToRef + '_) {}

impl Hash for (dyn IdlCacheKeyToRef + '_) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keyref().hash(state)
    }
}

impl PartialOrd for (dyn IdlCacheKeyToRef + '_) {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other.keyref()))
    }
}

impl Ord for (dyn IdlCacheKeyToRef + '_) {
    fn cmp(&self, other: &Self) -> Ordering {
        self.keyref().cmp(&other.keyref())
    }
}

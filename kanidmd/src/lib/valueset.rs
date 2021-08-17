use crate::prelude::*;
// use hashbrown::HashSet;
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::iter::FromIterator;

pub struct ValueSet {
    inner: BTreeSet<Value>,
}

impl Default for ValueSet {
    fn default() -> Self {
        ValueSet {
            inner: BTreeSet::new(),
        }
    }
}

impl ValueSet {
    pub fn new() -> Self {
        Self::default()
    }

    // insert
    pub fn insert(&mut self, value: Value) -> bool {
        // Return true if the element is new.
        self.inner.insert(value)
    }

    // set values
    pub fn set(&mut self, iter: impl Iterator<Item = Value>) {
        self.inner.clear();
        self.inner.extend(iter);
    }

    pub fn get<Q>(&self, value: &Q) -> Option<&Value>
    where
        Value: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.inner.get(value)
    }

    // delete a value
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        Value: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.inner.remove(value)
    }

    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        Value: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.inner.contains(value)
    }

    pub fn substring(&self, value: &PartialValue) -> bool {
        self.inner.iter().any(|v| v.substring(value))
    }

    pub fn lessthan(&self, value: &PartialValue) -> bool {
        self.inner.iter().any(|v| v.lessthan(value))
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // We'll need to be able to do partialeq/intersect etc later.

    pub fn iter(&self) -> Iter {
        self.into_iter()
    }

    pub fn difference<'a>(&'a self, other: &'a ValueSet) -> Difference<'a> {
        Difference {
            iter: self.inner.difference(&other.inner),
        }
    }

    pub fn symmetric_difference<'a>(&'a self, other: &'a ValueSet) -> SymmetricDifference<'a> {
        SymmetricDifference {
            iter: self.inner.symmetric_difference(&other.inner),
        }
    }
}

impl PartialEq for ValueSet {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl FromIterator<Value> for ValueSet {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Value>,
    {
        ValueSet {
            inner: BTreeSet::from_iter(iter),
        }
    }
}

impl Clone for ValueSet {
    fn clone(&self) -> Self {
        ValueSet {
            inner: self.inner.clone(),
        }
    }
}

pub struct Iter<'a> {
    iter: std::collections::btree_set::Iter<'a, Value>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        self.iter.next()
    }
}

impl<'a> IntoIterator for &'a ValueSet {
    type Item = &'a Value;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Iter {
            iter: (&self.inner).iter(),
        }
    }
}

pub struct Difference<'a> {
    iter: std::collections::btree_set::Difference<'a, Value>,
}

impl<'a> Iterator for Difference<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        self.iter.next()
    }
}

pub struct SymmetricDifference<'a> {
    iter: std::collections::btree_set::SymmetricDifference<'a, Value>,
}

impl<'a> Iterator for SymmetricDifference<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        self.iter.next()
    }
}

pub struct IntoIter {
    iter: std::collections::btree_set::IntoIter<Value>,
}

impl Iterator for IntoIter {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        self.iter.next()
    }
}

impl IntoIterator for ValueSet {
    type Item = Value;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            iter: self.inner.into_iter(),
        }
    }
}

impl std::fmt::Debug for ValueSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValueSet")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::value::Value;
    use crate::valueset::ValueSet;

    #[test]
    fn test_valueset_basic() {
        let mut vs = ValueSet::new();
        assert!(vs.insert(Value::new_uint32(0)));
        assert!(!vs.insert(Value::new_uint32(0)));
    }
}

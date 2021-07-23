use crate::prelude::*;
// use hashbrown::HashSet;
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::iter::FromIterator;
use std::marker::PhantomData;

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
        unimplemented!();
    }

    // set values
    pub fn set(&mut self, values: impl Iterator<Item = Value>) {
        unimplemented!();
    }

    pub fn get<Q>(&self, value: &Q) -> Option<&Value>
    where
        Value: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        unimplemented!();
    }

    // delete a value
    pub fn remove(&mut self, value: &PartialValue) {
        unimplemented!();
    }

    pub fn contains(&self, value: &PartialValue) -> bool {
        unimplemented!();
    }

    pub fn substring(&self, value: &PartialValue) -> bool {
        unimplemented!();
    }

    pub fn lessthan(&self, value: &PartialValue) -> bool {
        unimplemented!();
    }

    pub fn len(&self) -> usize {
        unimplemented!();
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // We'll need to be able to do partialeq/intersect etc later.

    pub fn iter(&self) -> ValueSetIter {
        unimplemented!()
    }

    pub fn difference<'a>(&'a self, other: &'a ValueSet) -> Difference<'a> {
        unimplemented!()
    }

    pub fn symmetric_difference<'a>(&'a self, other: &'a ValueSet) -> SymmetricDifference<'a> {
        unimplemented!()
    }
}

impl PartialEq for ValueSet {
    fn eq(&self, other: &Self) -> bool {
        unimplemented!()
    }
}

impl FromIterator<Value> for ValueSet {
    fn from_iter<T>(iter: T) -> Self {
        unimplemented!()
    }
}

impl Clone for ValueSet {
    fn clone(&self) -> Self {
        unimplemented!()
    }
}

pub struct ValueSetIter<'a> {
    phantom: PhantomData<&'a Value>,
}

impl<'a> Iterator for ValueSetIter<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        unimplemented!()
    }
}

pub struct Difference<'a> {
    phantom: PhantomData<&'a Value>,
}

impl<'a> Iterator for Difference<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        unimplemented!()
    }
}

pub struct SymmetricDifference<'a> {
    phantom: PhantomData<&'a Value>,
}

impl<'a> Iterator for SymmetricDifference<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        unimplemented!()
    }
}

impl<'a> IntoIterator for &'a ValueSet {
    type Item = &'a Value;
    type IntoIter = ValueSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        unimplemented!()
    }
}

pub struct ValueSetIntoIter {}

impl Iterator for ValueSetIntoIter {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        unimplemented!()
    }
}

impl IntoIterator for ValueSet {
    type Item = Value;
    type IntoIter = ValueSetIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        unimplemented!()
    }
}

impl std::fmt::Debug for ValueSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    /*
    use crate::value::*;
    */
    use crate::valueset::*;

    #[test]
    fn test_valueset_basic() {
        unimplemented!();
    }
}

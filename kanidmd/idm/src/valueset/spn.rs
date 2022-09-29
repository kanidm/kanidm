use smolset::SmolSet;

use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetSpn {
    set: SmolSet<[(String, String); 1]>,
}

impl ValueSetSpn {
    pub fn new(u: (String, String)) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(u);
        Box::new(ValueSetSpn { set })
    }

    pub fn push(&mut self, u: (String, String)) -> bool {
        self.set.insert(u)
    }

    pub fn from_dbvs2(data: Vec<(String, String)>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetSpn { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, String)>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetSpn { set }))
    }
}

impl ValueSetT for ValueSetSpn {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Spn(n, d) => Ok(self.set.insert((n, d))),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Spn(n, d) => self.set.remove(&(n.clone(), d.clone())),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Spn(n, d) => self.set.contains(&(n.clone(), d.clone())),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set
            .iter()
            .map(|(n, d)| format!("{}@{}", n, d))
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::SecurityPrincipalName
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|(n, d)| format!("{}@{}", n, d)))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Spn(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .map(|(n, d)| PartialValue::Spn(n.clone(), d.clone())),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.set
                .iter()
                .map(|(n, d)| Value::Spn(n.clone(), d.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_spn_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_spn_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    /*
    fn to_spn_single(&self) -> Option<> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }
    */

    fn as_spn_set(&self) -> Option<&SmolSet<[(String, String); 1]>> {
        Some(&self.set)
    }

    /*
    fn as_spn_iter(&self) -> Option<Box<dyn Iterator<Item = Spn> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
    */
}

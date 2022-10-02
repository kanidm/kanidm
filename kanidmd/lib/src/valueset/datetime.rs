use smolset::SmolSet;
use time::OffsetDateTime;

use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetDateTime {
    set: SmolSet<[OffsetDateTime; 1]>,
}

impl ValueSetDateTime {
    pub fn new(b: OffsetDateTime) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetDateTime { set })
    }

    pub fn push(&mut self, b: OffsetDateTime) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data
            .into_iter()
            .map(|s| {
                OffsetDateTime::parse(s, time::Format::Rfc3339)
                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                    .map_err(|_| OperationError::InvalidValueState)
            })
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetDateTime { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and offset date time is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = OffsetDateTime>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetDateTime { set }))
    }
}

impl ValueSetT for ValueSetDateTime {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::DateTime(u) => Ok(self.set.insert(u)),
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
            PartialValue::DateTime(u) => self.set.remove(u),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::DateTime(u) => self.set.contains(u),
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
            .map(|odt| {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            })
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::DateTime
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|odt| {
            debug_assert!(odt.offset() == time::UtcOffset::UTC);
            odt.format(time::Format::Rfc3339)
        }))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::DateTime(
            self.set
                .iter()
                .map(|odt| {
                    debug_assert!(odt.offset() == time::UtcOffset::UTC);
                    odt.format(time::Format::Rfc3339)
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::DateTime))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::DateTime))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_datetime_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_datetime_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_datetime_single(&self) -> Option<OffsetDateTime> {
        if self.set.len() == 1 {
            self.set.iter().cloned().take(1).next()
        } else {
            None
        }
    }

    fn as_datetime_set(&self) -> Option<&SmolSet<[OffsetDateTime; 1]>> {
        Some(&self.set)
    }
}

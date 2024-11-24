use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{
    DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut,
};
use kanidm_proto::scim_v1::{client::ScimDateTime, JsonValue};
use smolset::SmolSet;
use time::OffsetDateTime;

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
                OffsetDateTime::parse(&s, &Rfc3339)
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

impl ValueSetScimPut for ValueSetDateTime {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let ScimDateTime { date_time } = serde_json::from_value(value).map_err(|err| {
            error!(?err, "SCIM DateTime syntax invalid");
            OperationError::SC0010DateTimeSyntaxInvalid
        })?;

        let mut set = SmolSet::new();
        set.insert(date_time);

        Ok(ValueSetResolveStatus::Resolved(Box::new(
            ValueSetDateTime { set },
        )))
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
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
                debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                #[allow(clippy::expect_used)]
                odt.format(&Rfc3339)
                    .expect("Failed to format timestamp into RFC3339")
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
            debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
            #[allow(clippy::expect_used)]
            odt.format(&Rfc3339)
                .expect("Failed to format timestamp into RFC3339")
        }))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        self.set.iter().next().copied().map(|v| v.into())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::DateTime(
            self.set
                .iter()
                .map(|odt| {
                    debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                    #[allow(clippy::expect_used)]
                    odt.format(&Rfc3339)
                        .expect("Failed to format timestamp into RFC3339")
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

#[cfg(test)]
mod tests {
    use super::ValueSetDateTime;
    use crate::prelude::ValueSet;
    use std::time::Duration;
    use time::OffsetDateTime;

    #[test]
    fn test_scim_datetime() {
        let odt = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(69_420);
        let vs: ValueSet = ValueSetDateTime::new(odt);

        crate::valueset::scim_json_reflexive(vs.clone(), r#""1970-01-01T19:17:00Z""#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetDateTime>(vs, &[])
    }
}

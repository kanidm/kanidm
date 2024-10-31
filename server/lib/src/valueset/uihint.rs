use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{
    DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut,
};
use kanidm_proto::internal::UiHint;
use kanidm_proto::scim_v1::JsonValue;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetUiHint {
    set: BTreeSet<UiHint>,
}

impl ValueSetUiHint {
    pub fn new(s: UiHint) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s);
        Box::new(ValueSetUiHint { set })
    }

    pub fn push(&mut self, s: UiHint) -> bool {
        self.set.insert(s)
    }

    pub fn from_dbvs2(data: Vec<u16>) -> Result<ValueSet, OperationError> {
        let set: Result<_, _> = data.into_iter().map(UiHint::try_from).collect();
        let set = set.map_err(|_| OperationError::InvalidValueState)?;
        Ok(Box::new(ValueSetUiHint { set }))
    }
}

impl ValueSetScimPut for ValueSetUiHint {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value = serde_json::from_value::<Vec<UiHint>>(value).map_err(|err| {
            error!(?err, "SCIM UiHint syntax invalid");
            OperationError::SC0025UiHintSyntaxInvalid
        })?;

        let set = value.into_iter().collect();

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetUiHint {
            set,
        })))
    }
}

impl ValueSetT for ValueSetUiHint {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::UiHint(s) => Ok(self.set.insert(s)),
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::UiHint(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::UiHint(s) => self.set.contains(s),
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
        self.set.iter().map(|u| (*u as u16).to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::UiHint
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|u| u.to_string()))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.set.iter().copied().collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::UiHint(self.set.iter().map(|u| *u as u16).collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::UiHint))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::UiHint))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_uihint_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_uihint_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_uihint_set(&self) -> Option<&BTreeSet<UiHint>> {
        Some(&self.set)
    }

    fn as_uihint_iter(&self) -> Option<Box<dyn Iterator<Item = UiHint> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
}

#[cfg(test)]
mod tests {
    use super::{UiHint, ValueSetUiHint};
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_uihint() {
        let vs: ValueSet = ValueSetUiHint::new(UiHint::PosixAccount);
        crate::valueset::scim_json_reflexive(vs.clone(), r#"["posixaccount"]"#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetUiHint>(vs, &[])
    }
}

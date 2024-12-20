use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::{
    DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut,
};
use kanidm_proto::scim_v1::JsonValue;
use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetSyntax {
    set: SmolSet<[SyntaxType; 1]>,
}

impl ValueSetSyntax {
    pub fn new(s: SyntaxType) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(s);
        Box::new(ValueSetSyntax { set })
    }

    pub fn push(&mut self, s: SyntaxType) -> bool {
        self.set.insert(s)
    }

    pub fn from_dbvs2(data: Vec<u16>) -> Result<ValueSet, OperationError> {
        let set: Result<_, _> = data.into_iter().map(SyntaxType::try_from).collect();
        let set = set.map_err(|_| OperationError::InvalidValueState)?;
        Ok(Box::new(ValueSetSyntax { set }))
    }
}

impl ValueSetScimPut for ValueSetSyntax {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value = serde_json::from_value::<String>(value)
            .map_err(|err| {
                error!(?err, "SCIM SyntaxType syntax invalid");
                OperationError::SC0008SyntaxTypeSyntaxInvalid
            })
            .and_then(|value| {
                SyntaxType::try_from(value.as_str()).map_err(|()| {
                    error!("SCIM SyntaxType syntax invalid - value");
                    OperationError::SC0008SyntaxTypeSyntaxInvalid
                })
            })?;

        let mut set = SmolSet::new();
        set.insert(value);

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetSyntax {
            set,
        })))
    }
}

impl FromIterator<SyntaxType> for Option<Box<ValueSetSyntax>> {
    fn from_iter<T>(iter: T) -> Option<Box<ValueSetSyntax>>
    where
        T: IntoIterator<Item = SyntaxType>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetSyntax { set }))
    }
}

impl ValueSetT for ValueSetSyntax {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Syntax(u) => Ok(self.set.insert(u)),
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
            PartialValue::Syntax(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Syntax(u) => self.set.contains(u),
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
        self.set.iter().map(|b| b.to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::SyntaxId
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|b| b.to_string()))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        self.set
            .iter()
            .next()
            .map(|u| ScimResolveStatus::Resolved(ScimValueKanidm::from(u.to_string())))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::SyntaxType(self.set.iter().map(|s| *s as u16).collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Syntax))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Syntax))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_syntax_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_syntax_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_syntaxtype_single(&self) -> Option<SyntaxType> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_syntax_set(&self) -> Option<&SmolSet<[SyntaxType; 1]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetSyntax;
    use crate::prelude::{SyntaxType, ValueSet};

    #[test]
    fn test_scim_syntax() {
        let vs: ValueSet = ValueSetSyntax::new(SyntaxType::Uuid);
        crate::valueset::scim_json_reflexive(vs.clone(), r#""UUID""#);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetSyntax>(vs, &[])
    }
}

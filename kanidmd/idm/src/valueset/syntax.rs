use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::DbValueSetV2;
use crate::valueset::ValueSet;
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
        let set = set.map_err(|()| OperationError::InvalidValueState)?;
        Ok(Box::new(ValueSetSyntax { set }))
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

    fn remove(&mut self, pv: &PartialValue) -> bool {
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

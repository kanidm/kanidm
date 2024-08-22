use smolset::SmolSet;

use crate::prelude::*;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetUrl {
    set: SmolSet<[Url; 1]>,
}

impl ValueSetUrl {
    pub fn new(b: Url) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetUrl { set })
    }

    pub fn push(&mut self, b: Url) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<Url>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetUrl { set }))
    }

    pub fn from_repl_v1(data: &[Url]) -> Result<ValueSet, OperationError> {
        let set = data.iter().cloned().collect();
        Ok(Box::new(ValueSetUrl { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and Url is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Url>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetUrl { set }))
    }
}

impl ValueSetT for ValueSetUrl {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Url(u) => Ok(self.set.insert(u)),
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
            PartialValue::Url(u) => self.set.remove(u),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Url(u) => self.set.contains(u),
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
        self.set.iter().map(|u| u.to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Url
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|i| i.to_string()))
    }

    fn to_scim_value(&self) -> Option<ScimValue> {
        if self.len() == 1 {
            let v = self
                .set
                .iter()
                .next()
                .map(|url| url.to_string())
                .unwrap_or_default();
            Some(ScimAttr::String(v).into())
        } else {
            Some(ScimValue::MultiSimple(
                self.set.iter().map(|url| url.to_string().into()).collect(),
            ))
        }
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Url(self.set.iter().cloned().collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Url {
            set: self.set.iter().cloned().collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::Url))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::Url))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_url_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_url_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_url_single(&self) -> Option<&Url> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next()
        } else {
            None
        }
    }

    fn as_url_set(&self) -> Option<&SmolSet<[Url; 1]>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetUrl;
    use crate::prelude::{ScimValue, Url, ValueSet};

    #[test]
    fn test_scim_url() {
        let u = Url::parse("https://idm.example.com").unwrap();
        let vs: ValueSet = ValueSetUrl::new(u);

        let scim_value = vs.to_scim_value().unwrap();

        let strout = serde_json::to_string_pretty(&scim_value).unwrap();
        eprintln!("{}", strout);

        let expect: ScimValue = serde_json::from_str(r#""https://idm.example.com/""#).unwrap();
        assert_eq!(scim_value, expect);
    }
}

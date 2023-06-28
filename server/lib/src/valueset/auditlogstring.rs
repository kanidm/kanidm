use smolset::SmolSet;

use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::repl::proto::ReplAttrV1;
use crate::schema::SchemaAttribute;
use crate::valueset::{DbValueSetV2, ValueSet};

type AuditLogStringType = (Cid, String);

#[derive(Debug, Clone)]
pub struct ValueSetAuditLogString {
    set: SmolSet<[AuditLogStringType; 8]>,
}

impl ValueSetAuditLogString {
    fn remove_oldest(&mut self) {
        let oldest = self.set.iter().min().cloned();
        if let Some(oldest_value) = oldest {
            self.set.remove(&oldest_value);
        }
    }

    pub fn new(s: AuditLogStringType) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(s);
        Box::new(ValueSetAuditLogString { set })
    }

    pub fn push(&mut self, s: AuditLogStringType) -> bool {
        self.set.insert(s)
    }

    pub fn from_dbvs2(data: Vec<AuditLogStringType>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetAuditLogString { set }))
    }

    pub fn from_repl_v1(data: &[AuditLogStringType]) -> Result<ValueSet, OperationError> {
        let set = data.iter().map(|e| (e.0.clone(), e.1.clone())).collect();
        Ok(Box::new(ValueSetAuditLogString { set }))
    }
}

impl ValueSetT for ValueSetAuditLogString {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::AuditLogString(c, s) => {
                if self.set.len() >= 8 {
                    self.remove_oldest();
                }
                Ok(self.push((c, s)))
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, _pv: &PartialValue) -> bool {
        false
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(s) => self.set.iter().any(|(_, current)| s.eq(current)),
            _ => {
                debug_assert!(false);
                true
            }
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
        self.set.iter().map(|(d, s)| format!("{d}-{s}")).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::AuditLogString
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set
            .iter()
            .all(|(_, s)| Value::validate_str_escapes(s) && Value::validate_singleline(s))
            && self.set.len() <= 8
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|(d, s)| format!("{d}-{s}")))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::AuditLogString(self.set.iter().cloned().collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::AuditLogString {
            set: self.set.iter().cloned().collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().map(|(_, s)| PartialValue::Utf8(s.clone())))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.set
                .iter()
                .map(|(c, s)| Value::AuditLogString(c.clone(), s.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_audit_log_string() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_audit_log_string() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }
    fn as_audit_log_string(&self) -> Option<&SmolSet<[(Cid, String); 8]>> {
        Some(&self.set)
    }
}

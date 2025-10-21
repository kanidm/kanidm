use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::valueset::ScimResolveStatus;
use crate::valueset::{DbValueSetV2, ValueSet};
use kanidm_proto::v1::OutboundMessage;

#[derive(Debug, Clone)]
pub struct ValueSetMessage {
    message: OutboundMessage,
}

impl ValueSetMessage {
    pub fn new(message: OutboundMessage) -> Box<Self> {
        Box::new(ValueSetMessage { message })
    }
}

impl ValueSetT for ValueSetMessage {
    fn insert_checked(&mut self, _value: Value) -> Result<bool, OperationError> {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn clear(&mut self) {
        debug_assert!(false);
    }

    fn remove(&mut self, _pv: &PartialValue, _cid: &Cid) -> bool {
        debug_assert!(false);
        false
    }

    fn contains(&self, _pv: &PartialValue) -> bool {
        false
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
        1
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Message
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(std::iter::empty())
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.message.clone(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Message(self.message.clone())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(std::iter::empty())
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(std::iter::empty())
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_message() {
            &self.message == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, _other: &ValueSet) -> Result<(), OperationError> {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn as_message(&self) -> Option<&OutboundMessage> {
        Some(&self.message)
    }
}

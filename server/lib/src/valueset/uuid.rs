use crate::{
    prelude::*,
    schema::SchemaAttribute,
    valueset::{
        uuid_to_proto_string, DbValueSetV2, ScimResolveStatus, ScimValueIntermediate,
        UnresolvedReferenceState, ValueSet, ValueSetIntermediate, ValueSetResolveStatus,
        ValueSetScimPut,
    },
};
use kanidm_proto::scim_v1::JsonValue;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetUuidN {
    set: BTreeSet<Uuid>,
}

impl ValueSetUuidN {
    pub fn new(u: Uuid) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(u);
        Box::new(ValueSetUuidN { set })
    }

    pub fn from_dbvs2(data: Vec<Uuid>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetUuidN { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and uuid is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Uuid>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetUuidN { set }))
    }
}

impl ValueSetScimPut for ValueSetUuidN {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let set: BTreeSet<Uuid> = serde_json::from_value(value).map_err(|err| {
            warn!(?err, "Invalid SCIM Uuid syntax");
            OperationError::SC0004UuidSyntaxInvalid
        })?;

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetUuidN {
            set,
        })))
    }
}

impl ValueSetT for ValueSetUuidN {
    fn migrate(&self) -> Result<Option<ValueSet>, OperationError> {
        Ok(self
            .to_uuid_single()
            .map(|uuid| Box::new(ValueSetUuid { uuid }) as ValueSet))
    }

    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Uuid(u) => Ok(self.set.insert(u)),
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
            PartialValue::Uuid(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.set.contains(u),
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

    fn lessthan(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.set.iter().any(|v| v < u),
            _ => false,
        }
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set
            .iter()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::UuidN
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().copied().map(uuid_to_proto_string))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::ArrayUuid(
            self.set.iter().copied().collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Uuid(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Uuid))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Uuid))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_uuid_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_uuid_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_uuid_single(&self) -> Option<Uuid> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_uuid_set(&self) -> Option<&BTreeSet<Uuid>> {
        Some(&self.set)
    }

    /*
    fn as_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
    */
}

#[derive(Debug, Clone)]
pub struct ValueSetUuid {
    uuid: Uuid,
}

impl ValueSetUuid {
    pub fn new(uuid: Uuid) -> Box<Self> {
        Box::new(ValueSetUuid { uuid })
    }

    pub fn from_dbvs2(uuid: Uuid) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetUuid { uuid }))
    }
}

impl ValueSetScimPut for ValueSetUuid {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let uuid: Uuid = serde_json::from_value(value).map_err(|err| {
            warn!(?err, "Invalid SCIM Uuid syntax");
            OperationError::SC0034UuidSyntaxInvalid
        })?;

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetUuid {
            uuid,
        })))
    }
}

impl ValueSetT for ValueSetUuid {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Uuid(u) => {
                if self.uuid != u {
                    self.uuid = u;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        debug_assert!(false);
        // NO-OP
        // self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            // If we return true, then the whole ava is removed on the entry.
            PartialValue::Uuid(u) => *u == self.uuid,
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => *u == self.uuid,
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

    fn lessthan(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Uuid(u) => self.uuid < *u,
            _ => false,
        }
    }

    fn len(&self) -> usize {
        1
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        std::iter::once(self.uuid.as_hyphenated().to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Uuid
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(std::iter::once(self.uuid).map(uuid_to_proto_string))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::Uuid(
            self.uuid,
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::UuidSingle(self.uuid)
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(std::iter::once(self.uuid).map(PartialValue::Uuid))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(std::iter::once(self.uuid).map(Value::Uuid))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.to_uuid_single() {
            self.uuid == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, _other: &ValueSet) -> Result<(), OperationError> {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
    }

    fn to_uuid_single(&self) -> Option<Uuid> {
        Some(self.uuid)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetReferN {
    set: BTreeSet<Uuid>,
}

impl ValueSetReferN {
    pub fn new(u: Uuid) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(u);
        Box::new(ValueSetReferN { set })
    }

    pub fn push(&mut self, u: Uuid) -> bool {
        self.set.insert(u)
    }

    pub fn from_dbvs2(data: Vec<Uuid>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetReferN { set }))
    }

    pub fn from_repl_v1(data: &[Uuid]) -> Result<ValueSet, OperationError> {
        let set = data.iter().copied().collect();
        Ok(Box::new(ValueSetReferN { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and uuid is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = Uuid>,
    {
        let set: BTreeSet<_> = iter.into_iter().collect();
        if set.is_empty() {
            None
        } else {
            Some(Box::new(ValueSetReferN { set }))
        }
    }

    pub(crate) fn from_set(set: BTreeSet<Uuid>) -> ValueSet {
        Box::new(ValueSetReferN { set })
    }
}

impl ValueSetScimPut for ValueSetReferN {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        use kanidm_proto::scim_v1::client::{ScimReference, ScimReferences};

        // May be a single reference, lets wrap it in an array to proceed.
        let value = if !value.is_array() && value.is_object() {
            JsonValue::Array(vec![value])
        } else {
            value
        };

        let scim_refs: ScimReferences = serde_json::from_value(value).map_err(|err| {
            warn!(?err, "Invalid SCIM reference set syntax");
            OperationError::SC0002ReferenceSyntaxInvalid
        })?;

        let unresolved = scim_refs
            .into_iter()
            .map(|scim_ref| match scim_ref {
                ScimReference {
                    uuid: None,
                    value: None,
                } => {
                    warn!("Invalid SCIM reference set syntax, uuid and value are both unset.");
                    Err(OperationError::SC0002ReferenceSyntaxInvalid)
                }
                ScimReference {
                    uuid: Some(uuid),
                    value: Some(value),
                } => Ok(UnresolvedReferenceState::Complete { uuid, value }),
                ScimReference {
                    uuid: Some(uuid),
                    value: None,
                } => Ok(UnresolvedReferenceState::Uuid(uuid)),
                ScimReference {
                    uuid: None,
                    value: Some(value),
                } => Ok(UnresolvedReferenceState::Value(value)),
            })
            .collect::<Result<Vec<_>, _>>()?;

        // We may not actually need to resolve anything, but to make tests easier we
        // always return that we need resolution.
        Ok(ValueSetResolveStatus::NeedsResolution(
            ValueSetIntermediate::References { unresolved },
        ))
    }
}

impl ValueSetT for ValueSetReferN {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Refer(u) => Ok(self.set.insert(u)),
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
            PartialValue::Refer(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.set.contains(u),
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

    fn lessthan(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.set.iter().any(|v| v < u),
            _ => false,
        }
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set
            .iter()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::ReferenceUuidN
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().copied().map(uuid_to_proto_string))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        let uuids = self.set.iter().copied().collect::<Vec<_>>();
        Some(ScimResolveStatus::NeedsResolution(
            ScimValueIntermediate::References(uuids),
        ))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Reference(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::Refer))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_refer_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_refer_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_refer_single(&self) -> Option<Uuid> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_refer_set(&self) -> Option<&BTreeSet<Uuid>> {
        Some(&self.set)
    }

    fn as_refer_set_mut(&mut self) -> Option<&mut BTreeSet<Uuid>> {
        Some(&mut self.set)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetRefer {
    uuid: Uuid,
}

impl ValueSetRefer {
    pub fn new(uuid: Uuid) -> Box<Self> {
        Box::new(ValueSetRefer { uuid })
    }

    pub fn from_dbvs2(uuid: Uuid) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetRefer { uuid }))
    }
}

impl ValueSetScimPut for ValueSetRefer {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        use kanidm_proto::scim_v1::client::ScimReference;

        let scim_ref: ScimReference = serde_json::from_value(value).map_err(|err| {
            warn!(?err, "Invalid SCIM reference set syntax");
            OperationError::SC0002ReferenceSyntaxInvalid
        })?;

        match scim_ref {
            ScimReference {
                uuid: None,
                value: None,
            } => {
                warn!("Invalid SCIM reference set syntax, uuid and value are both unset.");
                return Err(OperationError::SC0002ReferenceSyntaxInvalid);
            }
            ScimReference {
                uuid: Some(uuid),
                value: Some(value),
            } => Ok(ValueSetResolveStatus::NeedsResolution(
                ValueSetIntermediate::Reference(UnresolvedReferenceState::Complete { uuid, value }),
            )),

            ScimReference {
                uuid: Some(uuid),
                value: None,
            } => Ok(ValueSetResolveStatus::NeedsResolution(
                ValueSetIntermediate::Reference(UnresolvedReferenceState::Uuid(uuid)),
            )),
            ScimReference {
                uuid: None,
                value: Some(value),
            } => Ok(ValueSetResolveStatus::NeedsResolution(
                ValueSetIntermediate::Reference(UnresolvedReferenceState::Value(value)),
            )),
        }
    }
}

impl ValueSetT for ValueSetRefer {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Refer(u) => {
                if self.uuid != u {
                    self.uuid = u;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        debug_assert!(false);
        // NO-OP
        // self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            // If we return true, then the whole ava is removed on the entry.
            PartialValue::Refer(u) => *u == self.uuid,
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => *u == self.uuid,
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

    fn lessthan(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.uuid < *u,
            _ => false,
        }
    }

    fn len(&self) -> usize {
        1
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        std::iter::once(self.uuid.as_hyphenated().to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::ReferenceUuid
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(std::iter::once(self.uuid).map(uuid_to_proto_string))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::NeedsResolution(
            ScimValueIntermediate::Reference(self.uuid),
        ))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::ReferenceSingle(self.uuid)
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(std::iter::once(self.uuid).map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(std::iter::once(self.uuid).map(Value::Refer))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.to_refer_single() {
            self.uuid == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(other) = other.to_refer_single() {
            self.uuid = other;
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_refer_single(&self) -> Option<Uuid> {
        Some(self.uuid)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        Some(Box::new(std::iter::once(self.uuid)))
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueSetRefer, ValueSetReferN, ValueSetUuid, ValueSetUuidN};
    use crate::prelude::*;

    #[test]
    fn test_scim_uuid_single() {
        let vs: ValueSet = ValueSetUuid::new(uuid::uuid!("4d21d04a-dc0e-42eb-b850-34dd180b107f"));

        let data = r#""4d21d04a-dc0e-42eb-b850-34dd180b107f""#;

        crate::valueset::scim_json_reflexive(&vs, data);

        crate::valueset::scim_json_put_reflexive::<ValueSetUuid>(&vs, &[])
    }

    #[test]
    fn test_scim_uuid_multi() {
        let vs: ValueSet = ValueSetUuidN::new(uuid::uuid!("4d21d04a-dc0e-42eb-b850-34dd180b107f"));

        let data = r#"["4d21d04a-dc0e-42eb-b850-34dd180b107f"]"#;

        crate::valueset::scim_json_reflexive(&vs, data);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetUuidN>(&vs, &[])
    }

    #[qs_test]
    async fn test_scim_refer_multi(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let t_uuid = uuid::uuid!("4d21d04a-dc0e-42eb-b850-34dd180b107f");
        assert!(write_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(t_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            ),])
            .is_ok());

        let vs: ValueSet = ValueSetReferN::new(t_uuid);

        let data = r#"[{"uuid": "4d21d04a-dc0e-42eb-b850-34dd180b107f", "value": "testperson1@example.com"}]"#;

        crate::valueset::scim_json_reflexive_unresolved(&mut write_txn, &vs, data);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive_unresolved::<ValueSetReferN>(
            &mut write_txn,
            &vs,
            &[],
        );

        assert!(write_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_scim_refer_single(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let t_uuid = uuid::uuid!("4d21d04a-dc0e-42eb-b850-34dd180b107f");
        assert!(write_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(t_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            ),])
            .is_ok());

        let vs: ValueSet = ValueSetRefer::new(t_uuid);

        let data = r#"{"uuid": "4d21d04a-dc0e-42eb-b850-34dd180b107f", "value": "testperson1@example.com"}"#;

        crate::valueset::scim_json_reflexive_unresolved(&mut write_txn, &vs, data);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive_unresolved::<ValueSetRefer>(
            &mut write_txn,
            &vs,
            &[],
        );

        assert!(write_txn.commit().is_ok());
    }
}

use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::be::dbvalue::{DbValueAccessScopeV1, DbValueIdentityId, DbValueSession};
use crate::identity::{AccessScope, IdentityId};
use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::value::Session;
use crate::valueset::{uuid_to_proto_string, DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetSession {
    map: BTreeMap<Uuid, Session>,
}

impl ValueSetSession {
    pub fn new(u: Uuid, m: Session) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, m);
        Box::new(ValueSetSession { map })
    }

    pub fn push(&mut self, u: Uuid, m: Session) -> bool {
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueSession>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .filter_map(|dbv| {
                match dbv {
                    DbValueSession::V1 {
                        refer,
                        label,
                        expiry,
                        issued_at,
                        issued_by,
                        scope,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(issued_at, time::Format::Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        // This is a bit annoying. In the case we can't parse the optional
                        // expiry, we need to NOT return the session so that it's immediately
                        // invalidated. To do this we have to invert some of the options involved
                        // here.
                        let expiry = expiry
                            .map(|e_inner| {
                                OffsetDateTime::parse(e_inner, time::Format::Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                // We now have an
                                // Option<Result<ODT, _>>
                            })
                            .transpose()
                            // Result<Option<ODT>, _>
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid expiry timestamp",
                                    refer
                                )
                            })
                            // Option<Option<ODT>>
                            .ok()?;

                        let issued_by = match issued_by {
                            DbValueIdentityId::V1Internal => IdentityId::Internal,
                            DbValueIdentityId::V1Uuid(u) => IdentityId::User(u),
                        };

                        let scope = match scope {
                            DbValueAccessScopeV1::IdentityOnly => AccessScope::IdentityOnly,
                            DbValueAccessScopeV1::ReadOnly => AccessScope::ReadOnly,
                            DbValueAccessScopeV1::ReadWrite => AccessScope::ReadWrite,
                            DbValueAccessScopeV1::Synchronise => AccessScope::Synchronise,
                        };

                        Some((
                            refer,
                            Session {
                                label,
                                expiry,
                                issued_at,
                                issued_by,
                                scope,
                            },
                        ))
                    }
                }
            })
            .collect();
        Ok(Box::new(ValueSetSession { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, Session)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetSession { map }))
    }
}

impl ValueSetT for ValueSetSession {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Session(u, m) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(m);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.contains_key(u),
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
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Session
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| format!("{}: {:?}", uuid_to_proto_string(*u), m)),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Session(
            self.map
                .iter()
                .map(|(u, m)| DbValueSession::V1 {
                    refer: *u,
                    label: m.label.clone(),
                    expiry: m.expiry.map(|odt| {
                        debug_assert!(odt.offset() == time::UtcOffset::UTC);
                        odt.format(time::Format::Rfc3339)
                    }),
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        m.issued_at.format(time::Format::Rfc3339)
                    },
                    issued_by: match m.issued_by {
                        IdentityId::Internal => DbValueIdentityId::V1Internal,
                        IdentityId::User(u) => DbValueIdentityId::V1Uuid(u),
                    },
                    scope: match m.scope {
                        AccessScope::IdentityOnly => DbValueAccessScopeV1::IdentityOnly,
                        AccessScope::ReadOnly => DbValueAccessScopeV1::ReadOnly,
                        AccessScope::ReadWrite => DbValueAccessScopeV1::ReadWrite,
                        AccessScope::Synchronise => DbValueAccessScopeV1::Synchronise,
                    },
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.iter().map(|(u, m)| Value::Session(*u, m.clone())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_session_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_session_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_session_map(&self) -> Option<&BTreeMap<Uuid, Session>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(self.map.keys().copied()))
    }
}

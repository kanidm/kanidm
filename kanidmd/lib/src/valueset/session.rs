use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;

use crate::be::dbvalue::{
    DbValueAccessScopeV1, DbValueIdentityId, DbValueOauth2Session, DbValueSession,
    DbValueApiToken, DbValueApiTokenScopeV1
};
use crate::prelude::*;
use crate::repl::proto::{
    ReplSessionScopeV1, ReplAttrV1, ReplIdentityIdV1, ReplOauth2SessionV1, ReplSessionV1,
    ReplApiTokenV1, ReplApiTokenScopeV1,
};
use crate::schema::SchemaAttribute;
use crate::value::{Oauth2Session, Session, ApiToken, SessionScope, ApiTokenScope};
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
        let map =
            data.into_iter()
                .filter_map(|dbv| {
                    match dbv {
                        // MISTAKE - Skip due to lack of credential id
                        // Don't actually skip, generate a random cred id. Session cleanup will
                        // trim sessions on users, but if we skip blazenly we invalidate every api
                        // token ever issued. OPPS!
                        DbValueSession::V1 {
                            refer,
                            label,
                            expiry,
                            issued_at,
                            issued_by,
                            scope,
                        } => {
                            let cred_id = Uuid::new_v4();

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
                                DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                            };

                            let scope = match scope {
                                DbValueAccessScopeV1::IdentityOnly
                                | DbValueAccessScopeV1::ReadOnly => SessionScope::ReadOnly,
                                DbValueAccessScopeV1::ReadWrite => SessionScope::ReadWrite,
                                DbValueAccessScopeV1::PrivilegeCapable => SessionScope::PrivilegeCapable,
                                DbValueAccessScopeV1::Synchronise => SessionScope::Synchronise,
                            };

                            Some((
                                refer,
                                Session {
                                    label,
                                    expiry,
                                    issued_at,
                                    issued_by,
                                    cred_id,
                                    scope,
                                },
                            ))
                        }
                        DbValueSession::V2 {
                            refer,
                            label,
                            expiry,
                            issued_at,
                            issued_by,
                            cred_id,
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
                                DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                            };

                            let scope = match scope {
                                DbValueAccessScopeV1::IdentityOnly
                                | DbValueAccessScopeV1::ReadOnly => SessionScope::ReadOnly,
                                DbValueAccessScopeV1::ReadWrite => SessionScope::ReadWrite,
                                DbValueAccessScopeV1::PrivilegeCapable => SessionScope::PrivilegeCapable,
                                DbValueAccessScopeV1::Synchronise => SessionScope::Synchronise,
                            };

                            Some((
                                refer,
                                Session {
                                    label,
                                    expiry,
                                    issued_at,
                                    issued_by,
                                    cred_id,
                                    scope,
                                },
                            ))
                        }
                    }
                })
                .collect();
        Ok(Box::new(ValueSetSession { map }))
    }

    pub fn from_repl_v1(data: &[ReplSessionV1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .filter_map(
                |ReplSessionV1 {
                     refer,
                     label,
                     expiry,
                     issued_at,
                     issued_by,
                     cred_id,
                     scope,
                 }| {
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
                        .as_ref()
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
                        ReplIdentityIdV1::Internal => IdentityId::Internal,
                        ReplIdentityIdV1::Uuid(u) => IdentityId::User(*u),
                        ReplIdentityIdV1::Synch(u) => IdentityId::Synch(*u),
                    };

                    let scope = match scope {
                        ReplSessionScopeV1::ReadOnly => SessionScope::ReadOnly,
                        ReplSessionScopeV1::ReadWrite => SessionScope::ReadWrite,
                        ReplSessionScopeV1::PrivilegeCapable => SessionScope::PrivilegeCapable,
                        ReplSessionScopeV1::Synchronise => SessionScope::Synchronise,
                    };

                    Some((
                        *refer,
                        Session {
                            label: label.to_string(),
                            expiry,
                            issued_at,
                            issued_by,
                            cred_id: *cred_id,
                            scope,
                        },
                    ))
                },
            )
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
                .map(|(u, m)| DbValueSession::V2 {
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
                        IdentityId::Synch(u) => DbValueIdentityId::V1Sync(u),
                    },
                    cred_id: m.cred_id,
                    scope: match m.scope {
                        SessionScope::ReadOnly => DbValueAccessScopeV1::ReadOnly,
                        SessionScope::ReadWrite => DbValueAccessScopeV1::ReadWrite,
                        SessionScope::PrivilegeCapable => DbValueAccessScopeV1::PrivilegeCapable,
                        SessionScope::Synchronise => DbValueAccessScopeV1::Synchronise,
                    },
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Session {
            set: self
                .map
                .iter()
                .map(|(u, m)| ReplSessionV1 {
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
                        IdentityId::Internal => ReplIdentityIdV1::Internal,
                        IdentityId::User(u) => ReplIdentityIdV1::Uuid(u),
                        IdentityId::Synch(u) => ReplIdentityIdV1::Synch(u),
                    },
                    cred_id: m.cred_id,
                    scope: match m.scope {
                        SessionScope::ReadOnly => ReplSessionScopeV1::ReadOnly,
                        SessionScope::ReadWrite => ReplSessionScopeV1::ReadWrite,
                        SessionScope::PrivilegeCapable => ReplSessionScopeV1::PrivilegeCapable,
                        SessionScope::Synchronise => ReplSessionScopeV1::Synchronise,
                    },
                })
                .collect(),
        }
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

// == oauth2 session ==

#[derive(Debug, Clone)]
pub struct ValueSetOauth2Session {
    map: BTreeMap<Uuid, Oauth2Session>,
    // this is a "filter" to tell us if as rs_id is used anywhere
    // in this set. The reason is so that we don't do O(n) searches
    // on a refer if it's not in this set. The alternate approach is
    // an index on these maps, but its more work to maintain for a rare
    // situation where we actually want to query rs_uuid -> sessions.
    rs_filter: BTreeSet<Uuid>,
}

impl ValueSetOauth2Session {
    pub fn new(u: Uuid, m: Oauth2Session) -> Box<Self> {
        let mut map = BTreeMap::new();
        let mut rs_filter = BTreeSet::new();
        rs_filter.insert(m.rs_uuid);
        map.insert(u, m);
        Box::new(ValueSetOauth2Session { map, rs_filter })
    }

    pub fn push(&mut self, u: Uuid, m: Oauth2Session) -> bool {
        self.rs_filter.insert(m.rs_uuid);
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueOauth2Session>) -> Result<ValueSet, OperationError> {
        let mut rs_filter = BTreeSet::new();
        let map = data
            .into_iter()
            .filter_map(|dbv| {
                match dbv {
                    DbValueOauth2Session::V1 {
                        refer,
                        parent,
                        expiry,
                        issued_at,
                        rs_uuid,
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

                        // Insert to the rs_filter.
                        rs_filter.insert(rs_uuid);
                        Some((
                            refer,
                            Oauth2Session {
                                parent,
                                expiry,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    }
                }
            })
            .collect();
        Ok(Box::new(ValueSetOauth2Session { map, rs_filter }))
    }

    pub fn from_repl_v1(data: &[ReplOauth2SessionV1]) -> Result<ValueSet, OperationError> {
        let mut rs_filter = BTreeSet::new();
        let map = data
            .iter()
            .filter_map(
                |ReplOauth2SessionV1 {
                     refer,
                     parent,
                     expiry,
                     issued_at,
                     rs_uuid,
                 }| {
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
                        .as_ref()
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

                    // Insert to the rs_filter.
                    rs_filter.insert(*rs_uuid);
                    Some((
                        *refer,
                        Oauth2Session {
                            parent: *parent,
                            expiry,
                            issued_at,
                            rs_uuid: *rs_uuid,
                        },
                    ))
                },
            )
            .collect();
        Ok(Box::new(ValueSetOauth2Session { rs_filter, map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, Oauth2Session)>,
    {
        let mut rs_filter = BTreeSet::new();
        let map = iter
            .into_iter()
            .map(|(u, m)| {
                rs_filter.insert(m.rs_uuid);
                (u, m)
            })
            .collect();
        Some(Box::new(ValueSetOauth2Session { map, rs_filter }))
    }
}

impl ValueSetT for ValueSetOauth2Session {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Oauth2Session(u, m) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    self.rs_filter.insert(m.rs_uuid);
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
        self.rs_filter.clear();
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => {
                let found = self.map.remove(u).is_some();
                if !found {
                    // Perhaps the reference id is an rs_uuid?
                    if self.rs_filter.contains(u) {
                        // It's there, so we need to do a more costly retain operation over the values.
                        self.map.retain(|_, m| m.rs_uuid != *u);
                        self.rs_filter.remove(u);
                        // We removed something, so yeeeet.
                        true
                    } else {
                        // It's not in the rs_filter or the map, false.
                        false
                    }
                } else {
                    // We found it in the map, true
                    true
                }
            }
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.contains_key(u) || self.rs_filter.contains(u),
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
            // We also refer to our rs_uuid's.
            .chain(self.rs_filter.iter().map(|u| u.as_hyphenated().to_string()))
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Oauth2Session
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
        DbValueSetV2::Oauth2Session(
            self.map
                .iter()
                .map(|(u, m)| DbValueOauth2Session::V1 {
                    refer: *u,
                    parent: m.parent,
                    expiry: m.expiry.map(|odt| {
                        debug_assert!(odt.offset() == time::UtcOffset::UTC);
                        odt.format(time::Format::Rfc3339)
                    }),
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        m.issued_at.format(time::Format::Rfc3339)
                    },
                    rs_uuid: m.rs_uuid,
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Oauth2Session {
            set: self
                .map
                .iter()
                .map(|(u, m)| ReplOauth2SessionV1 {
                    refer: *u,
                    parent: m.parent,
                    expiry: m.expiry.map(|odt| {
                        debug_assert!(odt.offset() == time::UtcOffset::UTC);
                        odt.format(time::Format::Rfc3339)
                    }),
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        m.issued_at.format(time::Format::Rfc3339)
                    },
                    rs_uuid: m.rs_uuid,
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| Value::Oauth2Session(*u, m.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_oauth2session_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_oauth2session_map() {
            // Merge the rs_filters.
            // We have to do this without the mergemap macro so that rs_filter
            // is updated.
            b.iter().for_each(|(k, v)| {
                if !self.map.contains_key(k) {
                    self.rs_filter.insert(v.rs_uuid);
                    self.map.insert(*k, v.clone());
                }
            });
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_oauth2session_map(&self) -> Option<&BTreeMap<Uuid, Oauth2Session>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked. We need to
        // bind to our resource servers, not our ids!
        Some(Box::new(self.map.values().map(|m| &m.rs_uuid).copied()))
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetApiToken {
    map: BTreeMap<Uuid, ApiToken>,
}

impl ValueSetApiToken {
    pub fn new(u: Uuid, m: ApiToken) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, m);
        Box::new(ValueSetApiToken { map })
    }

    pub fn push(&mut self, u: Uuid, m: ApiToken) -> bool {
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueApiToken>) -> Result<ValueSet, OperationError> {
        let map =
            data.into_iter()
                .filter_map(|dbv| {
                    match dbv {
                        DbValueApiToken::V1 {
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
                                    "Invalidating api token {} due to invalid issued_at timestamp",
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
                                        "Invalidating api token {} due to invalid expiry timestamp",
                                        refer
                                    )
                                })
                                // Option<Option<ODT>>
                                .ok()?;

                            let issued_by = match issued_by {
                                DbValueIdentityId::V1Internal => IdentityId::Internal,
                                DbValueIdentityId::V1Uuid(u) => IdentityId::User(u),
                                DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                            };

                            let scope = match scope {
                                DbValueApiTokenScopeV1::ReadOnly => ApiTokenScope::ReadOnly,
                                  DbValueApiTokenScopeV1::ReadWrite => ApiTokenScope::ReadWrite,
                                  DbValueApiTokenScopeV1::Synchronise => ApiTokenScope::Synchronise,
                            };

                            Some((
                                refer,
                                ApiToken {
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
        Ok(Box::new(ValueSetApiToken { map }))
    }

    pub fn from_repl_v1(data: &[ReplApiTokenV1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .filter_map(
                |ReplApiTokenV1 {
                     refer,
                     label,
                     expiry,
                     issued_at,
                     issued_by,
                     scope,
                 }| {
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
                        .as_ref()
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
                        ReplIdentityIdV1::Internal => IdentityId::Internal,
                        ReplIdentityIdV1::Uuid(u) => IdentityId::User(*u),
                        ReplIdentityIdV1::Synch(u) => IdentityId::Synch(*u),
                    };

                    let scope = match scope {
                        ReplApiTokenScopeV1::ReadOnly =>    ApiTokenScope::ReadOnly,
                        ReplApiTokenScopeV1::ReadWrite =>   ApiTokenScope::ReadWrite,
                        ReplApiTokenScopeV1::Synchronise => ApiTokenScope::Synchronise,
                    };

                    Some((
                        *refer,
                        ApiToken {
                            label: label.to_string(),
                            expiry,
                            issued_at,
                            issued_by,
                            scope,
                        },
                    ))
                },
            )
            .collect();
        Ok(Box::new(ValueSetApiToken { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, ApiToken)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetApiToken { map }))
    }
}

impl ValueSetT for ValueSetApiToken {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::ApiToken(u, m) => {
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
        SyntaxType::ApiToken
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
        DbValueSetV2::ApiToken(
            self.map
                .iter()
                .map(|(u, m)| DbValueApiToken::V1 {
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
                        IdentityId::Synch(u) => DbValueIdentityId::V1Sync(u),
                    },
                    scope: match m.scope {
                        ApiTokenScope::ReadOnly =>    DbValueApiTokenScopeV1::ReadOnly,
                        ApiTokenScope::ReadWrite =>   DbValueApiTokenScopeV1::ReadWrite,
                        ApiTokenScope::Synchronise => DbValueApiTokenScopeV1::Synchronise,
                    },
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::ApiToken {
            set: self
                .map
                .iter()
                .map(|(u, m)| ReplApiTokenV1 {
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
                        IdentityId::Internal => ReplIdentityIdV1::Internal,
                        IdentityId::User(u) => ReplIdentityIdV1::Uuid(u),
                        IdentityId::Synch(u) => ReplIdentityIdV1::Synch(u),
                    },
                    scope: match m.scope {
                        ApiTokenScope::ReadOnly =>         ReplApiTokenScopeV1::ReadOnly,
                        ApiTokenScope::ReadWrite =>        ReplApiTokenScopeV1::ReadWrite,
                        ApiTokenScope::Synchronise =>      ReplApiTokenScopeV1::Synchronise,
                    },
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.iter().map(|(u, m)| Value::ApiToken(*u, m.clone())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_apitoken_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_apitoken_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_apitoken_map(&self) -> Option<&BTreeMap<Uuid, ApiToken>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(self.map.keys().copied()))
    }
}

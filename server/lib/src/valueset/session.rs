use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::be::dbvalue::{
    DbCidV1, DbValueAccessScopeV1, DbValueApiToken, DbValueApiTokenScopeV1, DbValueIdentityId,
    DbValueOauth2Session, DbValueSession, DbValueSessionStateV1,
};
use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::repl::proto::{
    ReplApiTokenScopeV1, ReplApiTokenV1, ReplAttrV1, ReplIdentityIdV1, ReplOauth2SessionV1,
    ReplSessionScopeV1, ReplSessionStateV1, ReplSessionV1,
};
use crate::schema::SchemaAttribute;
use crate::value::{ApiToken, ApiTokenScope, Oauth2Session, Session, SessionScope, SessionState};
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
                        // token ever issued. OOPS!
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
                            let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
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
                                    OffsetDateTime::parse(&e_inner, &Rfc3339)
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

                            let state = expiry
                                .map(SessionState::ExpiresAt)
                                .unwrap_or(SessionState::NeverExpires);

                            let issued_by = match issued_by {
                                DbValueIdentityId::V1Internal => IdentityId::Internal,
                                DbValueIdentityId::V1Uuid(u) => IdentityId::User(u),
                                DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                            };

                            let scope = match scope {
                                DbValueAccessScopeV1::IdentityOnly
                                | DbValueAccessScopeV1::ReadOnly => SessionScope::ReadOnly,
                                DbValueAccessScopeV1::ReadWrite => SessionScope::ReadWrite,
                                DbValueAccessScopeV1::PrivilegeCapable => {
                                    SessionScope::PrivilegeCapable
                                }
                                DbValueAccessScopeV1::Synchronise => SessionScope::Synchronise,
                            };

                            Some((
                                refer,
                                Session {
                                    label,
                                    state,
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
                            let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
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
                                    OffsetDateTime::parse(&e_inner, &Rfc3339)
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

                            let state = expiry
                                .map(SessionState::ExpiresAt)
                                .unwrap_or(SessionState::NeverExpires);

                            let issued_by = match issued_by {
                                DbValueIdentityId::V1Internal => IdentityId::Internal,
                                DbValueIdentityId::V1Uuid(u) => IdentityId::User(u),
                                DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                            };

                            let scope = match scope {
                                DbValueAccessScopeV1::IdentityOnly
                                | DbValueAccessScopeV1::ReadOnly => SessionScope::ReadOnly,
                                DbValueAccessScopeV1::ReadWrite => SessionScope::ReadWrite,
                                DbValueAccessScopeV1::PrivilegeCapable => {
                                    SessionScope::PrivilegeCapable
                                }
                                DbValueAccessScopeV1::Synchronise => SessionScope::Synchronise,
                            };

                            Some((
                                refer,
                                Session {
                                    label,
                                    state,
                                    issued_at,
                                    issued_by,
                                    cred_id,
                                    scope,
                                },
                            ))
                        }
                        DbValueSession::V3 {
                            refer,
                            label,
                            state,
                            issued_at,
                            issued_by,
                            cred_id,
                            scope,
                        } => {
                            // Convert things.
                            let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                                .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                .map_err(|e| {
                                    admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                                })
                                .ok()?;

                            let state = match state {
                                DbValueSessionStateV1::ExpiresAt(e_inner) => {
                                    OffsetDateTime::parse(&e_inner, &Rfc3339)
                                        .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                        .map(SessionState::ExpiresAt)
                                        .map_err(|e| {
                                            admin_error!(
                                        ?e,
                                        "Invalidating session {} due to invalid expiry timestamp",
                                        refer
                                    )
                                        })
                                        .ok()?
                                }
                                DbValueSessionStateV1::Never => SessionState::NeverExpires,
                                DbValueSessionStateV1::RevokedAt(dc) => {
                                    SessionState::RevokedAt(Cid {
                                        s_uuid: dc.server_id,
                                        ts: dc.timestamp,
                                    })
                                }
                            };

                            let issued_by = match issued_by {
                                DbValueIdentityId::V1Internal => IdentityId::Internal,
                                DbValueIdentityId::V1Uuid(u) => IdentityId::User(u),
                                DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                            };

                            let scope = match scope {
                                DbValueAccessScopeV1::IdentityOnly
                                | DbValueAccessScopeV1::ReadOnly => SessionScope::ReadOnly,
                                DbValueAccessScopeV1::ReadWrite => SessionScope::ReadWrite,
                                DbValueAccessScopeV1::PrivilegeCapable => {
                                    SessionScope::PrivilegeCapable
                                }
                                DbValueAccessScopeV1::Synchronise => SessionScope::Synchronise,
                            };

                            Some((
                                refer,
                                Session {
                                    label,
                                    state,
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
                     state,
                     issued_at,
                     issued_by,
                     cred_id,
                     scope,
                 }| {
                    // Convert things.
                    let issued_at = OffsetDateTime::parse(issued_at, &Rfc3339)
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
                    let state = match state {
                        ReplSessionStateV1::ExpiresAt(e_inner) => {
                            OffsetDateTime::parse(e_inner, &Rfc3339)
                                .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                .map(SessionState::ExpiresAt)
                                .map_err(|e| {
                                    admin_error!(
                                        ?e,
                                        "Invalidating session {} due to invalid expiry timestamp",
                                        refer
                                    )
                                })
                                .ok()?
                        }
                        ReplSessionStateV1::Never => SessionState::NeverExpires,
                        ReplSessionStateV1::RevokedAt(rc) => SessionState::RevokedAt(rc.into()),
                    };

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
                            state,
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

    fn remove(&mut self, pv: &PartialValue, cid: &Cid) -> bool {
        match pv {
            PartialValue::Refer(u) => {
                if let Some(session) = self.map.get_mut(u) {
                    if !matches!(session.state, SessionState::RevokedAt(_)) {
                        session.state = SessionState::RevokedAt(cid.clone());
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn purge(&mut self, cid: &Cid) -> bool {
        for (_uuid, session) in self.map.iter_mut() {
            // Send them all to the shadow realm
            if !matches!(session.state, SessionState::RevokedAt(_)) {
                session.state = SessionState::RevokedAt(cid.clone())
            }
        }
        // Can't be purged since we need the cid's of revoked to persist.
        false
    }

    fn trim(&mut self, trim_cid: &Cid) {
        self.map.retain(|_, session| {
            match &session.state {
                SessionState::RevokedAt(cid) if cid < trim_cid => {
                    // This value is past the replication trim window and can now safely
                    // be removed
                    false
                }
                // Retain all else
                _ => true,
            }
        })
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
                .map(|(u, m)| DbValueSession::V3 {
                    refer: *u,
                    label: m.label.clone(),

                    state: match &m.state {
                        SessionState::ExpiresAt(odt) => {
                            debug_assert!(odt.offset() == time::UtcOffset::UTC);
                            #[allow(clippy::expect_used)]
                            odt.format(&Rfc3339)
                                .map(DbValueSessionStateV1::ExpiresAt)
                                .expect("Failed to format timestamp into RFC3339!")
                        }
                        SessionState::NeverExpires => DbValueSessionStateV1::Never,
                        SessionState::RevokedAt(c) => DbValueSessionStateV1::RevokedAt(DbCidV1 {
                            server_id: c.s_uuid,
                            timestamp: c.ts,
                        }),
                    },

                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339!")
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

                    state: match &m.state {
                        SessionState::ExpiresAt(odt) => {
                            debug_assert!(odt.offset() == time::UtcOffset::UTC);
                            #[allow(clippy::expect_used)]
                            odt.format(&Rfc3339)
                                .map(ReplSessionStateV1::ExpiresAt)
                                .expect("Failed to format timestamp into RFC3339!")
                        }
                        SessionState::NeverExpires => ReplSessionStateV1::Never,
                        SessionState::RevokedAt(c) => ReplSessionStateV1::RevokedAt(c.into()),
                    },

                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp to RFC3339")
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
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to.
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = self.map.get_mut(k_other) {
                    // We only update if lower. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Not present, just insert.
                    self.map.insert(*k_other, v_other.clone());
                }
            }
            Ok(())
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

    fn migrate_session_to_apitoken(&self) -> Result<ValueSet, OperationError> {
        let map = self
            .as_session_map()
            .iter()
            .flat_map(|m| m.iter())
            .filter_map(
                |(
                    u,
                    Session {
                        label,
                        state,
                        issued_at,
                        issued_by,
                        cred_id: _,
                        scope,
                    },
                )| {
                    let expiry = match state {
                        SessionState::ExpiresAt(e) => Some(*e),
                        SessionState::NeverExpires => None,
                        SessionState::RevokedAt(_) => return None,
                    };

                    Some((
                        *u,
                        ApiToken {
                            label: label.clone(),
                            expiry,
                            issued_at: *issued_at,
                            issued_by: issued_by.clone(),
                            scope: match scope {
                                SessionScope::Synchronise => ApiTokenScope::Synchronise,
                                SessionScope::ReadWrite => ApiTokenScope::ReadWrite,
                                _ => ApiTokenScope::ReadOnly,
                            },
                        },
                    ))
                },
            )
            .collect();
        Ok(Box::new(ValueSetApiToken { map }))
    }

    fn repl_merge_valueset(&self, older: &ValueSet, trim_cid: &Cid) -> Option<ValueSet> {
        if let Some(b) = older.as_session_map() {
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to.
            let mut map = self.map.clone();
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = map.get_mut(k_other) {
                    // We only update if lower. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Not present, just insert.
                    map.insert(*k_other, v_other.clone());
                }
            }
            // There might be a neater way to do this with less iterations. The problem
            // is we can't just check on what was in b/older, because then we miss
            // trimmable content from the local map. So once the merge is complete we
            // do a pass for trim.
            map.retain(|_, session| {
                match &session.state {
                    SessionState::RevokedAt(cid) if cid < trim_cid => {
                        // This value is past the replication trim window and can now safely
                        // be removed
                        false
                    }
                    // Retain all else
                    _ => true,
                }
            });
            Some(Box::new(ValueSetSession { map }))
        } else {
            // The older value has a different type - return nothing, we
            // just take the newer value.
            None
        }
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
    rs_filter: u128,
}

impl ValueSetOauth2Session {
    pub fn new(u: Uuid, m: Oauth2Session) -> Box<Self> {
        let mut map = BTreeMap::new();
        let rs_filter = m.rs_uuid.as_u128();
        map.insert(u, m);
        Box::new(ValueSetOauth2Session { map, rs_filter })
    }

    pub fn push(&mut self, u: Uuid, m: Oauth2Session) -> bool {
        self.rs_filter |= m.rs_uuid.as_u128();
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueOauth2Session>) -> Result<ValueSet, OperationError> {
        let mut rs_filter = u128::MIN;
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
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
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
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
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

                        let state = expiry
                            .map(SessionState::ExpiresAt)
                            .unwrap_or(SessionState::NeverExpires);

                        let parent = Some(parent);

                        // Insert to the rs_filter.
                        rs_filter |= rs_uuid.as_u128();
                        Some((
                            refer,
                            Oauth2Session {
                                parent,
                                state,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    }
                    DbValueOauth2Session::V2 {
                        refer,
                        parent,
                        state,
                        issued_at,
                        rs_uuid,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        let state = match state {
                            DbValueSessionStateV1::ExpiresAt(e_inner) => {
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                    .map(SessionState::ExpiresAt)
                                    .map_err(|e| {
                                        admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid expiry timestamp",
                                    refer
                                )
                                    })
                                    .ok()?
                            }
                            DbValueSessionStateV1::Never => SessionState::NeverExpires,
                            DbValueSessionStateV1::RevokedAt(dc) => SessionState::RevokedAt(Cid {
                                s_uuid: dc.server_id,
                                ts: dc.timestamp,
                            }),
                        };

                        rs_filter |= rs_uuid.as_u128();

                        let parent = Some(parent);

                        Some((
                            refer,
                            Oauth2Session {
                                parent,
                                state,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    } // End V2
                    DbValueOauth2Session::V3 {
                        refer,
                        parent,
                        state,
                        issued_at,
                        rs_uuid,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        let state = match state {
                            DbValueSessionStateV1::ExpiresAt(e_inner) => {
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                    .map(SessionState::ExpiresAt)
                                    .map_err(|e| {
                                        admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid expiry timestamp",
                                    refer
                                )
                                    })
                                    .ok()?
                            }
                            DbValueSessionStateV1::Never => SessionState::NeverExpires,
                            DbValueSessionStateV1::RevokedAt(dc) => SessionState::RevokedAt(Cid {
                                s_uuid: dc.server_id,
                                ts: dc.timestamp,
                            }),
                        };

                        rs_filter |= rs_uuid.as_u128();

                        Some((
                            refer,
                            Oauth2Session {
                                parent,
                                state,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    } // End V3
                }
            })
            .collect();
        Ok(Box::new(ValueSetOauth2Session { map, rs_filter }))
    }

    pub fn from_repl_v1(data: &[ReplOauth2SessionV1]) -> Result<ValueSet, OperationError> {
        let mut rs_filter = u128::MIN;
        let map = data
            .iter()
            .filter_map(
                |ReplOauth2SessionV1 {
                     refer,
                     parent,
                     state,
                     issued_at,
                     rs_uuid,
                 }| {
                    // Convert things.
                    let issued_at = OffsetDateTime::parse(issued_at, &Rfc3339)
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
                    let state = match state {
                        ReplSessionStateV1::ExpiresAt(e_inner) => {
                            OffsetDateTime::parse(e_inner, &Rfc3339)
                                .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                .map(SessionState::ExpiresAt)
                                .map_err(|e| {
                                    admin_error!(
                                        ?e,
                                        "Invalidating session {} due to invalid expiry timestamp",
                                        refer
                                    )
                                })
                                .ok()?
                        }
                        ReplSessionStateV1::Never => SessionState::NeverExpires,
                        ReplSessionStateV1::RevokedAt(rc) => SessionState::RevokedAt(rc.into()),
                    };

                    rs_filter |= rs_uuid.as_u128();

                    Some((
                        *refer,
                        Oauth2Session {
                            parent: *parent,
                            state,
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
        let mut rs_filter = u128::MIN;
        let map = iter
            .into_iter()
            .map(|(u, m)| {
                rs_filter |= m.rs_uuid.as_u128();
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
                // Unlike other types, this allows overwriting as oauth2 sessions
                // can be *extended* in time length.
                match self.map.entry(u) {
                    BTreeEntry::Vacant(e) => {
                        self.rs_filter |= m.rs_uuid.as_u128();
                        e.insert(m);
                        Ok(true)
                    }
                    BTreeEntry::Occupied(mut e) => {
                        let e_v = e.get_mut();
                        if m.state > e_v.state {
                            // Replace if the state has higher priority.
                            *e_v = m;
                            Ok(true)
                        } else {
                            // Else take no action.
                            Ok(false)
                        }
                    }
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.rs_filter = u128::MIN;
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, cid: &Cid) -> bool {
        match pv {
            PartialValue::Refer(u) => {
                if let Some(session) = self.map.get_mut(u) {
                    if !matches!(session.state, SessionState::RevokedAt(_)) {
                        session.state = SessionState::RevokedAt(cid.clone());
                        true
                    } else {
                        false
                    }
                } else {
                    // What if it's an rs_uuid?
                    let u_int = u.as_u128();
                    if self.rs_filter & u_int == u_int {
                        // It's there, so we need to do a more costly revoke over the values
                        // that are present.
                        let mut removed = false;
                        self.map.values_mut().for_each(|session| {
                            if session.rs_uuid == *u {
                                session.state = SessionState::RevokedAt(cid.clone());
                                removed = true;
                            }
                        });
                        removed
                    } else {
                        // It's not in the rs_filter or the map, false.
                        false
                    }
                }
            }
            _ => false,
        }
    }

    fn purge(&mut self, cid: &Cid) -> bool {
        for (_uuid, session) in self.map.iter_mut() {
            // Send them all to the shadow realm
            if !matches!(session.state, SessionState::RevokedAt(_)) {
                session.state = SessionState::RevokedAt(cid.clone())
            }
        }
        // Can't be purged since we need the cid's of revoked to persist.
        false
    }

    fn trim(&mut self, trim_cid: &Cid) {
        self.map.retain(|_, session| {
            match &session.state {
                SessionState::RevokedAt(cid) if cid < trim_cid => {
                    // This value is past the replication trim window and can now safely
                    // be removed
                    false
                }
                // Retain all else
                _ => true,
            }
        })
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => {
                self.map.contains_key(u) || {
                    let u_int = u.as_u128();
                    if self.rs_filter & u_int == u_int {
                        self.map.values().any(|session| {
                            session.rs_uuid == *u
                                && !matches!(session.state, SessionState::RevokedAt(_))
                        })
                    } else {
                        false
                    }
                }
            }
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
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        // Allocate twice as much for worst-case when every session is
        // a unique rs-uuid to prevent re-allocs.
        let mut idx_keys = Vec::with_capacity(self.map.len() * 2);
        for (k, v) in self.map.iter() {
            idx_keys.push(k.as_hyphenated().to_string());
            idx_keys.push(v.rs_uuid.as_hyphenated().to_string());
        }
        idx_keys.sort_unstable();
        idx_keys.dedup();
        idx_keys
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
                .map(|(u, m)| DbValueOauth2Session::V3 {
                    refer: *u,
                    parent: m.parent,
                    state: match &m.state {
                        SessionState::ExpiresAt(odt) => {
                            debug_assert!(odt.offset() == time::UtcOffset::UTC);
                            #[allow(clippy::expect_used)]
                            odt.format(&Rfc3339)
                                .map(DbValueSessionStateV1::ExpiresAt)
                                .expect("Failed to format timestamp into RFC3339!")
                        }
                        SessionState::NeverExpires => DbValueSessionStateV1::Never,
                        SessionState::RevokedAt(c) => DbValueSessionStateV1::RevokedAt(DbCidV1 {
                            server_id: c.s_uuid,
                            timestamp: c.ts,
                        }),
                    },
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp as RFC3339")
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
                    state: match &m.state {
                        SessionState::ExpiresAt(odt) => {
                            debug_assert!(odt.offset() == time::UtcOffset::UTC);
                            #[allow(clippy::expect_used)]
                            odt.format(&Rfc3339)
                                .map(ReplSessionStateV1::ExpiresAt)
                                .expect("Failed to format timestamp into RFC3339!")
                        }
                        SessionState::NeverExpires => ReplSessionStateV1::Never,
                        SessionState::RevokedAt(c) => ReplSessionStateV1::RevokedAt(c.into()),
                    },
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
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
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to. We also
            // need to make sure the rs_filter is updated too!
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = self.map.get_mut(k_other) {
                    // We only update if lower. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Update the rs_filter!
                    self.rs_filter |= v_other.rs_uuid.as_u128();
                    // Not present, just insert.
                    self.map.insert(*k_other, v_other.clone());
                }
            }
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

    fn repl_merge_valueset(&self, older: &ValueSet, trim_cid: &Cid) -> Option<ValueSet> {
        if let Some(b) = older.as_oauth2session_map() {
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to.
            let mut map = self.map.clone();
            let mut rs_filter = self.rs_filter;
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = map.get_mut(k_other) {
                    // We only update if lower. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Not present, just insert.
                    rs_filter |= v_other.rs_uuid.as_u128();
                    map.insert(*k_other, v_other.clone());
                }
            }
            // There might be a neater way to do this with less iterations. The problem
            // is we can't just check on what was in b/older, because then we miss
            // trimmable content from the local map. So once the merge is complete we
            // do a pass for trim.
            map.retain(|_, session| {
                match &session.state {
                    SessionState::RevokedAt(cid) if cid < trim_cid => {
                        // This value is past the replication trim window and can now safely
                        // be removed
                        false
                    }
                    // Retain all else
                    _ => true,
                }
            });
            Some(Box::new(ValueSetOauth2Session { map, rs_filter }))
        } else {
            // The older value has a different type - return nothing, we
            // just take the newer value.
            None
        }
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
        let map = data
            .into_iter()
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
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
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
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
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
                    let issued_at = OffsetDateTime::parse(issued_at, &Rfc3339)
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
                            OffsetDateTime::parse(e_inner, &Rfc3339)
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
                        ReplApiTokenScopeV1::ReadOnly => ApiTokenScope::ReadOnly,
                        ReplApiTokenScopeV1::ReadWrite => ApiTokenScope::ReadWrite,
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn purge(&mut self, _cid: &Cid) -> bool {
        // Could consider making this a TS capable entry.
        true
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
        self.map.iter().all(|(_, at)| {
            Value::validate_str_escapes(&at.label) && Value::validate_singleline(&at.label)
        })
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
                        #[allow(clippy::expect_used)]
                        odt.format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
                    }),
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
                    },
                    issued_by: match m.issued_by {
                        IdentityId::Internal => DbValueIdentityId::V1Internal,
                        IdentityId::User(u) => DbValueIdentityId::V1Uuid(u),
                        IdentityId::Synch(u) => DbValueIdentityId::V1Sync(u),
                    },
                    scope: match m.scope {
                        ApiTokenScope::ReadOnly => DbValueApiTokenScopeV1::ReadOnly,
                        ApiTokenScope::ReadWrite => DbValueApiTokenScopeV1::ReadWrite,
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
                        #[allow(clippy::expect_used)]
                        odt.format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
                    }),
                    issued_at: {
                        debug_assert!(m.issued_at.offset() == time::UtcOffset::UTC);

                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
                    },
                    issued_by: match m.issued_by {
                        IdentityId::Internal => ReplIdentityIdV1::Internal,
                        IdentityId::User(u) => ReplIdentityIdV1::Uuid(u),
                        IdentityId::Synch(u) => ReplIdentityIdV1::Synch(u),
                    },
                    scope: match m.scope {
                        ApiTokenScope::ReadOnly => ReplApiTokenScopeV1::ReadOnly,
                        ApiTokenScope::ReadWrite => ReplApiTokenScopeV1::ReadWrite,
                        ApiTokenScope::Synchronise => ReplApiTokenScopeV1::Synchronise,
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

    fn migrate_session_to_apitoken(&self) -> Result<ValueSet, OperationError> {
        // We are already in the api token format, don't do anything.
        Ok(Box::new(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueSetOauth2Session, ValueSetSession};
    use crate::prelude::{IdentityId, SessionScope, Uuid};
    use crate::repl::cid::Cid;
    use crate::value::{Oauth2Session, Session, SessionState};
    use crate::valueset::ValueSet;
    use time::OffsetDateTime;

    #[test]
    fn test_valueset_session_purge() {
        let s_uuid = Uuid::new_v4();

        let mut vs: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        let zero_cid = Cid::new_zero();

        // Simulate session revocation.
        vs.purge(&zero_cid);

        assert!(vs.len() == 1);

        let session = vs
            .as_session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_session_merge_left() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let mut vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        let vs_b: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::RevokedAt(zero_cid.clone()),
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        vs_a.merge(&vs_b).expect("failed to merge");

        let session = vs_a
            .as_session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_session_merge_right() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        let mut vs_b: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::RevokedAt(zero_cid.clone()),
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        // Note - inverse order!
        vs_b.merge(&vs_a).expect("failed to merge");

        let session = vs_b
            .as_session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_session_repl_merge_left() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        let vs_b: ValueSet = ValueSetSession::from_iter([
            (
                s_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(one_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
            (
                r_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
        ])
        .expect("Unable to build valueset session");

        let r_vs = vs_a
            .repl_merge_valueset(&vs_b, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs.as_session_map().expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_session_repl_merge_right() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal,
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
            },
        );

        let vs_b: ValueSet = ValueSetSession::from_iter([
            (
                s_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(one_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
            (
                r_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
        ])
        .expect("Unable to build valueset session");

        // Note - inverse order!
        let r_vs = vs_b
            .repl_merge_valueset(&vs_a, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs.as_session_map().expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_session_repl_trim() {
        let zero_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_uuid = Uuid::new_v4();
        let one_cid = Cid::new_count(1);
        let two_uuid = Uuid::new_v4();
        let two_cid = Cid::new_count(2);

        let mut vs_a: ValueSet = ValueSetSession::from_iter([
            (
                zero_uuid,
                Session {
                    state: SessionState::RevokedAt(zero_cid),
                    label: "hacks".to_string(),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
            (
                one_uuid,
                Session {
                    state: SessionState::RevokedAt(one_cid),
                    label: "hacks".to_string(),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
            (
                two_uuid,
                Session {
                    state: SessionState::RevokedAt(two_cid.clone()),
                    label: "hacks".to_string(),
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal,
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                },
            ),
        ])
        .unwrap();

        vs_a.trim(&two_cid);

        let sessions = vs_a.as_session_map().expect("Unable to locate session");

        assert!(!sessions.contains_key(&zero_uuid));
        assert!(!sessions.contains_key(&one_uuid));
        assert!(sessions.contains_key(&two_uuid));
    }

    #[test]
    fn test_valueset_oauth2_session_purge() {
        let s_uuid = Uuid::new_v4();
        let mut vs: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let zero_cid = Cid::new_zero();

        // Simulate session revocation.
        vs.purge(&zero_cid);

        assert!(vs.len() == 1);

        let session = vs
            .as_oauth2session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_oauth2_session_merge_left() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let mut vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let vs_b: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::RevokedAt(zero_cid.clone()),
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        vs_a.merge(&vs_b).expect("failed to merge");

        let session = vs_a
            .as_oauth2session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_oauth2_session_merge_right() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let mut vs_b: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::RevokedAt(zero_cid.clone()),
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        // Note inverse order
        vs_b.merge(&vs_a).expect("failed to merge");

        let session = vs_b
            .as_oauth2session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_oauth2_session_repl_merge_left() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let vs_b: ValueSet = ValueSetOauth2Session::from_iter([
            (
                s_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(one_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                r_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
        ])
        .expect("Unable to build valueset oauth2 session");

        let r_vs = vs_a
            .repl_merge_valueset(&vs_b, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs
            .as_oauth2session_map()
            .expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_oauth2_session_repl_merge_right() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            Oauth2Session {
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let vs_b: ValueSet = ValueSetOauth2Session::from_iter([
            (
                s_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(one_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                r_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
        ])
        .expect("Unable to build valueset oauth2 session");

        // Note inverse order
        let r_vs = vs_b
            .repl_merge_valueset(&vs_a, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs
            .as_oauth2session_map()
            .expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_oauth2_session_repl_trim() {
        let zero_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_uuid = Uuid::new_v4();
        let one_cid = Cid::new_count(1);
        let two_uuid = Uuid::new_v4();
        let two_cid = Cid::new_count(2);

        let mut vs_a: ValueSet = ValueSetOauth2Session::from_iter([
            (
                zero_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(zero_cid),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                one_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(one_cid),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                two_uuid,
                Oauth2Session {
                    state: SessionState::RevokedAt(two_cid.clone()),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
        ])
        .unwrap();

        vs_a.trim(&two_cid);

        let sessions = vs_a
            .as_oauth2session_map()
            .expect("Unable to locate session");

        assert!(!sessions.contains_key(&zero_uuid));
        assert!(!sessions.contains_key(&one_uuid));
        assert!(sessions.contains_key(&two_uuid));
    }
}

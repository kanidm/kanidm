use crate::credential::Credential;
use crate::prelude::*;
use crate::repl::cid::Cid;
use either::Either::{Left, Right};
use kanidm_proto::v1::Filter as ProtoFilter;
use smolset::{SmolSet, SmolSetIter};
use sshkeys::PublicKey as SshPublicKey;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet};
use std::iter::FromIterator;
use time::OffsetDateTime;
use tracing::trace;

use crate::be::dbvalue::{
    DbCidV1, DbValueCredV1, DbValueEmailAddressV1, DbValueOauthScopeMapV1, DbValueTaggedStringV1,
    DbValueV1,
};
use crate::value::DataValue;

// SmolSet<[; 1]>

#[derive(Debug, Clone)]
enum I {
    Utf8(BTreeSet<String>),
    Iutf8(BTreeSet<String>),
    Iname(BTreeSet<String>),
    Uuid(BTreeSet<Uuid>),
    Bool(SmolSet<[bool; 1]>),
    Syntax(SmolSet<[SyntaxType; 1]>),
    Index(SmolSet<[IndexType; 1]>),
    Refer(BTreeSet<Uuid>),
    JsonFilt(SmolSet<[ProtoFilter; 1]>),
    Cred(BTreeMap<String, Credential>),
    SshKey(BTreeMap<String, String>),
    SecretValue(SmolSet<[String; 1]>),
    Spn(BTreeSet<(String, String)>),
    Uint32(SmolSet<[u32; 1]>),
    Cid(SmolSet<[Cid; 1]>),
    Nsuniqueid(BTreeSet<String>),
    DateTime(SmolSet<[OffsetDateTime; 1]>),
    EmailAddress(BTreeSet<String>),
    Url(SmolSet<[Url; 1]>),
    OauthScope(BTreeSet<String>),
    OauthScopeMap(BTreeMap<Uuid, BTreeSet<String>>),
    Es256PrivateDer(SmolSet<[Vec<u8>; 1]>),
}

pub struct ValueSet {
    inner: I,
}

macro_rules! mergesets {
    (
        $a:expr,
        $b:expr
    ) => {{
        $b.iter().for_each(|v| {
            $a.insert(v.clone());
        });
        Ok(())
    }};
}

macro_rules! mergemaps {
    (
        $a:expr,
        $b:expr
    ) => {{
        $b.iter().for_each(|(k, v)| {
            if !$a.contains_key(k) {
                $a.insert(k.clone(), v.clone());
            }
        });
        Ok(())
    }};
}

impl ValueSet {
    pub fn uuid_to_proto_string(u: &Uuid) -> String {
        u.to_hyphenated_ref().to_string()
    }

    pub fn new(value: Value) -> Self {
        let Value { pv, data } = value;

        ValueSet {
            inner: match pv {
                PartialValue::Utf8(s) => I::Utf8(btreeset![s]),
                PartialValue::Iutf8(s) => I::Iutf8(btreeset![s]),
                PartialValue::Iname(s) => I::Iname(btreeset![s]),
                PartialValue::Uuid(u) => I::Uuid(btreeset![u]),
                PartialValue::Bool(b) => I::Bool(smolset![b]),
                PartialValue::Syntax(s) => I::Syntax(smolset![s]),
                PartialValue::Index(i) => I::Index(smolset![i]),
                PartialValue::Refer(u) => I::Refer(btreeset![u]),
                PartialValue::JsonFilt(f) => I::JsonFilt(smolset![f]),
                PartialValue::Cred(t) => match data.map(|b| (*b).clone()) {
                    Some(DataValue::Cred(c)) => I::Cred(btreemap![(t, c)]),
                    _ => unreachable!(),
                },
                PartialValue::SshKey(t) => match data.map(|b| (*b).clone()) {
                    Some(DataValue::SshKey(k)) => I::SshKey(btreemap![(t, k)]),
                    _ => unreachable!(),
                },
                PartialValue::SecretValue => match data.map(|b| (*b).clone()) {
                    Some(DataValue::SecretValue(c)) => I::SecretValue(smolset![c]),
                    _ => unreachable!(),
                },
                PartialValue::Spn(n, d) => I::Spn(btreeset![(n, d)]),
                PartialValue::Uint32(i) => I::Uint32(smolset![i]),
                PartialValue::Cid(c) => I::Cid(smolset![c]),
                PartialValue::Nsuniqueid(s) => I::Nsuniqueid(btreeset![s]),
                PartialValue::DateTime(dt) => I::DateTime(smolset![dt]),
                PartialValue::EmailAddress(e) => I::EmailAddress(btreeset![e]),
                PartialValue::Url(u) => I::Url(smolset![u]),
                PartialValue::OauthScope(x) => I::OauthScope(btreeset![x]),
                PartialValue::OauthScopeMap(u) => match data.map(|b| (*b).clone()) {
                    Some(DataValue::OauthScopeMap(c)) => I::OauthScopeMap(btreemap![(u, c)]),
                    _ => unreachable!(),
                },
                PartialValue::Es256PrivateDer => match data.map(|b| (*b).clone()) {
                    Some(DataValue::Es256PrivateDer(c)) => I::Es256PrivateDer(smolset![c]),
                    _ => unreachable!(),
                },
            },
        }
    }

    pub fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        let Value { pv, data } = value;

        match (&mut self.inner, pv) {
            (I::Utf8(set), PartialValue::Utf8(s)) => Ok(set.insert(s)),
            (I::Iutf8(set), PartialValue::Iutf8(s)) => Ok(set.insert(s)),
            (I::Iname(set), PartialValue::Iname(s)) => Ok(set.insert(s)),
            (I::Uuid(set), PartialValue::Uuid(u)) => Ok(set.insert(u)),
            (I::Bool(bs), PartialValue::Bool(b)) => {
                bs.insert(b);
                Ok(true)
            }
            (I::Syntax(set), PartialValue::Syntax(s)) => Ok(set.insert(s)),
            (I::Index(set), PartialValue::Index(i)) => Ok(set.insert(i)),
            (I::Refer(set), PartialValue::Refer(u)) => Ok(set.insert(u)),
            (I::JsonFilt(set), PartialValue::JsonFilt(f)) => Ok(set.insert(f)),
            (I::Cred(map), PartialValue::Cred(t)) => {
                if let BTreeEntry::Vacant(e) = map.entry(t) {
                    match data.map(|b| (*b).clone()) {
                        Some(DataValue::Cred(c)) => Ok({
                            e.insert(c);
                            true
                        }),
                        _ => Err(OperationError::InvalidValueState),
                    }
                } else {
                    Ok(false)
                }
            }
            (I::SshKey(map), PartialValue::SshKey(t)) => {
                if let BTreeEntry::Vacant(e) = map.entry(t) {
                    match data.map(|b| (*b).clone()) {
                        Some(DataValue::SshKey(k)) => Ok({
                            e.insert(k);
                            true
                        }),
                        _ => Err(OperationError::InvalidValueState),
                    }
                } else {
                    Ok(false)
                }
            }
            (I::SecretValue(set), PartialValue::SecretValue) => match data.map(|b| (*b).clone()) {
                Some(DataValue::SecretValue(c)) => Ok(set.insert(c)),
                _ => Err(OperationError::InvalidValueState),
            },
            (I::Spn(set), PartialValue::Spn(n, d)) => Ok(set.insert((n, d))),
            (I::Uint32(set), PartialValue::Uint32(i)) => Ok(set.insert(i)),
            (I::Cid(set), PartialValue::Cid(c)) => Ok(set.insert(c)),
            (I::Nsuniqueid(set), PartialValue::Nsuniqueid(u)) => Ok(set.insert(u)),
            (I::DateTime(set), PartialValue::DateTime(dt)) => Ok(set.insert(dt)),
            (I::EmailAddress(set), PartialValue::EmailAddress(e)) => Ok(set.insert(e)),
            (I::Url(set), PartialValue::Url(u)) => Ok(set.insert(u)),
            (I::OauthScope(set), PartialValue::OauthScope(u)) => Ok(set.insert(u)),
            (I::OauthScopeMap(map), PartialValue::OauthScopeMap(u)) => {
                if let BTreeEntry::Vacant(e) = map.entry(u) {
                    match data.map(|b| (*b).clone()) {
                        Some(DataValue::OauthScopeMap(k)) => Ok({
                            e.insert(k);
                            true
                        }),
                        _ => Err(OperationError::InvalidValueState),
                    }
                } else {
                    Ok(false)
                }
            }
            (I::Es256PrivateDer(set), PartialValue::Es256PrivateDer) => {
                match data.map(|b| (*b).clone()) {
                    Some(DataValue::Es256PrivateDer(c)) => Ok(set.insert(c)),
                    _ => Err(OperationError::InvalidValueState),
                }
            }
            (_, _) => Err(OperationError::InvalidValueState),
        }
    }

    /// # Safety
    /// This is unsafe as you are unable to distinguish the case between
    /// the value already existing, OR the value being an incorrect type to add
    /// to the set.
    pub unsafe fn insert(&mut self, value: Value) -> bool {
        self.insert_checked(value).unwrap_or(false)
    }

    // set values
    pub fn set(&mut self, iter: impl Iterator<Item = Value>) {
        self.clear();
        self.extend(iter);
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), OperationError> {
        match (&mut self.inner, &other.inner) {
            (I::Utf8(a), I::Utf8(b)) => mergesets!(a, b),
            (I::Iutf8(a), I::Iutf8(b)) => {
                mergesets!(a, b)
            }
            (I::Iname(a), I::Iname(b)) => {
                mergesets!(a, b)
            }
            (I::Uuid(a), I::Uuid(b)) => {
                mergesets!(a, b)
            }
            (I::Bool(a), I::Bool(b)) => {
                mergesets!(a, b)
            }
            (I::Syntax(a), I::Syntax(b)) => {
                mergesets!(a, b)
            }
            (I::Index(a), I::Index(b)) => {
                mergesets!(a, b)
            }
            (I::Refer(a), I::Refer(b)) => {
                mergesets!(a, b)
            }
            (I::JsonFilt(a), I::JsonFilt(b)) => {
                mergesets!(a, b)
            }
            (I::Cred(a), I::Cred(b)) => {
                mergemaps!(a, b)
            }
            (I::SshKey(a), I::SshKey(b)) => {
                mergemaps!(a, b)
            }
            (I::SecretValue(a), I::SecretValue(b)) => {
                mergesets!(a, b)
            }
            (I::Spn(a), I::Spn(b)) => {
                mergesets!(a, b)
            }
            (I::Uint32(a), I::Uint32(b)) => {
                mergesets!(a, b)
            }
            (I::Cid(a), I::Cid(b)) => {
                mergesets!(a, b)
            }
            (I::Nsuniqueid(a), I::Nsuniqueid(b)) => {
                mergesets!(a, b)
            }
            (I::DateTime(a), I::DateTime(b)) => {
                mergesets!(a, b)
            }
            (I::EmailAddress(a), I::EmailAddress(b)) => {
                mergesets!(a, b)
            }
            (I::Url(a), I::Url(b)) => {
                mergesets!(a, b)
            }
            (I::OauthScope(a), I::OauthScope(b)) => {
                mergesets!(a, b)
            }
            (I::OauthScopeMap(a), I::OauthScopeMap(b)) => {
                mergemaps!(a, b)
            }
            (I::Es256PrivateDer(a), I::Es256PrivateDer(b)) => {
                mergesets!(a, b)
            }
            // I think that in this case, we need to specify self / everything as we are changing
            // type and we need to potentially purge everything, so we just return the left side.
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn extend(&mut self, iter: impl Iterator<Item = Value>) {
        match &mut self.inner {
            I::Utf8(set) => {
                set.extend(iter.filter_map(|v| v.to_utf8()));
            }
            I::Iutf8(set) => {
                set.extend(iter.filter_map(|v| v.to_iutf8()));
            }
            I::Iname(set) => {
                set.extend(iter.filter_map(|v| v.to_iname()));
            }
            I::Uuid(set) => {
                set.extend(iter.filter_map(|v| v.to_uuid().copied()));
            }
            I::Bool(set) => {
                iter.filter_map(|v| v.to_bool()).for_each(|i| {
                    set.insert(i);
                });
            }
            I::Syntax(set) => {
                iter.filter_map(|v| v.to_syntaxtype().cloned())
                    .for_each(|i| {
                        set.insert(i);
                    });
            }
            I::Index(set) => {
                iter.filter_map(|v| v.to_indextype().cloned())
                    .for_each(|i| {
                        set.insert(i);
                    });
            }
            I::Refer(set) => {
                set.extend(iter.filter_map(|v| v.to_ref_uuid().copied()));
            }
            I::JsonFilt(set) => {
                iter.filter_map(|v| v.to_jsonfilt()).for_each(|i| {
                    set.insert(i);
                });
            }
            I::Cred(map) => {
                map.extend(iter.filter_map(|v| v.to_cred()));
            }
            I::SshKey(map) => {
                map.extend(iter.filter_map(|v| v.to_sshkey()));
            }
            I::SecretValue(set) => {
                iter.filter_map(|v| v.get_secret_str().map(str::to_string))
                    .for_each(|i| {
                        set.insert(i);
                    });
            }
            I::Spn(set) => {
                set.extend(iter.filter_map(|v| v.to_spn()));
            }
            I::Uint32(set) => {
                iter.filter_map(|v| v.to_uint32()).for_each(|i| {
                    set.insert(i);
                });
            }
            I::Cid(set) => {
                iter.filter_map(|v| v.to_cid()).for_each(|i| {
                    set.insert(i);
                });
            }
            I::Nsuniqueid(set) => {
                set.extend(iter.filter_map(|v| v.to_nsuniqueid()));
            }
            I::DateTime(set) => {
                iter.filter_map(|v| v.to_datetime()).for_each(|i| {
                    set.insert(i);
                });
            }
            I::EmailAddress(set) => {
                set.extend(iter.filter_map(|v| v.to_emailaddress()));
            }
            I::Url(set) => {
                iter.filter_map(|v| v.to_url().cloned()).for_each(|i| {
                    set.insert(i);
                });
            }
            I::OauthScope(set) => {
                set.extend(iter.filter_map(|v| v.to_oauthscope()));
            }
            I::OauthScopeMap(map) => {
                map.extend(iter.filter_map(|v| v.to_oauthscopemap()));
            }
            I::Es256PrivateDer(set) => {
                iter.filter_map(|v| v.to_es256privateder().cloned())
                    .for_each(|i| {
                        set.insert(i);
                    });
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        match &mut self.inner {
            I::Utf8(set) => {
                set.clear();
            }
            I::Iutf8(set) => {
                set.clear();
            }
            I::Iname(set) => {
                set.clear();
            }
            I::Uuid(set) => {
                set.clear();
            }
            I::Bool(set) => {
                set.clear();
            }
            I::Syntax(set) => {
                set.clear();
            }
            I::Index(set) => {
                set.clear();
            }
            I::Refer(set) => {
                set.clear();
            }
            I::JsonFilt(set) => {
                set.clear();
            }
            I::Cred(map) => {
                map.clear();
            }
            I::SshKey(map) => {
                map.clear();
            }
            I::SecretValue(set) => {
                set.clear();
            }
            I::Spn(set) => {
                set.clear();
            }
            I::Uint32(set) => {
                set.clear();
            }
            I::Cid(set) => {
                set.clear();
            }
            I::Nsuniqueid(set) => {
                set.clear();
            }
            I::DateTime(set) => {
                set.clear();
            }
            I::EmailAddress(set) => {
                set.clear();
            }
            I::Url(set) => {
                set.clear();
            }
            I::OauthScope(set) => {
                set.clear();
            }
            I::OauthScopeMap(map) => {
                map.clear();
            }
            I::Es256PrivateDer(set) => {
                set.clear();
            }
        };
        debug_assert!(self.is_empty());
    }

    // delete a value
    pub fn remove(&mut self, pv: &PartialValue) -> bool {
        match (&mut self.inner, pv) {
            (I::Utf8(set), PartialValue::Utf8(s)) => {
                set.remove(s);
            }
            (I::Iutf8(set), PartialValue::Iutf8(s)) => {
                set.remove(s);
            }
            (I::Iname(set), PartialValue::Iname(s)) => {
                set.remove(s);
            }
            (I::Uuid(set), PartialValue::Uuid(u)) => {
                set.remove(u);
            }
            (I::Bool(set), PartialValue::Bool(b)) => {
                set.remove(b);
            }
            (I::Syntax(set), PartialValue::Syntax(s)) => {
                set.remove(s);
            }
            (I::Index(set), PartialValue::Index(i)) => {
                set.remove(i);
            }
            (I::Refer(set), PartialValue::Refer(u)) => {
                set.remove(u);
            }
            (I::JsonFilt(set), PartialValue::JsonFilt(f)) => {
                set.remove(f);
            }
            (I::Cred(map), PartialValue::Cred(t)) => {
                map.remove(t);
            }
            (I::SshKey(map), PartialValue::SshKey(t)) => {
                map.remove(t);
            }
            (I::SecretValue(_set), PartialValue::SecretValue) => {
                debug_assert!(false)
            }
            (I::Spn(set), PartialValue::Spn(n, d)) => {
                set.remove(&(n.to_string(), d.to_string()));
            }
            (I::Uint32(set), PartialValue::Uint32(i)) => {
                set.remove(i);
            }
            (I::Cid(set), PartialValue::Cid(c)) => {
                set.remove(c);
            }
            (I::Nsuniqueid(set), PartialValue::Nsuniqueid(u)) => {
                set.remove(u);
            }
            (I::DateTime(set), PartialValue::DateTime(dt)) => {
                set.remove(dt);
            }
            (I::EmailAddress(set), PartialValue::EmailAddress(e)) => {
                set.remove(e);
            }
            (I::Url(set), PartialValue::Url(u)) => {
                set.remove(u);
            }
            (I::OauthScope(set), PartialValue::OauthScope(u)) => {
                set.remove(u);
            }
            (I::OauthScopeMap(set), PartialValue::OauthScopeMap(u))
            | (I::OauthScopeMap(set), PartialValue::Refer(u)) => {
                set.remove(u);
            }
            (I::Es256PrivateDer(_set), PartialValue::Es256PrivateDer) => {
                debug_assert!(false)
            }
            (_, _) => {
                debug_assert!(false)
            }
        };
        true
    }

    pub fn contains(&self, pv: &PartialValue) -> bool {
        match (&self.inner, pv) {
            (I::Utf8(set), PartialValue::Utf8(s)) => set.contains(s.as_str()),
            (I::Iutf8(set), PartialValue::Iutf8(s)) => set.contains(s.as_str()),
            (I::Iname(set), PartialValue::Iname(s)) => set.contains(s.as_str()),
            (I::Uuid(set), PartialValue::Uuid(u)) => set.contains(u),
            (I::Bool(set), PartialValue::Bool(b)) => set.contains(b),
            (I::Syntax(set), PartialValue::Syntax(s)) => set.contains(s),
            (I::Index(set), PartialValue::Index(i)) => set.contains(i),
            (I::Refer(set), PartialValue::Refer(u)) => set.contains(u),
            (I::JsonFilt(set), PartialValue::JsonFilt(f)) => set.contains(f),
            (I::Cred(map), PartialValue::Cred(t)) => map.contains_key(t.as_str()),
            (I::SshKey(map), PartialValue::SshKey(t)) => map.contains_key(t.as_str()),
            (I::SecretValue(_set), PartialValue::SecretValue) => false,
            // Borrowing into a &(&string, &string) doesn't work here, and spn is small so we iterate
            // instead.
            (I::Spn(set), PartialValue::Spn(n, d)) => set.iter().any(|(a, b)| a == n && b == d),
            (I::Uint32(set), PartialValue::Uint32(i)) => set.contains(i),
            (I::Cid(set), PartialValue::Cid(c)) => set.contains(c),
            (I::Nsuniqueid(set), PartialValue::Nsuniqueid(u)) => set.contains(u.as_str()),
            (I::DateTime(set), PartialValue::DateTime(dt)) => set.contains(dt),
            (I::EmailAddress(set), PartialValue::EmailAddress(e)) => set.contains(e.as_str()),
            (I::Url(set), PartialValue::Url(u)) => set.contains(u),
            (I::OauthScope(set), PartialValue::OauthScope(u)) => set.contains(u),
            (I::OauthScopeMap(map), PartialValue::OauthScopeMap(u))
            | (I::OauthScopeMap(map), PartialValue::Refer(u)) => map.contains_key(u),
            (I::Es256PrivateDer(_set), PartialValue::Es256PrivateDer) => false,
            _ => false,
        }
    }

    pub fn substring(&self, pv: &PartialValue) -> bool {
        match (&self.inner, pv) {
            (I::Utf8(set), PartialValue::Utf8(s2)) => set.iter().any(|s1| s1.contains(s2)),
            (I::Iutf8(set), PartialValue::Iutf8(s2)) => set.iter().any(|s1| s1.contains(s2)),
            (I::Iname(set), PartialValue::Iname(s2)) => set.iter().any(|s1| s1.contains(s2)),
            _ => false,
        }
    }

    pub fn lessthan(&self, pv: &PartialValue) -> bool {
        match (&self.inner, pv) {
            (I::Cid(set), PartialValue::Cid(c2)) => set.iter().any(|c1| c1 < c2),
            (I::Uint32(set), PartialValue::Uint32(u2)) => set.iter().any(|u1| u1 < u2),
            _ => false,
        }
    }

    pub fn len(&self) -> usize {
        match &self.inner {
            I::Utf8(set) => set.len(),
            I::Iutf8(set) => set.len(),
            I::Iname(set) => set.len(),
            I::Uuid(set) => set.len(),
            I::Bool(set) => set.len(),
            I::Syntax(set) => set.len(),
            I::Index(set) => set.len(),
            I::Refer(set) => set.len(),
            I::JsonFilt(set) => set.len(),
            I::Cred(map) => map.len(),
            I::SshKey(map) => map.len(),
            I::SecretValue(set) => set.len(),
            I::Spn(set) => set.len(),
            I::Uint32(set) => set.len(),
            I::Cid(set) => set.len(),
            I::Nsuniqueid(set) => set.len(),
            I::DateTime(set) => set.len(),
            I::EmailAddress(set) => set.len(),
            I::Url(set) => set.len(),
            I::OauthScope(set) => set.len(),
            I::OauthScopeMap(set) => set.len(),
            I::Es256PrivateDer(set) => set.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn generate_idx_eq_keys(&self) -> Vec<String> {
        match &self.inner {
            I::Utf8(set) => set.iter().cloned().collect(),
            I::Iutf8(set) => set.iter().cloned().collect(),
            I::Iname(set) => set.iter().cloned().collect(),
            I::Uuid(set) => set
                .iter()
                .map(|u| u.to_hyphenated_ref().to_string())
                .collect(),
            I::Bool(set) => set.iter().map(|u| u.to_string()).collect(),
            I::Syntax(set) => set.iter().map(|u| u.to_string()).collect(),
            I::Index(set) => set.iter().map(|u| u.to_string()).collect(),
            I::Refer(set) => set
                .iter()
                .map(|u| u.to_hyphenated_ref().to_string())
                .collect(),
            I::JsonFilt(set) => set
                .iter()
                .map(|s| {
                    #[allow(clippy::expect_used)]
                    serde_json::to_string(s)
                        .expect("A json filter value was corrupted during run-time")
                })
                .collect(),
            I::Cred(map) => map.keys().cloned().collect(),
            I::SshKey(map) => map.keys().cloned().collect(),
            I::SecretValue(_set) => vec![],
            I::Spn(set) => set.iter().map(|(n, d)| format!("{}@{}", n, d)).collect(),
            I::Uint32(set) => set.iter().map(|u| u.to_string()).collect(),
            I::Cid(_set) => vec![],
            I::Nsuniqueid(set) => set.iter().cloned().collect(),
            I::DateTime(set) => set
                .iter()
                .map(|odt| {
                    debug_assert!(odt.offset() == time::UtcOffset::UTC);
                    odt.format(time::Format::Rfc3339)
                })
                .collect(),
            I::EmailAddress(set) => set.iter().cloned().collect(),
            // Don't you dare comment on this quinn, it's a URL not a str.
            I::Url(set) => set.iter().map(|u| u.to_string()).collect(),
            // Should we index this?
            // I::OauthScope(set) => set.iter().map(|u| u.to_string()).collect(),
            I::OauthScope(_set) => vec![],
            I::OauthScopeMap(map) => map
                .keys()
                .map(|u| u.to_hyphenated_ref().to_string())
                .collect(),
            I::Es256PrivateDer(_set) => vec![],
        }
    }

    pub fn idx_eq_key_difference<'a>(&'a self, other: &'a ValueSet) -> Option<ValueSet> {
        // The values in self, that are not in other.
        match (&self.inner, &other.inner) {
            (I::Utf8(a), I::Utf8(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Utf8(x) })
                }
            }
            (I::Iutf8(a), I::Iutf8(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Iutf8(x) })
                }
            }
            (I::Iname(a), I::Iname(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Iname(x) })
                }
            }
            (I::Uuid(a), I::Uuid(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Uuid(x) })
                }
            }
            (I::Bool(a), I::Bool(b)) => {
                let x: SmolSet<_> = a.difference(b).copied().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Bool(x) })
                }
            }
            (I::Syntax(a), I::Syntax(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::Syntax(x),
                    })
                }
            }
            (I::Index(a), I::Index(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Index(x) })
                }
            }
            (I::Refer(a), I::Refer(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Refer(x) })
                }
            }
            (I::JsonFilt(a), I::JsonFilt(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::JsonFilt(x),
                    })
                }
            }
            (I::Cred(a), I::Cred(b)) => {
                let x: BTreeMap<_, _> = a
                    .iter()
                    .filter(|(k, _)| b.contains_key(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Cred(x) })
                }
            }
            (I::SshKey(a), I::SshKey(b)) => {
                let x: BTreeMap<_, _> = a
                    .iter()
                    .filter(|(k, _)| b.contains_key(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::SshKey(x),
                    })
                }
            }
            (I::SecretValue(a), I::SecretValue(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::SecretValue(x),
                    })
                }
            }
            (I::Spn(a), I::Spn(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Spn(x) })
                }
            }
            (I::Uint32(a), I::Uint32(b)) => {
                let x: SmolSet<_> = a.difference(b).copied().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::Uint32(x),
                    })
                }
            }
            (I::Cid(a), I::Cid(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Cid(x) })
                }
            }
            (I::Nsuniqueid(a), I::Nsuniqueid(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::Nsuniqueid(x),
                    })
                }
            }
            (I::DateTime(a), I::DateTime(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::DateTime(x),
                    })
                }
            }
            (I::EmailAddress(a), I::EmailAddress(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::EmailAddress(x),
                    })
                }
            }
            (I::Url(a), I::Url(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet { inner: I::Url(x) })
                }
            }
            (I::OauthScope(a), I::OauthScope(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::OauthScope(x),
                    })
                }
            }
            (I::OauthScopeMap(a), I::OauthScopeMap(b)) => {
                let x: BTreeMap<_, _> = a
                    .iter()
                    .filter(|(k, _)| b.contains_key(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::OauthScopeMap(x),
                    })
                }
            }
            (I::Es256PrivateDer(a), I::Es256PrivateDer(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::Es256PrivateDer(x),
                    })
                }
            }
            // I think that in this case, we need to specify self / everything as we are changing
            // type and we need to potentially purge everything, so we just return the left side.
            _ => Some(self.clone()),
        }
    }

    pub fn get_ssh_tag(&self, tag: &str) -> Option<&str> {
        match &self.inner {
            I::SshKey(map) => map.get(tag).map(|s| s.as_str()),
            _ => None,
        }
    }

    pub fn as_uuid_set(&self) -> Option<&BTreeSet<Uuid>> {
        // Need to return refer or not?
        match &self.inner {
            I::Uuid(set) => Some(set),
            _ => None,
        }
    }

    pub fn as_refer_set(&self) -> Option<&BTreeSet<Uuid>> {
        match &self.inner {
            I::Refer(set) => Some(set),
            _ => None,
        }
    }

    pub fn as_sshkey_map(&self) -> Option<&BTreeMap<String, String>> {
        match &self.inner {
            I::SshKey(map) => Some(map),
            _ => None,
        }
    }

    pub fn to_value_single(&self) -> Option<Value> {
        if self.len() != 1 {
            return None;
        }
        // From here it's guarantee everything is len 1.
        match &self.inner {
            I::Utf8(set) => set.iter().take(1).next().cloned().map(Value::new_utf8),
            I::Iutf8(set) => set
                .iter()
                .take(1)
                .next()
                .map(|s| s.as_str())
                .map(Value::new_iutf8),
            I::Iname(set) => set
                .iter()
                .take(1)
                .next()
                .map(|s| s.as_str())
                .map(Value::new_iname),
            I::Uuid(set) => set.iter().take(1).next().map(Value::new_uuidr),
            I::Bool(set) => set.iter().take(1).next().copied().map(Value::new_bool),
            I::Syntax(set) => set.iter().take(1).next().cloned().map(Value::new_syntax),
            I::Index(set) => set.iter().take(1).next().cloned().map(Value::new_index),
            I::Refer(set) => set.iter().take(1).next().map(Value::new_refer_r),
            I::JsonFilt(set) => set
                .iter()
                .take(1)
                .next()
                .cloned()
                .map(Value::new_json_filter),
            I::Cred(map) => map
                .iter()
                .take(1)
                .next()
                .map(|(t, c)| Value::new_credential(t, c.clone())),
            I::SshKey(map) => map
                .iter()
                .take(1)
                .next()
                .map(|(t, k)| Value::new_sshkey_str(t, k)),
            I::SecretValue(set) => set
                .iter()
                .take(1)
                .next()
                .map(|s| s.as_str())
                .map(Value::new_secret_str),
            I::Spn(set) => set
                .iter()
                .take(1)
                .next()
                .map(|(n, r)| Value::new_spn_str(n, r)),
            I::Uint32(set) => set.iter().take(1).next().copied().map(Value::new_uint32),
            I::Cid(set) => set.iter().take(1).next().cloned().map(Value::new_cid),
            I::Nsuniqueid(set) => set
                .iter()
                .take(1)
                .next()
                .map(|s| s.as_str())
                .map(Value::new_nsuniqueid_s),
            I::DateTime(set) => set.iter().take(1).next().cloned().map(Value::new_datetime),
            I::EmailAddress(set) => set
                .iter()
                .take(1)
                .next()
                .map(|s| s.as_str())
                .map(Value::new_email_address_s),
            I::Url(set) => set.iter().take(1).next().cloned().map(Value::new_url),
            I::OauthScope(set) => set
                .iter()
                .take(1)
                .next()
                .map(|s| s.as_str())
                .map(Value::new_oauthscope),
            I::OauthScopeMap(map) => map
                .iter()
                .take(1)
                .next()
                .map(|(u, s)| Value::new_oauthscopemap(*u, s.clone())),
            I::Es256PrivateDer(set) => set.iter().take(1).next().map(Value::new_es256privateder),
        }
    }

    pub fn to_proto_string_single(&self) -> Option<String> {
        if self.len() != 1 {
            None
        } else {
            self.to_proto_string_clone_iter().take(1).next()
        }
    }

    pub fn to_uuid_single(&self) -> Option<&Uuid> {
        match &self.inner {
            I::Uuid(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_refer_single(&self) -> Option<&Uuid> {
        match &self.inner {
            I::Refer(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_bool_single(&self) -> Option<bool> {
        match &self.inner {
            I::Bool(set) => {
                if set.len() == 1 {
                    set.iter().take(1).copied().next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_uint32_single(&self) -> Option<u32> {
        match &self.inner {
            I::Uint32(set) => {
                if set.len() == 1 {
                    set.iter().take(1).copied().next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_syntaxtype_single(&self) -> Option<&SyntaxType> {
        match &self.inner {
            I::Syntax(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_credential_single(&self) -> Option<&Credential> {
        match &self.inner {
            I::Cred(map) => {
                if map.len() == 1 {
                    map.values().take(1).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_secret_single(&self) -> Option<&str> {
        match &self.inner {
            I::SecretValue(set) => {
                if set.len() == 1 {
                    set.iter().take(1).map(|s| s.as_str()).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_str_single(&self) -> Option<&str> {
        match &self.inner {
            I::Utf8(set) | I::Iutf8(set) | I::Iname(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next().map(|s| s.as_str())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_datetime_single(&self) -> Option<OffsetDateTime> {
        match &self.inner {
            I::DateTime(set) => {
                if set.len() == 1 {
                    set.iter().take(1).cloned().next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_url_single(&self) -> Option<&Url> {
        match &self.inner {
            I::Url(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_json_filter_single(&self) -> Option<&ProtoFilter> {
        match &self.inner {
            I::JsonFilt(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_es256_private_key_der_single(&self) -> Option<&[u8]> {
        match &self.inner {
            I::Es256PrivateDer(set) => {
                if set.len() == 1 {
                    set.iter().take(1).next().map(|v| v.as_slice())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn as_classname_iter(&self) -> Option<impl Iterator<Item = &str>> {
        match &self.inner {
            I::Iutf8(set) => Some(set.iter().map(|s| s.as_str())),
            _ => None,
        }
    }

    pub fn as_indextype_set(&self) -> Option<impl Iterator<Item = &IndexType>> {
        match &self.inner {
            I::Index(set) => Some(set.iter()),
            _ => None,
        }
    }

    pub fn as_str_iter(&self) -> Option<impl Iterator<Item = &str>> {
        match &self.inner {
            I::Iutf8(set) | I::Utf8(set) => Some(Left(set.iter().map(|s| s.as_str()))),
            I::Iname(set) => Some(Right(set.iter().map(|s| s.as_str()))),
            _ => None,
        }
    }

    // Value::Refer
    pub fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = &Uuid> + '_>> {
        match &self.inner {
            I::Refer(set) => Some(Box::new(set.iter())),
            I::OauthScopeMap(map) => Some(Box::new(map.keys())),
            _ => None,
        }
    }

    pub fn as_sshpubkey_str_iter(&self) -> Option<impl Iterator<Item = &str>> {
        match &self.inner {
            I::SshKey(set) => Some(set.values().map(|s| s.as_str())),
            _ => None,
        }
    }

    pub fn as_oauthscope_iter(&self) -> Option<impl Iterator<Item = &str>> {
        match &self.inner {
            I::OauthScope(set) => Some(set.iter().map(|s| s.as_str())),
            _ => None,
        }
    }

    pub fn as_oauthscopemap(&self) -> Option<&BTreeMap<Uuid, BTreeSet<String>>> {
        match &self.inner {
            I::OauthScopeMap(map) => Some(map),
            _ => None,
        }
    }

    pub fn to_proto_string_clone_iter(&self) -> ProtoIter<'_> {
        // to_proto_string_clone
        match &self.inner {
            I::Utf8(set) => ProtoIter::Utf8(set.iter()),
            I::Iutf8(set) => ProtoIter::Iutf8(set.iter()),
            I::Iname(set) => ProtoIter::Iname(set.iter()),
            I::Uuid(set) => ProtoIter::Uuid(set.iter()),
            I::Bool(set) => ProtoIter::Bool(set.iter()),
            I::Syntax(set) => ProtoIter::Syntax(set.iter()),
            I::Index(set) => ProtoIter::Index(set.iter()),
            I::Refer(set) => ProtoIter::Refer(set.iter()),
            I::JsonFilt(set) => ProtoIter::JsonFilt(set.iter()),
            I::Cred(map) => ProtoIter::Cred(map.iter()),
            I::SshKey(map) => ProtoIter::SshKey(map.iter()),
            I::SecretValue(set) => ProtoIter::SecretValue(set.iter()),
            I::Spn(set) => ProtoIter::Spn(set.iter()),
            I::Uint32(set) => ProtoIter::Uint32(set.iter()),
            I::Cid(set) => ProtoIter::Cid(set.iter()),
            I::Nsuniqueid(set) => ProtoIter::Nsuniqueid(set.iter()),
            I::DateTime(set) => ProtoIter::DateTime(set.iter()),
            I::EmailAddress(set) => ProtoIter::EmailAddress(set.iter()),
            I::Url(set) => ProtoIter::Url(set.iter()),
            I::OauthScope(set) => ProtoIter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => ProtoIter::OauthScopeMap(set.iter()),
            I::Es256PrivateDer(set) => ProtoIter::Es256PrivateDer(set.iter()),
        }
    }

    pub fn to_db_valuev1_iter(&self) -> DbValueV1Iter<'_> {
        match &self.inner {
            I::Utf8(set) => DbValueV1Iter::Utf8(set.iter()),
            I::Iutf8(set) => DbValueV1Iter::Iutf8(set.iter()),
            I::Iname(set) => DbValueV1Iter::Iname(set.iter()),
            I::Uuid(set) => DbValueV1Iter::Uuid(set.iter()),
            I::Bool(set) => DbValueV1Iter::Bool(set.iter()),
            I::Syntax(set) => DbValueV1Iter::Syntax(set.iter()),
            I::Index(set) => DbValueV1Iter::Index(set.iter()),
            I::Refer(set) => DbValueV1Iter::Refer(set.iter()),
            I::JsonFilt(set) => DbValueV1Iter::JsonFilt(set.iter()),
            I::Cred(map) => DbValueV1Iter::Cred(map.iter()),
            I::SshKey(map) => DbValueV1Iter::SshKey(map.iter()),
            I::SecretValue(set) => DbValueV1Iter::SecretValue(set.iter()),
            I::Spn(set) => DbValueV1Iter::Spn(set.iter()),
            I::Uint32(set) => DbValueV1Iter::Uint32(set.iter()),
            I::Cid(set) => DbValueV1Iter::Cid(set.iter()),
            I::Nsuniqueid(set) => DbValueV1Iter::Nsuniqueid(set.iter()),
            I::DateTime(set) => DbValueV1Iter::DateTime(set.iter()),
            I::EmailAddress(set) => DbValueV1Iter::EmailAddress(set.iter()),
            I::Url(set) => DbValueV1Iter::Url(set.iter()),
            I::OauthScope(set) => DbValueV1Iter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => DbValueV1Iter::OauthScopeMap(set.iter()),
            I::Es256PrivateDer(set) => DbValueV1Iter::Es256PrivateDer(set.iter()),
        }
    }

    pub fn to_partialvalue_iter(&self) -> PartialValueIter<'_> {
        match &self.inner {
            I::Utf8(set) => PartialValueIter::Utf8(set.iter()),
            I::Iutf8(set) => PartialValueIter::Iutf8(set.iter()),
            I::Iname(set) => PartialValueIter::Iname(set.iter()),
            I::Uuid(set) => PartialValueIter::Uuid(set.iter()),
            I::Bool(set) => PartialValueIter::Bool(set.iter()),
            I::Syntax(set) => PartialValueIter::Syntax(set.iter()),
            I::Index(set) => PartialValueIter::Index(set.iter()),
            I::Refer(set) => PartialValueIter::Refer(set.iter()),
            I::JsonFilt(set) => PartialValueIter::JsonFilt(set.iter()),
            I::Cred(map) => PartialValueIter::Cred(map.iter()),
            I::SshKey(map) => PartialValueIter::SshKey(map.iter()),
            I::SecretValue(set) => PartialValueIter::SecretValue(set.iter()),
            I::Spn(set) => PartialValueIter::Spn(set.iter()),
            I::Uint32(set) => PartialValueIter::Uint32(set.iter()),
            I::Cid(set) => PartialValueIter::Cid(set.iter()),
            I::Nsuniqueid(set) => PartialValueIter::Nsuniqueid(set.iter()),
            I::DateTime(set) => PartialValueIter::DateTime(set.iter()),
            I::EmailAddress(set) => PartialValueIter::EmailAddress(set.iter()),
            I::Url(set) => PartialValueIter::Url(set.iter()),
            I::OauthScope(set) => PartialValueIter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => PartialValueIter::OauthScopeMap(set.iter()),
            I::Es256PrivateDer(set) => PartialValueIter::Es256PrivateDer(set.iter()),
        }
    }

    pub fn to_value_iter(&self) -> ValueIter<'_> {
        match &self.inner {
            I::Utf8(set) => ValueIter::Utf8(set.iter()),
            I::Iutf8(set) => ValueIter::Iutf8(set.iter()),
            I::Iname(set) => ValueIter::Iname(set.iter()),
            I::Uuid(set) => ValueIter::Uuid(set.iter()),
            I::Bool(set) => ValueIter::Bool(set.iter()),
            I::Syntax(set) => ValueIter::Syntax(set.iter()),
            I::Index(set) => ValueIter::Index(set.iter()),
            I::Refer(set) => ValueIter::Refer(set.iter()),
            I::JsonFilt(set) => ValueIter::JsonFilt(set.iter()),
            I::Cred(map) => ValueIter::Cred(map.iter()),
            I::SshKey(map) => ValueIter::SshKey(map.iter()),
            I::SecretValue(set) => ValueIter::SecretValue(set.iter()),
            I::Spn(set) => ValueIter::Spn(set.iter()),
            I::Uint32(set) => ValueIter::Uint32(set.iter()),
            I::Cid(set) => ValueIter::Cid(set.iter()),
            I::Nsuniqueid(set) => ValueIter::Nsuniqueid(set.iter()),
            I::DateTime(set) => ValueIter::DateTime(set.iter()),
            I::EmailAddress(set) => ValueIter::EmailAddress(set.iter()),
            I::Url(set) => ValueIter::Url(set.iter()),
            I::OauthScope(set) => ValueIter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => ValueIter::OauthScopeMap(set.iter()),
            I::Es256PrivateDer(set) => ValueIter::Es256PrivateDer(set.iter()),
        }
    }

    pub fn from_result_value_iter(
        mut iter: impl Iterator<Item = Result<Value, OperationError>>,
    ) -> Result<Self, OperationError> {
        let init = if let Some(v) = iter.next() {
            v
        } else {
            admin_error!("Empty value iterator");
            return Err(OperationError::InvalidValueState);
        };

        let init = init?;
        let mut vs = ValueSet::new(init);

        for maybe_v in iter {
            let v = maybe_v?;
            // Need to error if wrong type
            vs.insert_checked(v)?;
        }
        Ok(vs)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self.inner, I::Bool(_))
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self.inner, I::Syntax(_))
    }

    pub fn is_uuid(&self) -> bool {
        matches!(self.inner, I::Uuid(_))
    }

    pub fn is_refer(&self) -> bool {
        matches!(self.inner, I::Refer(_))
    }

    pub fn is_index(&self) -> bool {
        matches!(self.inner, I::Index(_))
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        matches!(self.inner, I::Iutf8(_))
    }

    pub fn is_iname(&self) -> bool {
        matches!(self.inner, I::Iname(_))
    }

    pub fn is_utf8(&self) -> bool {
        matches!(self.inner, I::Utf8(_))
    }

    pub fn is_json_filter(&self) -> bool {
        matches!(self.inner, I::JsonFilt(_))
    }

    pub fn is_credential(&self) -> bool {
        matches!(self.inner, I::Cred(_))
    }

    pub fn is_secret_string(&self) -> bool {
        matches!(self.inner, I::SecretValue(_))
    }

    pub fn is_sshkey(&self) -> bool {
        matches!(self.inner, I::SshKey(_))
    }

    pub fn is_spn(&self) -> bool {
        matches!(self.inner, I::Spn(_))
    }

    pub fn is_uint32(&self) -> bool {
        matches!(self.inner, I::Uint32(_))
    }

    pub fn is_cid(&self) -> bool {
        matches!(self.inner, I::Cid(_))
    }

    pub fn is_nsuniqueid(&self) -> bool {
        matches!(self.inner, I::Nsuniqueid(_))
    }

    pub fn is_datetime(&self) -> bool {
        matches!(self.inner, I::DateTime(_))
    }

    pub fn is_email_address(&self) -> bool {
        matches!(self.inner, I::EmailAddress(_))
    }

    pub fn is_url(&self) -> bool {
        matches!(self.inner, I::Url(_))
    }

    pub fn is_oauthscope(&self) -> bool {
        matches!(self.inner, I::OauthScope(_))
    }

    pub fn is_oauthscopemap(&self) -> bool {
        matches!(self.inner, I::OauthScopeMap(_))
    }

    pub fn is_es256privateder(&self) -> bool {
        matches!(self.inner, I::Es256PrivateDer(_))
    }

    pub fn migrate_iutf8_iname(&mut self) -> Result<(), OperationError> {
        // Swap iutf8 to Iname internally.
        let ninner = match &self.inner {
            I::Iutf8(set) => Some(I::Iname(set.clone())),
            _ => None,
        };

        if let Some(mut ninner) = ninner {
            std::mem::swap(&mut ninner, &mut self.inner);
        }
        trace!(valueset = tracing::field::debug(&self.inner));

        Ok(())
    }
}

impl PartialEq for ValueSet {
    fn eq(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (I::Utf8(a), I::Utf8(b)) => a.eq(b),
            (I::Iutf8(a), I::Iutf8(b)) => a.eq(b),
            (I::Iname(a), I::Iname(b)) => a.eq(b),
            (I::Uuid(a), I::Uuid(b)) => a.eq(b),
            (I::Bool(a), I::Bool(b)) => a.eq(b),
            (I::Syntax(a), I::Syntax(b)) => a.eq(b),
            (I::Index(a), I::Index(b)) => a.eq(b),
            (I::Refer(a), I::Refer(b)) => a.eq(b),
            (I::JsonFilt(a), I::JsonFilt(b)) => a.eq(b),
            // May not be possible to do?
            // (I::Cred(a), I::Cred(b)) => a.eq(b),
            (I::SshKey(a), I::SshKey(b)) => a.eq(b),
            (I::SecretValue(a), I::SecretValue(b)) => a.eq(b),
            (I::Spn(a), I::Spn(b)) => a.eq(b),
            (I::Uint32(a), I::Uint32(b)) => a.eq(b),
            (I::Cid(a), I::Cid(b)) => a.eq(b),
            (I::Nsuniqueid(a), I::Nsuniqueid(b)) => a.eq(b),
            (I::DateTime(a), I::DateTime(b)) => a.eq(b),
            (I::EmailAddress(a), I::EmailAddress(b)) => a.eq(b),
            (I::Url(a), I::Url(b)) => a.eq(b),
            (I::OauthScope(a), I::OauthScope(b)) => a.eq(b),
            (I::OauthScopeMap(a), I::OauthScopeMap(b)) => a.eq(b),
            (I::Es256PrivateDer(a), I::Es256PrivateDer(b)) => a.eq(b),
            _ => false,
        }
    }
}

impl FromIterator<Value> for Option<ValueSet> {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Value>,
    {
        let mut iter = iter.into_iter();
        // Get a first element, vs has to have at least one.
        let mut vs = if let Some(v) = iter.next() {
            ValueSet::new(v)
        } else {
            return None;
        };

        // Now finish it up.
        vs.extend(iter);
        Some(vs)
    }
}

impl Clone for ValueSet {
    fn clone(&self) -> Self {
        ValueSet {
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Debug for ValueSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValueSet")
            .field("inner", &self.inner)
            .finish()
    }
}

pub enum ValueIter<'a> {
    Utf8(std::collections::btree_set::Iter<'a, String>),
    Iutf8(std::collections::btree_set::Iter<'a, String>),
    Iname(std::collections::btree_set::Iter<'a, String>),
    Uuid(std::collections::btree_set::Iter<'a, Uuid>),
    Bool(SmolSetIter<'a, [bool; 1]>),
    Syntax(SmolSetIter<'a, [SyntaxType; 1]>),
    Index(SmolSetIter<'a, [IndexType; 1]>),
    Refer(std::collections::btree_set::Iter<'a, Uuid>),
    JsonFilt(SmolSetIter<'a, [ProtoFilter; 1]>),
    Cred(std::collections::btree_map::Iter<'a, String, Credential>),
    SshKey(std::collections::btree_map::Iter<'a, String, String>),
    SecretValue(SmolSetIter<'a, [String; 1]>),
    Spn(std::collections::btree_set::Iter<'a, (String, String)>),
    Uint32(SmolSetIter<'a, [u32; 1]>),
    Cid(SmolSetIter<'a, [Cid; 1]>),
    Nsuniqueid(std::collections::btree_set::Iter<'a, String>),
    DateTime(SmolSetIter<'a, [OffsetDateTime; 1]>),
    EmailAddress(std::collections::btree_set::Iter<'a, String>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    Es256PrivateDer(SmolSetIter<'a, [Vec<u8>; 1]>),
}

impl<'a> Iterator for ValueIter<'a> {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        match self {
            ValueIter::Utf8(iter) => iter.next().map(|i| Value::new_utf8s(i.as_str())),
            ValueIter::Iutf8(iter) => iter.next().map(|i| Value::new_iutf8(i.as_str())),
            ValueIter::Iname(iter) => iter.next().map(|i| Value::new_iname(i.as_str())),
            ValueIter::Uuid(iter) => iter.next().map(|i| Value::new_uuidr(i)),
            ValueIter::Bool(iter) => iter.next().map(
                // Use the from bool impl.
                Value::from,
            ),
            ValueIter::Syntax(iter) => iter.next().map(|i|
                // Uses the "from syntax type" impl.
                Value::from(i.clone())),
            ValueIter::Index(iter) => iter.next().map(|i|
                // Uses the from index type impl.
                Value::from(i.clone())),
            ValueIter::Refer(iter) => iter.next().map(|i| Value::new_refer_r(i)),
            ValueIter::JsonFilt(iter) => iter.next().map(|i| Value::from(i.clone())),
            ValueIter::Cred(iter) => iter
                .next()
                .map(|(tag, cred)| Value::new_credential(tag.as_str(), cred.clone())),
            ValueIter::SshKey(iter) => iter
                .next()
                .map(|(tag, key)| Value::new_sshkey(tag.clone(), key.clone())),
            ValueIter::SecretValue(iter) => iter.next().map(|i| Value::new_secret_str(i.as_str())),
            ValueIter::Spn(iter) => iter
                .next()
                .map(|(n, d)| Value::new_spn_str(n.as_str(), d.as_str())),
            ValueIter::Uint32(iter) => iter.next().copied().map(Value::from),
            ValueIter::Cid(iter) => iter.next().map(|i| Value::new_cid(i.clone())),
            ValueIter::Nsuniqueid(iter) => {
                iter.next().map(|i| Value::new_email_address_s(i.as_str()))
            }
            ValueIter::DateTime(iter) => iter.next().copied().map(Value::from),
            ValueIter::EmailAddress(iter) => {
                iter.next().map(|i| Value::new_email_address_s(i.as_str()))
            }
            ValueIter::Url(iter) => iter.next().map(|i| Value::from(i.clone())),
            ValueIter::OauthScope(iter) => iter.next().map(|i| Value::new_oauthscope(i)),
            ValueIter::OauthScopeMap(iter) => iter
                .next()
                .map(|(group, scopes)| Value::new_oauthscopemap(*group, scopes.clone())),
            ValueIter::Es256PrivateDer(iter) => iter.next().map(|i| Value::new_es256privateder(i)),
        }
    }
}

pub enum PartialValueIter<'a> {
    Utf8(std::collections::btree_set::Iter<'a, String>),
    Iutf8(std::collections::btree_set::Iter<'a, String>),
    Iname(std::collections::btree_set::Iter<'a, String>),
    Uuid(std::collections::btree_set::Iter<'a, Uuid>),
    Bool(SmolSetIter<'a, [bool; 1]>),
    Syntax(SmolSetIter<'a, [SyntaxType; 1]>),
    Index(SmolSetIter<'a, [IndexType; 1]>),
    Refer(std::collections::btree_set::Iter<'a, Uuid>),
    JsonFilt(SmolSetIter<'a, [ProtoFilter; 1]>),
    Cred(std::collections::btree_map::Iter<'a, String, Credential>),
    SshKey(std::collections::btree_map::Iter<'a, String, String>),
    SecretValue(SmolSetIter<'a, [String; 1]>),
    Spn(std::collections::btree_set::Iter<'a, (String, String)>),
    Uint32(SmolSetIter<'a, [u32; 1]>),
    Cid(SmolSetIter<'a, [Cid; 1]>),
    Nsuniqueid(std::collections::btree_set::Iter<'a, String>),
    DateTime(SmolSetIter<'a, [OffsetDateTime; 1]>),
    EmailAddress(std::collections::btree_set::Iter<'a, String>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    Es256PrivateDer(SmolSetIter<'a, [Vec<u8>; 1]>),
}

impl<'a> Iterator for PartialValueIter<'a> {
    type Item = PartialValue;

    fn next(&mut self) -> Option<PartialValue> {
        match self {
            PartialValueIter::Utf8(iter) => {
                iter.next().map(|i| PartialValue::new_utf8s(i.as_str()))
            }
            PartialValueIter::Iutf8(iter) => {
                iter.next().map(|i| PartialValue::new_iutf8(i.as_str()))
            }
            PartialValueIter::Iname(iter) => {
                iter.next().map(|i| PartialValue::new_iname(i.as_str()))
            }
            PartialValueIter::Uuid(iter) => iter.next().map(|i| PartialValue::new_uuidr(i)),
            PartialValueIter::Bool(iter) => iter.next().map(
                // Use the from bool impl.
                PartialValue::from,
            ),
            PartialValueIter::Syntax(iter) => iter.next().map(|i|
                // Uses the "from syntax type" impl.
                PartialValue::from(i.clone())),
            PartialValueIter::Index(iter) => iter.next().map(|i|
                // Uses the from index type impl.
                PartialValue::from(i.clone())),
            PartialValueIter::Refer(iter) => iter.next().map(|i| PartialValue::new_refer_r(i)),
            PartialValueIter::JsonFilt(iter) => iter.next().map(|i| PartialValue::from(i.clone())),
            PartialValueIter::Cred(iter) => iter
                .next()
                .map(|(tag, _cred)| PartialValue::new_credential_tag(tag.as_str())),
            PartialValueIter::SshKey(iter) => iter
                .next()
                .map(|(tag, _key)| PartialValue::new_sshkey_tag_s(tag.as_str())),
            PartialValueIter::SecretValue(iter) => {
                iter.next().map(|_| PartialValue::new_secret_str())
            }
            PartialValueIter::Spn(iter) => iter
                .next()
                .map(|(n, d)| PartialValue::new_spn_nrs(n.as_str(), d.as_str())),
            PartialValueIter::Uint32(iter) => iter.next().copied().map(PartialValue::from),
            PartialValueIter::Cid(iter) => iter.next().cloned().map(PartialValue::new_cid),
            PartialValueIter::Nsuniqueid(iter) => iter
                .next()
                .map(|i| PartialValue::new_email_address_s(i.as_str())),
            PartialValueIter::DateTime(iter) => iter.next().copied().map(PartialValue::from),
            PartialValueIter::EmailAddress(iter) => iter
                .next()
                .map(|i| PartialValue::new_email_address_s(i.as_str())),
            PartialValueIter::Url(iter) => iter.next().map(|i| PartialValue::from(i.clone())),
            PartialValueIter::OauthScope(iter) => {
                iter.next().map(|i| PartialValue::new_oauthscope(i))
            }
            PartialValueIter::OauthScopeMap(iter) => iter
                .next()
                .map(|(group, _scopes)| PartialValue::new_oauthscopemap(*group)),
            PartialValueIter::Es256PrivateDer(iter) => {
                iter.next().map(|_| PartialValue::Es256PrivateDer)
            }
        }
    }
}

pub enum DbValueV1Iter<'a> {
    Utf8(std::collections::btree_set::Iter<'a, String>),
    Iutf8(std::collections::btree_set::Iter<'a, String>),
    Iname(std::collections::btree_set::Iter<'a, String>),
    Uuid(std::collections::btree_set::Iter<'a, Uuid>),
    Bool(SmolSetIter<'a, [bool; 1]>),
    Syntax(SmolSetIter<'a, [SyntaxType; 1]>),
    Index(SmolSetIter<'a, [IndexType; 1]>),
    Refer(std::collections::btree_set::Iter<'a, Uuid>),
    JsonFilt(SmolSetIter<'a, [ProtoFilter; 1]>),
    Cred(std::collections::btree_map::Iter<'a, String, Credential>),
    SshKey(std::collections::btree_map::Iter<'a, String, String>),
    SecretValue(SmolSetIter<'a, [String; 1]>),
    Spn(std::collections::btree_set::Iter<'a, (String, String)>),
    Uint32(SmolSetIter<'a, [u32; 1]>),
    Cid(SmolSetIter<'a, [Cid; 1]>),
    Nsuniqueid(std::collections::btree_set::Iter<'a, String>),
    DateTime(SmolSetIter<'a, [OffsetDateTime; 1]>),
    EmailAddress(std::collections::btree_set::Iter<'a, String>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    Es256PrivateDer(SmolSetIter<'a, [Vec<u8>; 1]>),
}

impl<'a> Iterator for DbValueV1Iter<'a> {
    type Item = DbValueV1;

    fn next(&mut self) -> Option<DbValueV1> {
        match self {
            DbValueV1Iter::Utf8(iter) => iter.next().map(|i| DbValueV1::Utf8(i.clone())),
            DbValueV1Iter::Iutf8(iter) => iter.next().map(|i| DbValueV1::Iutf8(i.clone())),
            DbValueV1Iter::Iname(iter) => iter.next().map(|i| DbValueV1::Iname(i.clone())),
            DbValueV1Iter::Uuid(iter) => iter.next().map(|i| DbValueV1::Uuid(*i)),
            DbValueV1Iter::Bool(iter) => iter.next().map(|i| DbValueV1::Bool(*i)),
            DbValueV1Iter::Syntax(iter) => iter.next().map(|i| DbValueV1::SyntaxType(i.to_usize())),
            DbValueV1Iter::Index(iter) => iter.next().map(|i| DbValueV1::IndexType(i.to_usize())),
            DbValueV1Iter::Refer(iter) => iter.next().map(|i| DbValueV1::Reference(*i)),
            DbValueV1Iter::JsonFilt(iter) => iter.next().map(|i| {
                DbValueV1::JsonFilter(
                    serde_json::to_string(i)
                        .expect("A json filter value was corrupted during run-time"),
                )
            }),
            DbValueV1Iter::Cred(iter) => iter.next().map(|(tag, cred)| {
                DbValueV1::Credential(DbValueCredV1 {
                    tag: tag.clone(),
                    data: cred.to_db_valuev1(),
                })
            }),
            DbValueV1Iter::SshKey(iter) => iter.next().map(|(tag, key)| {
                DbValueV1::SshKey(DbValueTaggedStringV1 {
                    tag: tag.clone(),
                    data: key.clone(),
                })
            }),
            DbValueV1Iter::SecretValue(iter) => {
                iter.next().map(|i| DbValueV1::SecretValue(i.clone()))
            }
            DbValueV1Iter::Spn(iter) => iter
                .next()
                .map(|(n, d)| DbValueV1::Spn(n.clone(), d.clone())),
            DbValueV1Iter::Uint32(iter) => iter.next().map(|i| DbValueV1::Uint32(*i)),
            DbValueV1Iter::Cid(iter) => iter.next().map(|c| {
                DbValueV1::Cid(DbCidV1 {
                    domain_id: c.d_uuid,
                    server_id: c.s_uuid,
                    timestamp: c.ts,
                })
            }),
            DbValueV1Iter::Nsuniqueid(iter) => {
                iter.next().map(|i| DbValueV1::NsUniqueId(i.clone()))
            }
            DbValueV1Iter::DateTime(iter) => iter.next().map(|odt| {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                DbValueV1::DateTime(odt.format(time::Format::Rfc3339))
            }),
            DbValueV1Iter::EmailAddress(iter) => iter
                .next()
                .map(|i| DbValueV1::EmailAddress(DbValueEmailAddressV1 { d: i.clone() })),
            DbValueV1Iter::Url(iter) => iter.next().map(|i| DbValueV1::Url(i.clone())),
            DbValueV1Iter::OauthScope(iter) => {
                iter.next().map(|i| DbValueV1::OauthScope(i.clone()))
            }
            DbValueV1Iter::OauthScopeMap(iter) => iter.next().map(|(u, m)| {
                DbValueV1::OauthScopeMap(DbValueOauthScopeMapV1 {
                    refer: *u,
                    data: m.iter().cloned().collect(),
                })
            }),
            DbValueV1Iter::Es256PrivateDer(iter) => {
                iter.next().map(|i| DbValueV1::Es256PrivateDer(i.clone()))
            }
        }
    }
}

pub enum ProtoIter<'a> {
    Utf8(std::collections::btree_set::Iter<'a, String>),
    Iutf8(std::collections::btree_set::Iter<'a, String>),
    Iname(std::collections::btree_set::Iter<'a, String>),
    Uuid(std::collections::btree_set::Iter<'a, Uuid>),
    Bool(SmolSetIter<'a, [bool; 1]>),
    Syntax(SmolSetIter<'a, [SyntaxType; 1]>),
    Index(SmolSetIter<'a, [IndexType; 1]>),
    Refer(std::collections::btree_set::Iter<'a, Uuid>),
    JsonFilt(SmolSetIter<'a, [ProtoFilter; 1]>),
    Cred(std::collections::btree_map::Iter<'a, String, Credential>),
    SshKey(std::collections::btree_map::Iter<'a, String, String>),
    SecretValue(SmolSetIter<'a, [String; 1]>),
    Spn(std::collections::btree_set::Iter<'a, (String, String)>),
    Uint32(SmolSetIter<'a, [u32; 1]>),
    Cid(SmolSetIter<'a, [Cid; 1]>),
    Nsuniqueid(std::collections::btree_set::Iter<'a, String>),
    DateTime(SmolSetIter<'a, [OffsetDateTime; 1]>),
    EmailAddress(std::collections::btree_set::Iter<'a, String>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    Es256PrivateDer(SmolSetIter<'a, [Vec<u8>; 1]>),
}

impl<'a> Iterator for ProtoIter<'a> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        match self {
            ProtoIter::Utf8(iter) => iter.next().cloned(),
            ProtoIter::Iutf8(iter) => iter.next().cloned(),
            ProtoIter::Iname(iter) => iter.next().cloned(),
            ProtoIter::Uuid(iter) => iter.next().map(ValueSet::uuid_to_proto_string),

            ProtoIter::Bool(iter) => iter.next().map(|i| i.to_string()),
            ProtoIter::Syntax(iter) => iter.next().map(|i| i.to_string()),
            ProtoIter::Index(iter) => iter.next().map(|i| i.to_string()),
            ProtoIter::Refer(iter) => iter.next().map(ValueSet::uuid_to_proto_string),
            ProtoIter::JsonFilt(iter) => iter.next().map(|i| {
                #[allow(clippy::expect_used)]
                serde_json::to_string(i).expect("A json filter value was corrupted during run-time")
            }),
            ProtoIter::Cred(iter) => iter.next().map(|(tag, _cred)|
                // You can't actually read the credential values because we only display the
                // tag to the proto side. The credentials private data is stored seperately.
                tag.to_string()),
            ProtoIter::SshKey(iter) => {
                iter.next()
                    .map(|(tag, key)| match SshPublicKey::from_string(key) {
                        Ok(spk) => {
                            let fp = spk.fingerprint();
                            format!("{}: {}", tag, fp.hash)
                        }
                        Err(_) => format!("{}: corrupted ssh public key", tag),
                    })
            }
            ProtoIter::SecretValue(iter) => iter.next().map(|_| "hidden".to_string()),
            ProtoIter::Spn(iter) => iter.next().map(|(n, d)| format!("{}@{}", n, d)),
            ProtoIter::Uint32(iter) => iter.next().map(|i| i.to_string()),
            ProtoIter::Cid(iter) => iter
                .next()
                .map(|c| format!("{:?}_{}_{}", c.ts, c.d_uuid, c.s_uuid)),
            ProtoIter::Nsuniqueid(iter) => iter.next().cloned(),
            ProtoIter::DateTime(iter) => iter.next().map(|odt| {
                debug_assert!(odt.offset() == time::UtcOffset::UTC);
                odt.format(time::Format::Rfc3339)
            }),
            ProtoIter::EmailAddress(iter) => iter.next().cloned(),
            ProtoIter::Url(iter) => iter.next().map(|i| i.to_string()),
            ProtoIter::OauthScope(iter) => iter.next().cloned(),
            ProtoIter::OauthScopeMap(iter) => iter
                .next()
                .map(|(u, m)| format!("{}: {:?}", ValueSet::uuid_to_proto_string(u), m)),
            ProtoIter::Es256PrivateDer(iter) => {
                iter.next().map(|_| "es256_der_private_key".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::value::Value;
    use crate::valueset::ValueSet;

    #[test]
    fn test_valueset_basic() {
        let mut vs = ValueSet::new(Value::new_uint32(0));
        assert!(vs.insert_checked(Value::new_uint32(0)) == Ok(false));
        assert!(vs.insert_checked(Value::new_uint32(1)) == Ok(true));
        assert!(vs.insert_checked(Value::new_uint32(1)) == Ok(false));
    }
}

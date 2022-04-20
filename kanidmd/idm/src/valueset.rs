use crate::credential::Credential;
use crate::prelude::*;
use crate::repl::cid::Cid;
use either::Either::{Left, Right};
use kanidm_proto::v1::Filter as ProtoFilter;
use smolset::{SmolSet, SmolSetIter};
use sshkeys::PublicKey as SshPublicKey;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use time::OffsetDateTime;
use tracing::trace;

use crate::be::dbvalue::{
    DbCidV1, DbValueAddressV1, DbValueCredV1, DbValueEmailAddressV1, DbValueOauthScopeMapV1,
    DbValuePhoneNumberV1, DbValueTaggedStringV1, DbValueV1,
};
use crate::value::{Address, IntentTokenState, INAME_RE, NSUNIQUEID_RE, OAUTHSCOPE_RE};

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
    EmailAddress {
        primary: Option<String>,
        set: BTreeSet<String>,
    },
    PhoneNumber {
        primary: Option<String>,
        set: BTreeSet<String>,
    },
    Address {
        set: BTreeSet<Address>,
    },
    Url(SmolSet<[Url; 1]>),
    OauthScope(BTreeSet<String>),
    OauthScopeMap(BTreeMap<Uuid, BTreeSet<String>>),
    PrivateBinary(SmolSet<[Vec<u8>; 1]>),
    PublicBinary(BTreeMap<String, Vec<u8>>),
    // Enumeration(SmolSet<[String; 1]>),
    // Float64(Vec<[f64; 1]>),
    RestrictedString(BTreeSet<String>),
    IntentToken(BTreeMap<Uuid, IntentTokenState>),
    TrustedDeviceEnrollment(BTreeMap<Uuid, ()>),
    AuthSession(BTreeMap<Uuid, ()>),
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

impl From<Value> for ValueSet {
    fn from(value: Value) -> Self {
        ValueSet {
            inner: match value {
                Value::Utf8(s) => I::Utf8(btreeset![s]),
                Value::Iutf8(s) => I::Iutf8(btreeset![s]),
                Value::Iname(s) => I::Iname(btreeset![s]),
                Value::Uuid(u) => I::Uuid(btreeset![u]),
                Value::Bool(b) => I::Bool(smolset![b]),
                Value::Syntax(s) => I::Syntax(smolset![s]),
                Value::Index(i) => I::Index(smolset![i]),
                Value::Refer(u) => I::Refer(btreeset![u]),
                Value::JsonFilt(f) => I::JsonFilt(smolset![f]),
                Value::Cred(t, c) => I::Cred(btreemap![(t, c)]),
                Value::SshKey(t, k) => I::SshKey(btreemap![(t, k)]),
                Value::SecretValue(c) => I::SecretValue(smolset![c]),
                Value::Spn(n, d) => I::Spn(btreeset![(n, d)]),
                Value::Uint32(i) => I::Uint32(smolset![i]),
                Value::Cid(c) => I::Cid(smolset![c]),
                Value::Nsuniqueid(s) => I::Nsuniqueid(btreeset![s]),
                Value::DateTime(dt) => I::DateTime(smolset![dt]),
                Value::EmailAddress(e, _) => I::EmailAddress {
                    // We have to disregard the primary here
                    // as we only have one!
                    primary: Some(e.clone()),
                    set: btreeset![e],
                },
                Value::Url(u) => I::Url(smolset![u]),
                Value::OauthScope(x) => I::OauthScope(btreeset![x]),
                Value::OauthScopeMap(u, m) => I::OauthScopeMap(btreemap![(u, m)]),
                Value::PrivateBinary(c) => I::PrivateBinary(smolset![c]),
                Value::PhoneNumber(p, _) => I::PhoneNumber {
                    primary: None,
                    set: btreeset![p],
                },
                Value::Address(a) => I::Address { set: btreeset![a] },
                Value::PublicBinary(tag, bin) => I::PublicBinary(btreemap![(tag, bin)]),
                Value::RestrictedString(s) => I::RestrictedString(btreeset![s]),
            },
        }
    }
}

impl TryFrom<DbValueV1> for ValueSet {
    type Error = ();

    fn try_from(value: DbValueV1) -> Result<Self, Self::Error> {
        Ok(ValueSet {
            inner: match value {
                DbValueV1::Utf8(s) => I::Utf8(btreeset![s]),
                DbValueV1::Iutf8(s) => I::Iutf8(btreeset![s]),
                DbValueV1::Iname(s) => I::Iname(btreeset![s]),
                DbValueV1::Uuid(u) => I::Uuid(btreeset![u]),
                DbValueV1::Bool(b) => I::Bool(smolset![b]),
                DbValueV1::SyntaxType(us) => {
                    let s = SyntaxType::try_from(us)?;
                    I::Syntax(smolset![s])
                }
                DbValueV1::IndexType(ui) => {
                    let i = IndexType::try_from(ui)?;
                    I::Index(smolset![i])
                }
                DbValueV1::Reference(u) => I::Refer(btreeset![u]),
                DbValueV1::JsonFilter(s) => {
                    let f = serde_json::from_str(&s).map_err(|_| ())?;
                    I::JsonFilt(smolset![f])
                }
                DbValueV1::Credential(dvc) => {
                    let t = dvc.tag.to_lowercase();
                    let c = Credential::try_from(dvc.data)?;
                    I::Cred(btreemap![(t, c)])
                }
                DbValueV1::SshKey(ts) => I::SshKey(btreemap![(ts.tag, ts.data)]),
                DbValueV1::SecretValue(c) => I::SecretValue(smolset![c]),
                DbValueV1::Spn(n, d) => I::Spn(btreeset![(n, d)]),
                DbValueV1::Uint32(i) => I::Uint32(smolset![i]),
                DbValueV1::Cid(dc) => {
                    let c = Cid {
                        ts: dc.timestamp,
                        d_uuid: dc.domain_id,
                        s_uuid: dc.server_id,
                    };
                    I::Cid(smolset![c])
                }
                DbValueV1::NsUniqueId(s) => I::Nsuniqueid(btreeset![s]),
                DbValueV1::DateTime(s) => {
                    let dt = OffsetDateTime::parse(s, time::Format::Rfc3339)
                        .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                        .map_err(|_| ())?;
                    I::DateTime(smolset![dt])
                }
                DbValueV1::EmailAddress(DbValueEmailAddressV1 {
                    d: email_addr,
                    p: _,
                }) => {
                    // Since this is the first, we need to disregard the primary.
                    let primary = Some(email_addr.clone());
                    I::EmailAddress {
                        primary,
                        set: btreeset![email_addr],
                    }
                }
                DbValueV1::Url(u) => I::Url(smolset![u]),
                DbValueV1::OauthScope(x) => I::OauthScope(btreeset![x]),
                DbValueV1::OauthScopeMap(osm) => {
                    let u = osm.refer;
                    let m = osm.data.into_iter().collect();
                    I::OauthScopeMap(btreemap![(u, m)])
                }
                DbValueV1::PrivateBinary(c) => I::PrivateBinary(smolset![c]),
                DbValueV1::PhoneNumber(DbValuePhoneNumberV1 {
                    d: phone_number,
                    p: is_primary,
                }) => {
                    let primary = if is_primary {
                        Some(phone_number.clone())
                    } else {
                        None
                    };
                    I::PhoneNumber {
                        primary,
                        set: btreeset![phone_number],
                    }
                }
                DbValueV1::Address(_a) => todo!(),
                // I::Address { set: btreeset![a] },
                DbValueV1::PublicBinary(tag, bin) => I::PublicBinary(btreemap![(tag, bin)]),
                DbValueV1::RestrictedString(s) => I::RestrictedString(btreeset![s]),
            },
        })
    }
}

impl ValueSet {
    pub fn uuid_to_proto_string(u: &Uuid) -> String {
        u.to_hyphenated_ref().to_string()
    }

    pub fn new(value: Value) -> Self {
        Self::from(value)
    }

    // Returns Ok(true) if value was NOT present before.
    pub fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match (&mut self.inner, value) {
            (I::Utf8(set), Value::Utf8(s)) => Ok(set.insert(s)),
            (I::Iutf8(set), Value::Iutf8(s)) => Ok(set.insert(s)),
            (I::Iname(set), Value::Iname(s)) => Ok(set.insert(s)),
            (I::Uuid(set), Value::Uuid(u)) => Ok(set.insert(u)),
            (I::Bool(bs), Value::Bool(b)) => {
                bs.insert(b);
                Ok(true)
            }
            (I::Syntax(set), Value::Syntax(s)) => Ok(set.insert(s)),
            (I::Index(set), Value::Index(i)) => Ok(set.insert(i)),
            (I::Refer(set), Value::Refer(u)) => Ok(set.insert(u)),
            (I::JsonFilt(set), Value::JsonFilt(f)) => Ok(set.insert(f)),
            (I::Cred(map), Value::Cred(t, c)) => {
                if let BTreeEntry::Vacant(e) = map.entry(t) {
                    e.insert(c);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::SshKey(map), Value::SshKey(t, k)) => {
                if let BTreeEntry::Vacant(e) = map.entry(t) {
                    e.insert(k);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::SecretValue(set), Value::SecretValue(c)) => Ok(set.insert(c)),
            (I::Spn(set), Value::Spn(n, d)) => Ok(set.insert((n, d))),
            (I::Uint32(set), Value::Uint32(i)) => Ok(set.insert(i)),
            (I::Cid(set), Value::Cid(c)) => Ok(set.insert(c)),
            (I::Nsuniqueid(set), Value::Nsuniqueid(u)) => Ok(set.insert(u)),
            (I::DateTime(set), Value::DateTime(dt)) => Ok(set.insert(dt)),
            (I::EmailAddress { primary, set }, Value::EmailAddress(e, is_primary)) => {
                // Need to check primary first.
                if is_primary {
                    *primary = Some(e.clone());
                };
                Ok(set.insert(e))
            }
            (I::PhoneNumber { primary, set }, Value::PhoneNumber(e, is_primary)) => {
                // Need to check primary first.
                if is_primary {
                    *primary = Some(e.clone());
                };
                Ok(set.insert(e))
            }
            (I::Address { set }, Value::Address(e)) => {
                // Need to check primary first.
                Ok(set.insert(e))
            }
            (I::Url(set), Value::Url(u)) => Ok(set.insert(u)),
            (I::OauthScope(set), Value::OauthScope(u)) => Ok(set.insert(u)),
            (I::OauthScopeMap(map), Value::OauthScopeMap(u, m)) => {
                if let BTreeEntry::Vacant(e) = map.entry(u) {
                    e.insert(m);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::PrivateBinary(set), Value::PrivateBinary(c)) => Ok(set.insert(c)),
            (I::PublicBinary(map), Value::PublicBinary(tag, c)) => {
                if let BTreeEntry::Vacant(e) = map.entry(tag) {
                    e.insert(c);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::RestrictedString(set), Value::RestrictedString(s)) => Ok(set.insert(s)),
            (_, _) => Err(OperationError::InvalidValueState),
        }
    }

    fn insert_db_valuev1(&mut self, v: DbValueV1) -> Result<(), ()> {
        match (&mut self.inner, v) {
            (I::Utf8(set), DbValueV1::Utf8(s)) => Ok(set.insert(s)),
            (I::Iutf8(set), DbValueV1::Iutf8(s)) => Ok(set.insert(s)),
            (I::Iname(set), DbValueV1::Iname(s)) => Ok(set.insert(s)),
            (I::Uuid(set), DbValueV1::Uuid(u)) => Ok(set.insert(u)),
            (I::Bool(set), DbValueV1::Bool(b)) => {
                set.insert(b);
                Ok(true)
            }
            (I::Syntax(set), DbValueV1::SyntaxType(us)) => {
                let s = SyntaxType::try_from(us)?;
                Ok(set.insert(s))
            }
            (I::Index(set), DbValueV1::IndexType(ui)) => {
                let i = IndexType::try_from(ui)?;
                Ok(set.insert(i))
            }
            (I::Refer(set), DbValueV1::Reference(u)) => Ok(set.insert(u)),
            (I::JsonFilt(set), DbValueV1::JsonFilter(s)) => {
                let f = serde_json::from_str(&s).map_err(|_| ())?;
                Ok(set.insert(f))
            }
            (I::Cred(map), DbValueV1::Credential(dvc)) => {
                let t = dvc.tag.to_lowercase();
                let c = Credential::try_from(dvc.data)?;
                if let BTreeEntry::Vacant(e) = map.entry(t) {
                    e.insert(c);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::SshKey(map), DbValueV1::SshKey(ts)) => {
                if let BTreeEntry::Vacant(e) = map.entry(ts.tag) {
                    e.insert(ts.data);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::SecretValue(set), DbValueV1::SecretValue(c)) => Ok(set.insert(c)),
            (I::Spn(set), DbValueV1::Spn(n, d)) => Ok(set.insert((n, d))),
            (I::Uint32(set), DbValueV1::Uint32(i)) => Ok(set.insert(i)),
            (I::Cid(set), DbValueV1::Cid(dc)) => {
                let c = Cid {
                    ts: dc.timestamp,
                    d_uuid: dc.domain_id,
                    s_uuid: dc.server_id,
                };
                Ok(set.insert(c))
            }
            (I::Nsuniqueid(set), DbValueV1::NsUniqueId(s)) => Ok(set.insert(s)),
            (I::DateTime(set), DbValueV1::DateTime(s)) => {
                let dt = OffsetDateTime::parse(s, time::Format::Rfc3339)
                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                    .map_err(|_| ())?;
                Ok(set.insert(dt))
            }
            (
                I::EmailAddress { primary, set },
                DbValueV1::EmailAddress(DbValueEmailAddressV1 {
                    d: email_addr,
                    p: is_primary,
                }),
            ) => {
                if is_primary {
                    *primary = Some(email_addr.clone());
                };

                Ok(set.insert(email_addr))
            }
            (
                I::PhoneNumber { primary, set },
                DbValueV1::PhoneNumber(DbValuePhoneNumberV1 {
                    d: phone_number,
                    p: is_primary,
                }),
            ) => {
                if is_primary {
                    *primary = Some(phone_number.clone());
                };
                Ok(set.insert(phone_number))
            }
            (I::Address { set: _ }, DbValueV1::Address(_a)) => {
                todo!()
            }
            (I::Url(set), DbValueV1::Url(u)) => Ok(set.insert(u)),
            (I::OauthScope(set), DbValueV1::OauthScope(x)) => Ok(set.insert(x)),
            (I::OauthScopeMap(map), DbValueV1::OauthScopeMap(osm)) => {
                let u = osm.refer;
                let m = osm.data.into_iter().collect();

                if let BTreeEntry::Vacant(e) = map.entry(u) {
                    e.insert(m);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::PrivateBinary(set), DbValueV1::PrivateBinary(c)) => Ok(set.insert(c)),
            (I::PublicBinary(map), DbValueV1::PublicBinary(tag, bin)) => {
                if let BTreeEntry::Vacant(e) = map.entry(tag) {
                    e.insert(bin);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            (I::RestrictedString(set), DbValueV1::RestrictedString(s)) => Ok(set.insert(s)),
            (_, _) => Err(()),
        }
        .and_then(|is_new| {
            debug_assert!(is_new);
            // If its ok(false) error?
            if is_new {
                Ok(())
            } else {
                Err(())
            }
        })
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
            (
                I::EmailAddress {
                    primary: _,
                    set: set_a,
                },
                I::EmailAddress {
                    primary: _,
                    set: set_b,
                },
            ) => {
                mergesets!(set_a, set_b)
            }
            (
                I::PhoneNumber {
                    primary: _,
                    set: set_a,
                },
                I::PhoneNumber {
                    primary: _,
                    set: set_b,
                },
            ) => {
                mergesets!(set_a, set_b)
            }
            (I::Address { set: set_a }, I::Address { set: set_b }) => {
                mergesets!(set_a, set_b)
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
            (I::PrivateBinary(a), I::PrivateBinary(b)) => {
                mergesets!(a, b)
            }
            (I::PublicBinary(a), I::PublicBinary(b)) => {
                mergemaps!(a, b)
            }
            (I::RestrictedString(a), I::RestrictedString(b)) => {
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
            I::EmailAddress { primary: _, set } => {
                set.extend(iter.filter_map(|v| v.to_emailaddress()));
            }
            I::PhoneNumber { primary: _, set } => {
                set.extend(iter.filter_map(|v| v.to_phonenumber()));
            }
            I::Address { set } => {
                set.extend(iter.filter_map(|v| v.to_address()));
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
            I::PrivateBinary(set) => {
                iter.filter_map(|v| v.to_privatebinary().cloned())
                    .for_each(|i| {
                        set.insert(i);
                    });
            }
            I::PublicBinary(map) => {
                map.extend(iter.filter_map(|v| v.to_publicbinary()));
            }
            I::RestrictedString(set) => {
                set.extend(iter.filter_map(|v| v.to_restrictedstring()));
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
            I::EmailAddress { primary, set } => {
                *primary = None;
                set.clear();
            }
            I::PhoneNumber { primary, set } => {
                *primary = None;
                set.clear();
            }
            I::Address { set } => {
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
            I::PrivateBinary(set) => {
                set.clear();
            }
            I::PublicBinary(set) => {
                set.clear();
            }
            I::RestrictedString(set) => {
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
            (I::EmailAddress { primary, set }, PartialValue::EmailAddress(e)) => {
                set.remove(e);
                if Some(e) == primary.as_ref() {
                    *primary = set.iter().cloned().next();
                    // *primary = None;
                };
            }
            (I::PhoneNumber { primary, set }, PartialValue::PhoneNumber(e)) => {
                if Some(e) == primary.as_ref() {
                    *primary = None;
                };
                set.remove(e);
            }
            (I::Address { set: _ }, PartialValue::Address(_e)) => {
                // set.remove(e);
                todo!();
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
            (I::PrivateBinary(_set), PartialValue::PrivateBinary) => {
                debug_assert!(false)
            }
            (I::PublicBinary(map), PartialValue::PublicBinary(t)) => {
                map.remove(t);
            }
            (I::RestrictedString(set), PartialValue::RestrictedString(s)) => {
                set.remove(s);
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
            (I::EmailAddress { primary: _, set }, PartialValue::EmailAddress(e)) => set.contains(e),
            (I::PhoneNumber { primary: _, set }, PartialValue::PhoneNumber(e)) => set.contains(e),
            (I::Address { set: _ }, PartialValue::Address(_e)) => {
                todo!()
            }
            (I::Url(set), PartialValue::Url(u)) => set.contains(u),
            (I::OauthScope(set), PartialValue::OauthScope(u)) => set.contains(u),
            (I::OauthScopeMap(map), PartialValue::OauthScopeMap(u))
            | (I::OauthScopeMap(map), PartialValue::Refer(u)) => map.contains_key(u),
            (I::PrivateBinary(_set), PartialValue::PrivateBinary) => false,
            (I::PublicBinary(map), PartialValue::PublicBinary(t)) => map.contains_key(t.as_str()),
            (I::RestrictedString(set), PartialValue::RestrictedString(s)) => {
                set.contains(s.as_str())
            }
            _ => false,
        }
    }

    pub fn substring(&self, pv: &PartialValue) -> bool {
        match (&self.inner, pv) {
            (I::Utf8(set), PartialValue::Utf8(s2)) => set.iter().any(|s1| s1.contains(s2)),
            (I::Iutf8(set), PartialValue::Iutf8(s2)) => set.iter().any(|s1| s1.contains(s2)),
            (I::Iname(set), PartialValue::Iname(s2)) => set.iter().any(|s1| s1.contains(s2)),
            (I::RestrictedString(set), PartialValue::RestrictedString(s2)) => {
                set.iter().any(|s1| s1.contains(s2))
            }
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
            I::EmailAddress { primary: _, set } => set.len(),
            I::PhoneNumber { primary: _, set } => set.len(),
            I::Address { set } => set.len(),
            I::Url(set) => set.len(),
            I::OauthScope(set) => set.len(),
            I::OauthScopeMap(set) => set.len(),
            I::PrivateBinary(set) => set.len(),
            I::PublicBinary(map) => map.len(),
            I::RestrictedString(set) => set.len(),
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
            I::EmailAddress { primary: _, set } => set.iter().cloned().collect(),
            I::PhoneNumber { primary: _, set } => set.iter().cloned().collect(),
            I::Address { set: _ } => todo!(),
            // set.iter().cloned().collect(),
            // Don't you dare comment on this quinn, it's a URL not a str.
            I::Url(set) => set.iter().map(|u| u.to_string()).collect(),
            // Should we index this?
            // I::OauthScope(set) => set.iter().map(|u| u.to_string()).collect(),
            I::OauthScope(_set) => vec![],
            I::OauthScopeMap(map) => map
                .keys()
                .map(|u| u.to_hyphenated_ref().to_string())
                .collect(),
            I::PrivateBinary(_set) => vec![],
            I::PublicBinary(map) => map.keys().cloned().collect(),
            I::RestrictedString(set) => set.iter().cloned().collect(),
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
            (
                I::EmailAddress {
                    primary: _,
                    set: set_a,
                },
                I::EmailAddress {
                    primary: _,
                    set: set_b,
                },
            ) => {
                let x: BTreeSet<_> = set_a.difference(set_b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::EmailAddress {
                            primary: None,
                            set: x,
                        },
                    })
                }
            }
            (
                I::PhoneNumber {
                    primary: _,
                    set: set_a,
                },
                I::PhoneNumber {
                    primary: _,
                    set: set_b,
                },
            ) => {
                let x: BTreeSet<_> = set_a.difference(set_b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::PhoneNumber {
                            primary: None,
                            set: x,
                        },
                    })
                }
            }
            (I::Address { set: _set_a }, I::Address { set: _set_b }) => {
                todo!()
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
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::OauthScopeMap(x),
                    })
                }
            }
            (I::PrivateBinary(a), I::PrivateBinary(b)) => {
                let x: SmolSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::PrivateBinary(x),
                    })
                }
            }
            (I::PublicBinary(a), I::PublicBinary(b)) => {
                let x: BTreeMap<_, _> = a
                    .iter()
                    .filter(|(k, _)| b.contains_key(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::PublicBinary(x),
                    })
                }
            }
            (I::RestrictedString(a), I::RestrictedString(b)) => {
                let x: BTreeSet<_> = a.difference(b).cloned().collect();
                if x.is_empty() {
                    None
                } else {
                    Some(ValueSet {
                        inner: I::RestrictedString(x),
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

    pub fn as_email_set(&self) -> Option<&BTreeSet<String>> {
        match &self.inner {
            I::EmailAddress { primary: _, set } => Some(set),
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
            None
        } else {
            self.to_value_iter().take(1).next()
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

    pub fn to_email_address_primary_str(&self) -> Option<&str> {
        match &self.inner {
            I::EmailAddress { primary, set } => {
                if let Some(p) = primary {
                    debug_assert!(set.contains(p));
                    Some(p.as_str())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_private_binary_single(&self) -> Option<&[u8]> {
        match &self.inner {
            I::PrivateBinary(set) => {
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

    pub fn as_email_str_iter(&self) -> Option<impl Iterator<Item = &str>> {
        match &self.inner {
            I::EmailAddress { primary: _, set } => Some(set.iter().map(|s| s.as_str())),
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
            I::EmailAddress { primary: _, set } => ProtoIter::EmailAddress(set.iter()),
            I::PhoneNumber { primary: _, set } => ProtoIter::PhoneNumber(set.iter()),
            I::Address { set } => ProtoIter::Address(set.iter()),
            I::Url(set) => ProtoIter::Url(set.iter()),
            I::OauthScope(set) => ProtoIter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => ProtoIter::OauthScopeMap(set.iter()),
            I::PrivateBinary(set) => ProtoIter::PrivateBinary(set.iter()),
            I::PublicBinary(set) => ProtoIter::PublicBinary(set.iter()),
            I::RestrictedString(set) => ProtoIter::RestrictedString(set.iter()),
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
            I::EmailAddress { primary, set } => {
                DbValueV1Iter::EmailAddress(primary.as_deref(), set.iter())
            }
            I::PhoneNumber { primary, set } => {
                DbValueV1Iter::PhoneNumber(primary.as_deref(), set.iter())
            }
            I::Address { set } => DbValueV1Iter::Address(set.iter()),
            I::Url(set) => DbValueV1Iter::Url(set.iter()),
            I::OauthScope(set) => DbValueV1Iter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => DbValueV1Iter::OauthScopeMap(set.iter()),
            I::PrivateBinary(set) => DbValueV1Iter::PrivateBinary(set.iter()),
            I::PublicBinary(set) => DbValueV1Iter::PublicBinary(set.iter()),
            I::RestrictedString(set) => DbValueV1Iter::RestrictedString(set.iter()),
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
            I::EmailAddress { primary: _, set } => PartialValueIter::EmailAddress(set.iter()),
            I::PhoneNumber { primary: _, set } => PartialValueIter::PhoneNumber(set.iter()),
            I::Address { set } => PartialValueIter::Address(set.iter()),
            I::Url(set) => PartialValueIter::Url(set.iter()),
            I::OauthScope(set) => PartialValueIter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => PartialValueIter::OauthScopeMap(set.iter()),
            I::PrivateBinary(set) => PartialValueIter::PrivateBinary(set.iter()),
            I::PublicBinary(set) => PartialValueIter::PublicBinary(set.iter()),
            I::RestrictedString(set) => PartialValueIter::RestrictedString(set.iter()),
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
            I::EmailAddress { primary: _, set } => ValueIter::EmailAddress(set.iter()),
            I::PhoneNumber { primary: _, set } => ValueIter::PhoneNumber(set.iter()),
            I::Address { set } => ValueIter::Address(set.iter()),
            I::Url(set) => ValueIter::Url(set.iter()),
            I::OauthScope(set) => ValueIter::OauthScope(set.iter()),
            I::OauthScopeMap(set) => ValueIter::OauthScopeMap(set.iter()),
            I::PrivateBinary(set) => ValueIter::PrivateBinary(set.iter()),
            I::PublicBinary(set) => ValueIter::PublicBinary(set.iter()),
            I::RestrictedString(set) => ValueIter::RestrictedString(set.iter()),
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

    pub fn from_db_valuev1_iter(
        mut iter: impl Iterator<Item = DbValueV1>,
    ) -> Result<ValueSet, OperationError> {
        let init = if let Some(v) = iter.next() {
            v
        } else {
            admin_error!("Empty db valuev1 iterator");
            return Err(OperationError::InvalidValueState);
        };

        let mut vs = ValueSet::try_from(init).map_err(|_| OperationError::InvalidValueState)?;

        for v in iter {
            // Need to error if wrong type
            vs.insert_db_valuev1(v)
                .map_err(|_| OperationError::InvalidValueState)?;
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
        matches!(self.inner, I::EmailAddress { primary: _, set: _ })
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

    pub fn is_privatebinary(&self) -> bool {
        matches!(self.inner, I::PrivateBinary(_))
    }

    pub fn validate(&self) -> bool {
        match &self.inner {
            I::Iname(set) => set.iter().all(|s| {
                match Uuid::parse_str(s) {
                    // It is a uuid, disallow.
                    Ok(_) => false,
                    // Not a uuid, check it against the re.
                    Err(_) => !INAME_RE.is_match(s),
                }
            }),
            I::SshKey(map) => map
                .values()
                .all(|key| SshPublicKey::from_string(key).is_ok()),
            I::Nsuniqueid(set) => set.iter().all(|s| NSUNIQUEID_RE.is_match(s)),
            I::DateTime(set) => set.iter().all(|odt| odt.offset() == time::UtcOffset::UTC),
            I::EmailAddress { primary, set } => {
                set.iter()
                    .all(|mail| validator::validate_email(mail.as_str()))
                    && if let Some(p) = primary {
                        set.contains(p)
                    } else {
                        true
                    }
            }
            I::OauthScope(set) => set.iter().all(|s| OAUTHSCOPE_RE.is_match(s)),
            I::OauthScopeMap(map) => map
                .values()
                .map(|set| set.iter())
                .flatten()
                .all(|s| OAUTHSCOPE_RE.is_match(s)),
            _ => true,
        }
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
            (
                I::EmailAddress {
                    primary: pa,
                    set: set_a,
                },
                I::EmailAddress {
                    primary: pb,
                    set: set_b,
                },
            ) => pa.eq(pb) && set_a.eq(set_b),
            (
                I::PhoneNumber {
                    primary: pa,
                    set: set_a,
                },
                I::PhoneNumber {
                    primary: pb,
                    set: set_b,
                },
            ) => pa.eq(pb) && set_a.eq(set_b),
            (I::Address { set: set_a }, I::Address { set: set_b }) => set_a.eq(set_b),
            (I::Url(a), I::Url(b)) => a.eq(b),
            (I::OauthScope(a), I::OauthScope(b)) => a.eq(b),
            (I::OauthScopeMap(a), I::OauthScopeMap(b)) => a.eq(b),
            (I::PrivateBinary(a), I::PrivateBinary(b)) => a.eq(b),
            (I::PublicBinary(a), I::PublicBinary(b)) => a.eq(b),
            (I::RestrictedString(a), I::RestrictedString(b)) => a.eq(b),
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
    PhoneNumber(std::collections::btree_set::Iter<'a, String>),
    Address(std::collections::btree_set::Iter<'a, Address>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    PrivateBinary(SmolSetIter<'a, [Vec<u8>; 1]>),
    PublicBinary(std::collections::btree_map::Iter<'a, String, Vec<u8>>),
    RestrictedString(std::collections::btree_set::Iter<'a, String>),
}

impl<'a> Iterator for ValueIter<'a> {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        match self {
            // Clippy may try to report these as bugs, but it's wrong.
            ValueIter::Utf8(iter) => iter.next().map(|i| Value::new_utf8s(i)),
            ValueIter::Iutf8(iter) => iter.next().map(|i| Value::new_iutf8(i)),
            ValueIter::Iname(iter) => iter.next().map(|i| Value::new_iname(i)),
            ValueIter::Uuid(iter) => iter.next().map(Value::new_uuidr),
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
            ValueIter::Refer(iter) => iter.next().map(Value::new_refer_r),
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
            ValueIter::Nsuniqueid(iter) => iter
                .next()
                .and_then(|i| Value::new_nsuniqueid_s(i.as_str())),
            ValueIter::DateTime(iter) => iter.next().copied().map(Value::from),
            ValueIter::EmailAddress(iter) => iter
                .next()
                .and_then(|i| Value::new_email_address_s(i.as_str())),
            ValueIter::PhoneNumber(iter) => {
                iter.next().map(|i| Value::new_phonenumber_s(i.as_str()))
            }
            ValueIter::Address(iter) => iter.next().map(|a| Value::new_address(a.clone())),
            ValueIter::Url(iter) => iter.next().map(|i| Value::from(i.clone())),
            ValueIter::OauthScope(iter) => iter.next().and_then(|i| Value::new_oauthscope(i)),
            ValueIter::OauthScopeMap(iter) => iter
                .next()
                .and_then(|(group, scopes)| Value::new_oauthscopemap(*group, scopes.clone())),
            ValueIter::PrivateBinary(iter) => iter.next().map(|i| Value::new_privatebinary(i)),
            ValueIter::PublicBinary(iter) => iter
                .next()
                .map(|(t, b)| Value::new_publicbinary(t.clone(), b.clone())),
            ValueIter::RestrictedString(iter) => {
                iter.next().map(|i| Value::new_restrictedstring(i.clone()))
            }
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
    PhoneNumber(std::collections::btree_set::Iter<'a, String>),
    Address(std::collections::btree_set::Iter<'a, Address>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    PrivateBinary(SmolSetIter<'a, [Vec<u8>; 1]>),
    PublicBinary(std::collections::btree_map::Iter<'a, String, Vec<u8>>),
    RestrictedString(std::collections::btree_set::Iter<'a, String>),
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
            PartialValueIter::Uuid(iter) => iter.next().map(PartialValue::new_uuidr),
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
            PartialValueIter::Refer(iter) => iter.next().map(PartialValue::new_refer_r),
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
            PartialValueIter::PhoneNumber(iter) => iter
                .next()
                .map(|i| PartialValue::new_phonenumber_s(i.as_str())),
            PartialValueIter::Address(iter) => iter
                .next()
                .map(|a| PartialValue::new_address(a.formatted.as_str())),
            PartialValueIter::Url(iter) => iter.next().map(|i| PartialValue::from(i.clone())),
            PartialValueIter::OauthScope(iter) => {
                iter.next().map(|i| PartialValue::new_oauthscope(i))
            }
            PartialValueIter::OauthScopeMap(iter) => iter
                .next()
                .map(|(group, _scopes)| PartialValue::new_oauthscopemap(*group)),
            PartialValueIter::PrivateBinary(iter) => {
                iter.next().map(|_| PartialValue::PrivateBinary)
            }
            PartialValueIter::PublicBinary(iter) => iter
                .next()
                .map(|(tag, _key)| PartialValue::new_publicbinary_tag_s(tag.as_str())),
            PartialValueIter::RestrictedString(iter) => iter
                .next()
                .map(|i| PartialValue::new_restrictedstring_s(i.as_str())),
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
    EmailAddress(
        Option<&'a str>,
        std::collections::btree_set::Iter<'a, String>,
    ),
    PhoneNumber(
        Option<&'a str>,
        std::collections::btree_set::Iter<'a, String>,
    ),
    Address(std::collections::btree_set::Iter<'a, Address>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    PrivateBinary(SmolSetIter<'a, [Vec<u8>; 1]>),
    PublicBinary(std::collections::btree_map::Iter<'a, String, Vec<u8>>),
    RestrictedString(std::collections::btree_set::Iter<'a, String>),
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
            DbValueV1Iter::EmailAddress(pri, iter) => iter.next().map(|i| {
                DbValueV1::EmailAddress(DbValueEmailAddressV1 {
                    d: i.clone(),
                    p: Some(i.as_str()) == *pri,
                })
            }),
            DbValueV1Iter::PhoneNumber(pri, iter) => iter.next().map(|i| {
                DbValueV1::PhoneNumber(DbValuePhoneNumberV1 {
                    d: i.clone(),
                    p: Some(i.as_str()) == *pri,
                })
            }),
            DbValueV1Iter::Address(iter) => iter.next().map(|a| {
                DbValueV1::Address(DbValueAddressV1 {
                    formatted: a.formatted.clone(),
                    street_address: a.street_address.clone(),
                    locality: a.locality.clone(),
                    region: a.region.clone(),
                    postal_code: a.postal_code.clone(),
                    country: a.country.clone(),
                })
            }),
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
            DbValueV1Iter::PrivateBinary(iter) => {
                iter.next().map(|i| DbValueV1::PrivateBinary(i.clone()))
            }
            DbValueV1Iter::PublicBinary(iter) => iter
                .next()
                .map(|(t, b)| DbValueV1::PublicBinary(t.clone(), b.clone())),
            DbValueV1Iter::RestrictedString(iter) => {
                iter.next().map(|i| DbValueV1::RestrictedString(i.clone()))
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
    PhoneNumber(std::collections::btree_set::Iter<'a, String>),
    Address(std::collections::btree_set::Iter<'a, Address>),
    Url(SmolSetIter<'a, [Url; 1]>),
    OauthScope(std::collections::btree_set::Iter<'a, String>),
    OauthScopeMap(std::collections::btree_map::Iter<'a, Uuid, BTreeSet<String>>),
    PrivateBinary(SmolSetIter<'a, [Vec<u8>; 1]>),
    PublicBinary(std::collections::btree_map::Iter<'a, String, Vec<u8>>),
    RestrictedString(std::collections::btree_set::Iter<'a, String>),
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
            ProtoIter::PhoneNumber(iter) => iter.next().cloned(),
            ProtoIter::Address(iter) => iter.next().map(|a| a.formatted.clone()),
            ProtoIter::Url(iter) => iter.next().map(|i| i.to_string()),
            ProtoIter::OauthScope(iter) => iter.next().cloned(),
            ProtoIter::OauthScopeMap(iter) => iter
                .next()
                .map(|(u, m)| format!("{}: {:?}", ValueSet::uuid_to_proto_string(u), m)),
            ProtoIter::PrivateBinary(iter) => iter.next().map(|_| "private_binary".to_string()),

            ProtoIter::PublicBinary(iter) => iter
                .next()
                .map(|(t, b)| format!("{}: {}", t, base64::encode_config(&b, base64::URL_SAFE))),
            ProtoIter::RestrictedString(iter) => iter.next().cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::value::{PartialValue, Value};
    use crate::valueset::ValueSet;

    #[test]
    fn test_valueset_basic() {
        let mut vs = ValueSet::new(Value::new_uint32(0));
        assert!(vs.insert_checked(Value::new_uint32(0)) == Ok(false));
        assert!(vs.insert_checked(Value::new_uint32(1)) == Ok(true));
        assert!(vs.insert_checked(Value::new_uint32(1)) == Ok(false));
    }

    #[test]
    fn test_valueset_emailaddress() {
        // Can be created
        //
        let mut vs =
            ValueSet::new(Value::new_email_address_s("claire@example.com").expect("Invalid Email"));

        assert!(vs.len() == 1);
        assert!(vs.to_email_address_primary_str() == Some("claire@example.com"));

        // Add another, still not primary.
        assert!(
            vs.insert_checked(
                Value::new_email_address_s("alice@example.com").expect("Invalid Email")
            ) == Ok(true)
        );

        assert!(vs.len() == 2);
        assert!(vs.to_email_address_primary_str() == Some("claire@example.com"));

        // Update primary
        assert!(
            vs.insert_checked(
                Value::new_email_address_primary_s("primary@example.com").expect("Invalid Email")
            ) == Ok(true)
        );
        assert!(vs.to_email_address_primary_str() == Some("primary@example.com"));

        // Restore from dbv1, ensure correct primary

        let vs2 = ValueSet::from_db_valuev1_iter(vs.to_db_valuev1_iter())
            .expect("Failed to construct vs2 from dbvalue");

        assert!(vs == vs2);
        assert!(vs.to_email_address_primary_str() == vs2.to_email_address_primary_str());

        // Remove primary, assert it's gone and that the "first" address is assigned.
        assert!(vs.remove(&PartialValue::new_email_address_s("primary@example.com")));
        assert!(vs.len() == 2);
        assert!(vs.to_email_address_primary_str() == Some("alice@example.com"));

        // Restore from dbv1, alice persisted.
        let vs3 = ValueSet::from_db_valuev1_iter(vs.to_db_valuev1_iter())
            .expect("Failed to construct vs2 from dbvalue");
        assert!(vs == vs3);
        assert!(vs3.len() == 2);
        assert!(vs3.as_email_set().unwrap().contains("alice@example.com"));
        assert!(vs3.as_email_set().unwrap().contains("claire@example.com"));

        // If we clear, no primary.
        vs.clear();
        assert!(vs.len() == 0);
        assert!(vs.to_email_address_primary_str().is_none());
    }
}

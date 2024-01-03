//! Entries are the base unit of object storage in the server. This is one of the three foundational
//! concepts along with [`filter`]s and [`schema`] that everything else builds upon.
//!
//! An [`Entry`] is a collection of attribute-value sets. There are sometimes called attribute value
//! assertions, or AVAs. The attribute is a "key" and it holds 1 to infinite associated values
//! with no ordering. An entry has many AVAs. A pseudo example, minus schema and typing:
//!
//! ```text
//! Entry {
//!   "name": ["william"],
//!   "uuid": ["..."],
//!   "mail": ["maila@example.com", "mailb@example.com"],
//! };
//! ```
//!
//! There are three rules for entries:
//! * Must have an AVA for UUID containing a single value.
//! * Any AVA with zero values will be removed.
//! * AVAs are stored with no sorting.
//!
//! For more, see the [`Entry`] type.
//!
//! [`Entry`]: struct.Entry.html
//! [`filter`]: ../filter/index.html
//! [`schema`]: ../schema/index.html

use std::cmp::Ordering;
pub use std::collections::BTreeSet as Set;
use std::collections::{BTreeMap as Map, BTreeMap, BTreeSet};
use std::sync::Arc;

use compact_jwt::JwsEs256Signer;
use hashbrown::{HashMap, HashSet};
use kanidm_proto::internal::ImageValue;
use kanidm_proto::v1::{
    ConsistencyError, Entry as ProtoEntry, Filter as ProtoFilter, OperationError, SchemaError,
    UiHint,
};
use ldap3_proto::simple::{LdapPartialAttribute, LdapSearchResultEntry};
use openssl::ec::EcKey;
use openssl::pkey::{Private, Public};
use smartstring::alias::String as AttrString;
use time::OffsetDateTime;
use tracing::trace;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, Passkey as PasskeyV4,
};

use crate::be::dbentry::{DbEntry, DbEntryVers};
use crate::be::dbvalue::DbValueSetV2;
use crate::be::{IdxKey, IdxSlope};
use crate::credential::Credential;
use crate::filter::{Filter, FilterInvalid, FilterResolved, FilterValidResolved};
use crate::idm::ldap::ldap_vattr_map;
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::repl::entry::EntryChangeState;
use crate::repl::proto::{ReplEntryV1, ReplIncrementalEntryV1};

use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};
use crate::value::{
    ApiToken, CredentialType, IndexType, IntentTokenState, Oauth2Session, PartialValue, Session,
    SyntaxType, Value,
};
use crate::valueset::{self, ValueSet};

pub type EntryInitNew = Entry<EntryInit, EntryNew>;
pub type EntryInvalidNew = Entry<EntryInvalid, EntryNew>;
pub type EntryRefreshNew = Entry<EntryRefresh, EntryNew>;
pub type EntrySealedNew = Entry<EntrySealed, EntryNew>;
pub type EntryValidCommitted = Entry<EntryValid, EntryCommitted>;
pub type EntrySealedCommitted = Entry<EntrySealed, EntryCommitted>;
pub type EntryInvalidCommitted = Entry<EntryInvalid, EntryCommitted>;
pub type EntryReducedCommitted = Entry<EntryReduced, EntryCommitted>;
pub type EntryTuple = (Arc<EntrySealedCommitted>, EntryInvalidCommitted);

pub type EntryIncrementalNew = Entry<EntryIncremental, EntryNew>;
pub type EntryIncrementalCommitted = Entry<EntryIncremental, EntryCommitted>;

// Entry should have a lifecycle of types. This is Raw (modifiable) and Entry (verified).
// This way, we can move between them, but only certain actions are possible on either
// This means modifications happen on Raw, but to move to Entry, you schema normalise.
// Vice versa, you can for free, move to Raw, but you lose the validation.

// Because this is type system it's "free" in the end, and means we force validation
// at the correct and required points of the entries life.

// This is specifically important for the commit to the backend, as we only want to
// commit validated types.

// Has never been in the DB, so doesn't have an ID.
#[derive(Clone, Debug)]
pub struct EntryNew; // new

// It's been in the DB, so it has an id
#[derive(Clone, Debug)]
pub struct EntryCommitted {
    id: u64,
}

#[derive(Clone, Debug)]
pub struct EntryInit;

/*  |
 *  | Init comes from a proto entry, it's new.
 *  | We add the current Cid before we allow mods.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryInvalid {
    cid: Cid,
    ecstate: EntryChangeState,
}

// Alternate path - this entry came from a full refresh, and already has an entry change state.
#[derive(Clone, Debug)]
pub struct EntryRefresh {
    ecstate: EntryChangeState,
}

// Alternate path - this entry came from an incremental replication.
#[derive(Clone, Debug)]
pub struct EntryIncremental {
    // Must have a uuid, else we can't proceed at all.
    uuid: Uuid,
    ecstate: EntryChangeState,
}

/*  |
 *  | The changes made within this entry are validated by the schema.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryValid {
    // Asserted with schema, so we know it has a UUID now ...
    uuid: Uuid,
    ecstate: EntryChangeState,
}

/*  |
 *  | The changes are extracted into the changelog as needed, creating a
 *  | stable database entry.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntrySealed {
    uuid: Uuid,
    ecstate: EntryChangeState,
}

/*  |
 *  | The entry has access controls applied to reduce what is yielded to a client
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryReduced {
    uuid: Uuid,
}

// One day this is going to be Map<Attribute, ValueSet> - @yaleman
// pub type Eattrs = Map<Attribute, ValueSet>;
pub type Eattrs = Map<AttrString, ValueSet>;

pub(crate) fn compare_attrs(left: &Eattrs, right: &Eattrs) -> bool {
    // We can't shortcut based on len because cid mod may not be present.
    // Build the set of all keys between both.
    let allkeys: Set<&str> = left
        .keys()
        .filter(|k| k != &Attribute::LastModifiedCid.as_ref())
        .chain(
            right
                .keys()
                .filter(|k| k != &Attribute::LastModifiedCid.as_ref()),
        )
        .map(|s| s.as_ref())
        .collect();

    allkeys.into_iter().all(|k| {
        // Both must be Some, and both must have the same interiors.
        let r = match (left.get(k), right.get(k)) {
            (Some(l), Some(r)) => l.eq(r),
            _ => false,
        };
        if !r {
            trace!(?k, "compare_attrs_allkeys");
        }
        r
    })
}

/// Entry is the core data storage type of the server. Almost every aspect of the server is
/// designed to read, handle and manipulate entries.
///
/// Entries store attribute value assertions, or AVA. These are sets of key-values.
///
/// Entries have a lifecycle within a single operation, and as part of replication.
/// The lifecycle for operations is defined through state and valid types. Each entry has a pair
/// Of these types at anytime. The first is the AVA [`schema`] and [`access`] control assertion
/// state. This is represented by the type `VALID` as one of `EntryValid`, `EntryInvalid` or
/// `EntryReduced`. Every entry starts as `EntryInvalid`, and when checked by the schema for
/// correctness, transitions to `EntryValid`. While an entry is `EntryValid` it can not be
/// altered - you must invalidate it to `EntryInvalid`, then modify, then check again.
/// An entry that has had access controls applied moves from `EntryValid` to `EntryReduced`,
/// to show that the AVAs have reduced to the valid read set of the current [`event`] user.
///
/// The second type of `STATE` represents the database commit state and internal db ID's. A
/// new entry that has never been committed is `EntryNew`, but an entry that has been retrieved
/// from the database is `EntryCommitted`. This affects the operations you can apply IE modify
/// or delete.
///
/// These types exist to prevent at compile time, mishandling of Entries, to ensure they are always
/// handled with the correct lifecycles and processes.
///
/// [`schema`]: ../schema/index.html
/// [`access`]: ../access/index.html
/// [`event`]: ../event/index.html
pub struct Entry<VALID, STATE> {
    valid: VALID,
    state: STATE,
    // We may need to change this to Set to allow borrow of Value -> PartialValue for lookups.
    attrs: Eattrs,
}

impl<VALID, STATE> std::fmt::Debug for Entry<VALID, STATE>
where
    STATE: std::fmt::Debug,
    VALID: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Entry<EntrySealed, _>")
            .field("state", &self.state)
            .field("valid", &self.valid)
            .field("attrs", &self.attrs)
            .finish()
    }
}

impl<STATE> std::fmt::Display for Entry<EntrySealed, STATE>
where
    STATE: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.get_uuid())
    }
}

impl<STATE> std::fmt::Display for Entry<EntryInit, STATE>
where
    STATE: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Entry in initial state")
    }
}

impl<STATE> Entry<EntryInit, STATE>
where
    STATE: Clone,
{
    /// Get the uuid of this entry.
    pub(crate) fn get_uuid(&self) -> Option<Uuid> {
        self.attrs
            .get(Attribute::Uuid.as_ref())
            .and_then(|vs| vs.to_uuid_single())
    }
}

impl Default for Entry<EntryInit, EntryNew> {
    fn default() -> Self {
        Self::new()
    }
}

impl Entry<EntryInit, EntryNew> {
    pub fn new() -> Self {
        Entry {
            // This means NEVER COMMITTED
            valid: EntryInit,
            state: EntryNew,
            attrs: Map::new(),
            // attrs: Map::with_capacity(32),
        }
    }

    /// Consume a Protocol Entry from JSON, and validate and process the data into an internal
    /// [`Entry`] type.
    pub fn from_proto_entry(
        e: &ProtoEntry,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        trace!("from_proto_entry");
        // Why not the trait? In the future we may want to extend
        // this with server aware functions for changes of the
        // incoming data.

        // Somehow we need to take the tree of e attrs, and convert
        // all ref types to our types ...
        let map2: Result<Eattrs, OperationError> = e
            .attrs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                trace!(?k, ?v, "attribute");
                let nk = qs.get_schema().normalise_attr_name(k);
                let nv =
                    valueset::from_result_value_iter(v.iter().map(|vr| qs.clone_value(&nk, vr)));
                trace!(?nv, "new valueset transform");
                match nv {
                    Ok(nvi) => Ok((nk, nvi)),
                    Err(e) => Err(e),
                }
            })
            .collect();

        let x = map2?;

        Ok(Entry {
            state: EntryNew,
            valid: EntryInit,
            attrs: x,
        })
    }

    /// Given a proto entry in JSON formed as a serialised string, processed that string
    /// into an Entry.
    #[instrument(level = "debug", skip_all)]
    pub fn from_proto_entry_str(
        es: &str,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        if cfg!(test) {
            if es.len() > 256 {
                let (dsp_es, _) = es.split_at(255);
                trace!("Parsing -> {}...", dsp_es);
            } else {
                trace!("Parsing -> {}", es);
            }
        }
        // str -> Proto entry
        let pe: ProtoEntry = serde_json::from_str(es).map_err(|e| {
            // We probably shouldn't print ES here because that would allow users
            // to inject content into our logs :)
            admin_error!(?e, "SerdeJson Failure");
            OperationError::SerdeJsonError
        })?;
        // now call from_proto_entry
        Self::from_proto_entry(&pe, qs)
    }

    #[cfg(test)]
    // TODO: #[deprecated(note = "Use entry_init! macro instead or like... anything else")]
    pub(crate) fn unsafe_from_entry_str(es: &str) -> Self {
        // Just use log directly here, it's testing
        // str -> proto entry
        let pe: ProtoEntry = serde_json::from_str(es).expect("Invalid Proto Entry");
        // use a const map to convert str -> ava
        let x: Eattrs = pe.attrs.into_iter()
            .filter_map(|(k, vs)| {
                if vs.is_empty() {
                    None
                } else {
                    // TODO: this should be an "Attribute::from(k)"
                let attr = AttrString::from(k.to_lowercase());
                let vv: ValueSet = match attr.as_str() {
                    kanidm_proto::constants::ATTR_ATTRIBUTENAME | kanidm_proto::constants::ATTR_CLASSNAME | kanidm_proto::constants::ATTR_DOMAIN => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_iutf8(&v))
                        )
                    }
                    kanidm_proto::constants::ATTR_NAME | kanidm_proto::constants::ATTR_DOMAIN_NAME => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_iname(&v))
                        )
                    }
                    kanidm_proto::constants::ATTR_USERID | kanidm_proto::constants::ATTR_UIDNUMBER  => {
                        warn!("WARNING: Use of unstabilised attributes userid/uidnumber");
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_iutf8(&v))
                        )
                    }
                    kanidm_proto::constants::ATTR_CLASS | kanidm_proto::constants::ATTR_ACP_CREATE_CLASS | kanidm_proto::constants::ATTR_ACP_MODIFY_CLASS  => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_class(v.as_str()))
                        )
                    }
                    kanidm_proto::constants::ATTR_ACP_CREATE_ATTR |
                    kanidm_proto::constants::ATTR_ACP_SEARCH_ATTR |
                    kanidm_proto::constants::ATTR_ACP_MODIFY_REMOVEDATTR |
                    kanidm_proto::constants::ATTR_ACP_MODIFY_PRESENTATTR |
                    kanidm_proto::constants::ATTR_SYSTEMMAY |
                    kanidm_proto::constants::ATTR_SYSTEMMUST |
                    kanidm_proto::constants::ATTR_MAY |
                    kanidm_proto::constants::ATTR_MUST
                    => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_attr(v.as_str()))
                        )
                    }
                    kanidm_proto::constants::ATTR_UUID |
                    kanidm_proto::constants::ATTR_DOMAIN_UUID => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_uuid_s(v.as_str())
                                .unwrap_or_else(|| {
                                    warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                    Value::new_utf8(v)
                                })
                            )
                        )
                    }
                    kanidm_proto::constants::ATTR_MEMBER |
                    kanidm_proto::constants::ATTR_MEMBEROF |
                    kanidm_proto::constants::ATTR_DIRECTMEMBEROF |
                    kanidm_proto::constants::ATTR_ACP_RECEIVER_GROUP => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_refer_s(v.as_str()).unwrap() )
                        )
                    }
                    kanidm_proto::constants::ATTR_ACP_ENABLE |
                    kanidm_proto::constants::ATTR_MULTIVALUE |
                    kanidm_proto::constants::ATTR_UNIQUE => {
                        valueset::from_value_iter(
                        vs.into_iter().map(|v| Value::new_bools(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                            )
                        )
                    }
                    kanidm_proto::constants::ATTR_SYNTAX => {
                        valueset::from_value_iter(
                        vs.into_iter().map(|v| Value::new_syntaxs(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        )
                        )
                    }
                    kanidm_proto::constants::ATTR_INDEX => {
                        valueset::from_value_iter(
                        vs.into_iter().map(|v| Value::new_indexes(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        )
                        )
                    }
                    kanidm_proto::constants::ATTR_ACP_TARGET_SCOPE |
                    kanidm_proto::constants::ATTR_ACP_RECEIVER
                     => {
                        valueset::from_value_iter(
                        vs.into_iter().map(|v| Value::new_json_filter_s(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        )
                        )
                    }
                    kanidm_proto::constants::ATTR_DISPLAYNAME | kanidm_proto::constants::ATTR_DESCRIPTION | kanidm_proto::constants::ATTR_DOMAIN_DISPLAY_NAME => {
                        valueset::from_value_iter(
                        vs.into_iter().map(Value::new_utf8)
                        )
                    }
                    kanidm_proto::constants::ATTR_SPN => {
                        valueset::from_value_iter(
                        vs.into_iter().map(|v| {
                            Value::new_spn_parse(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect SPN attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        })
                        )
                    }
                    kanidm_proto::constants::ATTR_GIDNUMBER |
                    kanidm_proto::constants::ATTR_VERSION => {
                        valueset::from_value_iter(
                        vs.into_iter().map(|v| {
                            Value::new_uint32_str(v.as_str())
                            .unwrap_or_else(|| {
                                warn!("WARNING: Allowing syntax incorrect UINT32 attribute to be presented UTF8 string");
                                Value::new_utf8(v)
                            })
                        })
                        )
                    }
                    kanidm_proto::constants::ATTR_DOMAIN_TOKEN_KEY |
                    kanidm_proto::constants::ATTR_FERNET_PRIVATE_KEY_STR => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_secret_str(&v))
                        )
                    }
                    kanidm_proto::constants::ATTR_ES256_PRIVATE_KEY_DER |
                    kanidm_proto::constants::ATTR_PRIVATE_COOKIE_KEY => {
                        valueset::from_value_iter(
                            vs.into_iter().map(|v| Value::new_privatebinary_base64(&v))
                        )
                    }
                    ia => {
                        error!("WARNING: Allowing invalid attribute {} to be interpreted as UTF8 string. YOU MAY ENCOUNTER ODD BEHAVIOUR!!!", ia);
                        valueset::from_value_iter(
                            vs.into_iter().map(Value::new_utf8)
                        )
                    }
                }
                .unwrap();
                Some((attr, vv))
                }
            })
            .collect();

        // return the entry!
        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs: x,
        }
    }

    /// Assign the Change Identifier to this Entry, allowing it to be modified and then
    /// written to the `Backend`
    pub fn assign_cid(
        self,
        cid: Cid,
        schema: &dyn SchemaTransaction,
    ) -> Entry<EntryInvalid, EntryNew> {
        /*
         * Create the change log. This must be the last thing BEFORE we return!
         * This is because we need to capture the set_last_changed attribute in
         * the create transition.
         */
        let ecstate = EntryChangeState::new(&cid, &self.attrs, schema);

        let mut ent = Entry {
            valid: EntryInvalid { cid, ecstate },
            state: EntryNew,
            attrs: self.attrs,
        };
        // trace!("trigger_last_changed - assign_cid");
        ent.trigger_last_changed();
        ent
    }

    /// Compare this entry to another.
    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

    /// ⚠️  This function bypasses the db commit and creates invalid replication metadata.
    /// The entry it creates can never be replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_invalid_new(mut self) -> Entry<EntryInvalid, EntryNew> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());

        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit and creates invalid replication metadata.
    /// The entry it creates can never be replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_new(mut self) -> Entry<EntryValid, EntryNew> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());
        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntryValid {
                ecstate,
                uuid: self.get_uuid().expect("Invalid uuid"),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit, assigns fake db ids, and invalid replication metadata.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(mut self) -> Entry<EntrySealed, EntryCommitted> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());
        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntrySealed { uuid, ecstate },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit and creates invalid replication metadata.
    /// The entry it creates can never be replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_new(mut self) -> Entry<EntrySealed, EntryNew> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());
        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntrySealed {
                uuid: self.get_uuid().expect("Invalid uuid"),
                ecstate,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    //              ⚠️   replication safety  ⚠️
    // These functions are SAFE because they occur in the EntryInit
    // state, which precedes the generation of the initial Create
    // event for the attribute.
    /// Add an attribute-value-assertion to this Entry.
    pub fn add_ava(&mut self, attr: Attribute, value: Value) {
        self.add_ava_int(attr, value);
    }

    /// Replace the existing content of an attribute set of this Entry, with a new set of Values.
    pub fn set_ava<T>(&mut self, attr: Attribute, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        self.set_ava_iter_int(attr, iter);
    }

    pub fn get_ava_mut(&mut self, attr: Attribute) -> Option<&mut ValueSet> {
        self.attrs.get_mut(attr.as_ref())
    }
}

impl Entry<EntryRefresh, EntryNew> {
    pub fn from_repl_entry_v1(repl_entry: &ReplEntryV1) -> Result<Self, OperationError> {
        // From the entry, we have to rebuild the ecstate and the attrs.
        let (ecstate, attrs) = repl_entry.rehydrate()?;

        Ok(Entry {
            valid: EntryRefresh { ecstate },
            state: EntryNew,
            attrs,
        })
    }
}

impl<STATE> Entry<EntryRefresh, STATE> {
    pub fn validate(
        self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let uuid: Uuid = self
            .attrs
            .get(Attribute::Uuid.as_ref())
            .ok_or_else(|| SchemaError::MissingMustAttribute(vec![Attribute::Uuid.to_string()]))
            .and_then(|vs| {
                vs.to_uuid_single().ok_or_else(|| {
                    SchemaError::MissingMustAttribute(vec![Attribute::Uuid.to_string()])
                })
            })?;

        // Build the new valid entry ...
        let ne = Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        };

        ne.validate(schema).map(|()| ne)
    }
}

impl<STATE> Entry<EntryIncremental, STATE> {
    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }
}

impl Entry<EntryIncremental, EntryNew> {
    fn stub_ecstate(&self) -> EntryChangeState {
        self.valid.ecstate.stub()
    }

    pub fn rehydrate(repl_inc_entry: &ReplIncrementalEntryV1) -> Result<Self, OperationError> {
        let (uuid, ecstate, attrs) = repl_inc_entry.rehydrate()?;

        Ok(Entry {
            valid: EntryIncremental { uuid, ecstate },
            state: EntryNew,
            attrs,
        })
    }

    pub(crate) fn is_add_conflict(&self, db_entry: &EntrySealedCommitted) -> bool {
        use crate::repl::entry::State;
        debug_assert!(self.valid.uuid == db_entry.valid.uuid);
        // This is a conflict if the state 'at' is not identical
        let self_cs = &self.valid.ecstate;
        let db_cs = db_entry.get_changestate();

        // Can only add conflict on live entries.
        match (self_cs.current(), db_cs.current()) {
            (State::Live { at: at_left, .. }, State::Live { at: at_right, .. }) => {
                at_left != at_right
            }
            // Tombstone will always overwrite.
            _ => false,
        }
    }

    pub(crate) fn resolve_add_conflict(
        &self,
        cid: &Cid,
        db_ent: &EntrySealedCommitted,
    ) -> (Option<EntrySealedNew>, EntryIncrementalCommitted) {
        use crate::repl::entry::State;
        debug_assert!(self.valid.uuid == db_ent.valid.uuid);
        let self_cs = &self.valid.ecstate;
        let db_cs = db_ent.get_changestate();

        match (self_cs.current(), db_cs.current()) {
            (
                State::Live {
                    at: at_left,
                    changes: _changes_left,
                },
                State::Live {
                    at: at_right,
                    changes: _changes_right,
                },
            ) => {
                debug_assert!(at_left != at_right);
                // Determine which of the entries must become the conflict
                // and which will now persist. There are three possible cases.
                //
                // 1. The incoming ReplIncremental is after DBentry. This means RI is the
                //    conflicting node. We take no action and just return the db_ent
                //    as the valid state.
                if at_left > at_right {
                    trace!("RI > DE, return DE");
                    (
                        None,
                        Entry {
                            valid: EntryIncremental {
                                uuid: db_ent.valid.uuid,
                                ecstate: db_cs.clone(),
                            },
                            state: EntryCommitted {
                                id: db_ent.state.id,
                            },
                            attrs: db_ent.attrs.clone(),
                        },
                    )
                }
                //
                // 2. The incoming ReplIncremental is before DBentry. This means our
                //    DE is the conflicting note. There are now two choices:
                //    a.  We are the origin of the DE, and thus must create the conflict
                //        entry for replication (to guarantee single create)
                //    b.  We are not the origin of the DE and so do not create a conflict
                //        entry.
                //    In both cases we update the DE with the state of RI after we have
                //    followed the above logic.
                else {
                    trace!("RI < DE, return RI");
                    // Are we the origin?
                    let conflict = if at_right.s_uuid == cid.s_uuid {
                        trace!("Origin process conflict entry");
                        // We are making a new entry!

                        let mut cnf_ent = Entry {
                            valid: EntryInvalid {
                                cid: cid.clone(),
                                ecstate: db_cs.clone(),
                            },
                            state: EntryNew,
                            attrs: db_ent.attrs.clone(),
                        };

                        // Setup the last changed to now.
                        cnf_ent.trigger_last_changed();

                        // Move the current uuid to source_uuid
                        cnf_ent.add_ava(Attribute::SourceUuid, Value::Uuid(db_ent.valid.uuid));

                        // We need to make a random uuid in the conflict gen process.
                        let new_uuid = Uuid::new_v4();
                        cnf_ent.purge_ava(Attribute::Uuid);
                        cnf_ent.add_ava(Attribute::Uuid, Value::Uuid(new_uuid));
                        cnf_ent.add_ava(Attribute::Class, EntryClass::Recycled.into());
                        cnf_ent.add_ava(Attribute::Class, EntryClass::Conflict.into());

                        // Now we have to internally bypass some states.
                        // This is okay because conflict entries aren't subject
                        // to schema anyway.
                        let Entry {
                            valid: EntryInvalid { cid: _, ecstate },
                            state,
                            attrs,
                        } = cnf_ent;

                        let cnf_ent = Entry {
                            valid: EntrySealed {
                                uuid: new_uuid,
                                ecstate,
                            },
                            state,
                            attrs,
                        };

                        Some(cnf_ent)
                    } else {
                        None
                    };

                    (
                        conflict,
                        Entry {
                            valid: EntryIncremental {
                                uuid: self.valid.uuid,
                                ecstate: self_cs.clone(),
                            },
                            state: EntryCommitted {
                                id: db_ent.state.id,
                            },
                            attrs: self.attrs.clone(),
                        },
                    )
                }
            }
            // Can never get here due to is_add_conflict above.
            _ => unreachable!(),
        }
    }

    pub(crate) fn merge_state(
        &self,
        db_ent: &EntrySealedCommitted,
        _schema: &dyn SchemaTransaction,
        trim_cid: &Cid,
    ) -> EntryIncrementalCommitted {
        use crate::repl::entry::State;

        // Paranoid check.
        debug_assert!(self.valid.uuid == db_ent.valid.uuid);

        // First, determine if either side is a tombstone. This is needed so that only
        // when both sides are live
        let self_cs = &self.valid.ecstate;
        let db_cs = db_ent.get_changestate();

        match (self_cs.current(), db_cs.current()) {
            (
                State::Live {
                    at: at_left,
                    changes: changes_left,
                },
                State::Live {
                    at: at_right,
                    changes: changes_right,
                },
            ) => {
                debug_assert!(at_left == at_right);
                // Given the current db entry, compare and merge our attributes to
                // form a resultant entry attr and ecstate
                //
                // To shortcut this we dedup the attr set and then iterate.
                let mut attr_set: Vec<_> =
                    changes_left.keys().chain(changes_right.keys()).collect();
                attr_set.sort_unstable();
                attr_set.dedup();

                // Make a new ecstate and attrs set.
                let mut changes = BTreeMap::default();
                let mut eattrs = Eattrs::default();

                // Now we have the set of attrs from both sides. Lets see what state they are in!
                for attr_name in attr_set.into_iter() {
                    match (changes_left.get(attr_name), changes_right.get(attr_name)) {
                        (Some(cid_left), Some(cid_right)) => {
                            // This is the normal / usual and most "fun" case. Here we need to determine
                            // which side is latest and then do a valueset merge. This is also
                            // needing schema awareness depending on the attribute!
                            //
                            // The behaviour is very dependent on the state of the attributes and
                            // if they exist.
                            let take_left = cid_left > cid_right;

                            match (self.attrs.get(attr_name), db_ent.attrs.get(attr_name)) {
                                (Some(vs_left), Some(vs_right)) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    #[allow(clippy::todo)]
                                    if let Some(merged_attr_state) =
                                        vs_left.repl_merge_valueset(vs_right, trim_cid)
                                    {
                                        // NOTE: This is for special attr types that need to merge
                                        // rather than choose content.
                                        eattrs.insert(attr_name.clone(), merged_attr_state);
                                    } else {
                                        eattrs.insert(attr_name.clone(), vs_left.clone());
                                    }
                                }
                                (Some(vs_left), Some(vs_right)) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    #[allow(clippy::todo)]
                                    if let Some(merged_attr_state) =
                                        vs_right.repl_merge_valueset(vs_left, trim_cid)
                                    {
                                        // NOTE: This is for special attr types that need to merge
                                        // rather than choose content.
                                        eattrs.insert(attr_name.clone(), merged_attr_state);
                                    } else {
                                        eattrs.insert(attr_name.clone(), vs_right.clone());
                                    }
                                }
                                (Some(vs_left), None) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    eattrs.insert(attr_name.clone(), vs_left.clone());
                                }
                                (Some(_vs_left), None) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    // Taking right, nothing to do due to no attr.
                                }
                                (None, Some(_vs_right)) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    // Taking left, nothing to do due to no attr.
                                }
                                (None, Some(vs_right)) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    eattrs.insert(attr_name.clone(), vs_right.clone());
                                }
                                (None, None) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    // Taking left, nothing to do due to no attr.
                                }
                                (None, None) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    // Taking right, nothing to do due to no attr.
                                }
                            }
                            // End attr merging
                        }
                        (Some(cid_left), None) => {
                            // Keep the value on the left.
                            changes.insert(attr_name.clone(), cid_left.clone());
                            if let Some(valueset) = self.attrs.get(attr_name) {
                                eattrs.insert(attr_name.clone(), valueset.clone());
                            }
                        }
                        (None, Some(cid_right)) => {
                            // Keep the value on the right.
                            changes.insert(attr_name.clone(), cid_right.clone());
                            if let Some(valueset) = db_ent.attrs.get(attr_name) {
                                eattrs.insert(attr_name.clone(), valueset.clone());
                            }
                        }
                        (None, None) => {
                            // Should be impossible! At least one side or the other must have a change.
                            debug_assert!(false);
                        }
                    }
                }

                let ecstate = EntryChangeState::build(State::Live {
                    at: at_left.clone(),
                    changes,
                });

                Entry {
                    valid: EntryIncremental {
                        uuid: self.valid.uuid,
                        ecstate,
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: eattrs,
                }
            }
            (State::Tombstone { at: left_at }, State::Live { .. }) => {
                // We have to generate the attrs here, since on replication
                // we just send the tombstone ecstate rather than attrs. Our
                // db stub also lacks these attributes too.
                let mut attrs_new: Eattrs = Map::new();
                let class_ava = vs_iutf8![EntryClass::Object.into(), EntryClass::Tombstone.into()];
                let last_mod_ava = vs_cid![left_at.clone()];

                attrs_new.insert(Attribute::Uuid.into(), vs_uuid![self.valid.uuid]);
                attrs_new.insert(Attribute::Class.into(), class_ava);
                attrs_new.insert(Attribute::LastModifiedCid.into(), last_mod_ava);

                Entry {
                    valid: EntryIncremental {
                        uuid: self.valid.uuid,
                        ecstate: self.valid.ecstate.clone(),
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: attrs_new,
                }
            }
            (State::Live { .. }, State::Tombstone { .. }) => {
                // Our current DB entry is a tombstone - ignore the incoming live
                // entry and just retain our DB tombstone.
                //
                // Note we don't need to gen the attrs here since if a stub was made then
                // we'd be live:live. To be in live:ts, then our db entry MUST exist and
                // must be a ts.

                Entry {
                    valid: EntryIncremental {
                        uuid: db_ent.valid.uuid,
                        ecstate: db_ent.valid.ecstate.clone(),
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: db_ent.attrs.clone(),
                }
            }
            (State::Tombstone { at: left_at }, State::Tombstone { at: right_at }) => {
                // WARNING - this differs from the other tombstone check cases
                // lower of the two AT values. This way replicas always have the
                // earliest TS value. It's a rare case but needs handling.

                let (at, ecstate) = if left_at < right_at {
                    (left_at, self.valid.ecstate.clone())
                } else {
                    (right_at, db_ent.valid.ecstate.clone())
                };

                let mut attrs_new: Eattrs = Map::new();
                let class_ava = vs_iutf8![EntryClass::Object.into(), EntryClass::Tombstone.into()];
                let last_mod_ava = vs_cid![at.clone()];

                attrs_new.insert(Attribute::Uuid.into(), vs_uuid![db_ent.valid.uuid]);
                attrs_new.insert(Attribute::Class.into(), class_ava);
                attrs_new.insert(Attribute::LastModifiedCid.into(), last_mod_ava);

                Entry {
                    valid: EntryIncremental {
                        uuid: db_ent.valid.uuid,
                        ecstate,
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: attrs_new,
                }
            }
        }
    }
}

impl Entry<EntryIncremental, EntryCommitted> {
    pub(crate) fn validate_repl(self, schema: &dyn SchemaTransaction) -> EntryValidCommitted {
        // Unlike the other method of schema validation, we can't return an error
        // here when schema fails - we need to in-place move the entry to a
        // conflict state so that the replication can proceed.

        let mut ne = Entry {
            valid: EntryValid {
                uuid: self.valid.uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        };

        if let Err(e) = ne.validate(schema) {
            warn!(uuid = ?self.valid.uuid, err = ?e, "Entry failed schema check, moving to a conflict state");
            ne.add_ava_int(Attribute::Class, EntryClass::Recycled.into());
            ne.add_ava_int(Attribute::Class, EntryClass::Conflict.into());
            ne.add_ava_int(Attribute::SourceUuid, Value::Uuid(self.valid.uuid));
        }
        ne
    }
}

impl<STATE> Entry<EntryInvalid, STATE> {
    // This is only used in tests today, but I don't want to cfg test it.
    pub(crate) fn get_uuid(&self) -> Option<Uuid> {
        self.attrs
            .get(Attribute::Uuid.as_ref())
            .and_then(|vs| vs.to_uuid_single())
    }

    /// Validate that this entry and its attribute-value sets are conformant to the system's'
    /// schema and the relevant syntaxes.
    pub fn validate(
        self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let uuid: Uuid = self
            .attrs
            .get(Attribute::Uuid.as_ref())
            .ok_or_else(|| SchemaError::MissingMustAttribute(vec![Attribute::Uuid.to_string()]))
            .and_then(|vs| {
                vs.to_uuid_single().ok_or_else(|| {
                    SchemaError::MissingMustAttribute(vec![Attribute::Uuid.to_string()])
                })
            })?;

        // Build the new valid entry ...
        let ne = Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        };

        ne.validate(schema).map(|()| ne)
    }
}

impl<VALID, STATE> Clone for Entry<VALID, STATE>
where
    VALID: Clone,
    STATE: Clone,
{
    // Dirty modifiable state. Works on any other state to dirty them.
    fn clone(&self) -> Entry<VALID, STATE> {
        Entry {
            valid: self.valid.clone(),
            state: self.state.clone(),
            attrs: self.attrs.clone(),
        }
    }
}

impl Entry<EntryInvalid, EntryCommitted> {
    /// ⚠️  This function bypasses the schema validation and can panic if uuid is not found.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        let uuid = self.get_uuid().expect("Invalid uuid");
        Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// Convert this entry into a recycled entry, that is "in the recycle bin".
    pub fn to_recycled(mut self) -> Self {
        // This will put the modify ahead of the recycle transition.
        self.add_ava(Attribute::Class, EntryClass::Recycled.into());

        // Change state repl doesn't need this flag
        // self.valid.ecstate.recycled(&self.valid.cid);

        Entry {
            valid: self.valid,
            state: self.state,
            attrs: self.attrs,
        }
    }

    /// Convert this entry into a conflict, declaring what entries it conflicted against.
    pub fn to_conflict<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Uuid>,
    {
        self.add_ava(Attribute::Class, EntryClass::Recycled.into());
        self.add_ava(Attribute::Class, EntryClass::Conflict.into());
        // Add all the source uuids we conflicted against.
        for source_uuid in iter {
            self.add_ava(Attribute::SourceUuid, Value::Uuid(source_uuid));
        }
    }

    /// Extract this entry from the recycle bin into a live state.
    pub fn to_revived(mut self) -> Self {
        // This will put the modify ahead of the revive transition.
        self.remove_ava(Attribute::Class, &EntryClass::Recycled.into());
        self.remove_ava(Attribute::Class, &EntryClass::Conflict.into());
        self.purge_ava(Attribute::SourceUuid);

        // Change state repl doesn't need this flag
        // self.valid.ecstate.revive(&self.valid.cid);

        Entry {
            valid: self.valid,
            state: self.state,
            attrs: self.attrs,
        }
    }
}
// Both invalid states can be reached from "entry -> invalidate"

impl Entry<EntryInvalid, EntryNew> {
    /// ⚠️  This function bypasses the schema validation and can panic if uuid is not found.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        let uuid = self.get_uuid().expect("Invalid uuid");
        Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit, assigns fake db ids, and assigns an invalid uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntrySealed {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the schema validation and assigns a fake uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryInvalid, EntryCommitted> {
    /// ⚠️  This function bypasses the schema validation and assigns a fake uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntrySealed {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntrySealed, EntryNew> {
    /// ⚠️  This function bypasses schema validation and assigns an invalid uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// Given this validated and sealed entry, process it with a `Backend` ID number so that it
    /// can be then serialised to the database.
    pub fn into_sealed_committed_id(self, id: u64) -> Entry<EntrySealed, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id },
            attrs: self.attrs,
        }
    }

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryNew>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }
}

type IdxDiff<'a> =
    Vec<Result<(&'a AttrString, IndexType, String), (&'a AttrString, IndexType, String)>>;

impl<VALID> Entry<VALID, EntryCommitted> {
    /// If this entry has ever been committed to disk, retrieve it's database id number.
    pub fn get_id(&self) -> u64 {
        self.state.id
    }
}

impl<STATE> Entry<EntrySealed, STATE> {
    pub fn into_init(self) -> Entry<EntryInit, STATE> {
        Entry {
            valid: EntryInit,
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntrySealed, EntryCommitted> {
    #[cfg(test)]
    pub(crate) fn get_last_changed(&self) -> Cid {
        self.valid.ecstate.get_tail_cid()
    }

    /// State transititon to allow self to self for certain test macros.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        // NO-OP to satisfy macros.
        self
    }

    pub(crate) fn stub_sealed_committed_id(
        id: u64,
        ctx_ent: &EntryIncrementalNew,
    ) -> EntrySealedCommitted {
        let uuid = ctx_ent.get_uuid();
        let ecstate = ctx_ent.stub_ecstate();

        Entry {
            valid: EntrySealed { uuid, ecstate },
            state: EntryCommitted { id },
            attrs: Default::default(),
        }
    }

    /// Insert a claim to this entry. This claim can NOT be persisted to disk, this is only
    /// used during a single Event session.
    pub fn insert_claim(&mut self, value: &str) {
        self.add_ava_int(Attribute::Claim, Value::new_iutf8(value));
    }

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

    /// Serialise this entry to it's Database format ready for storage.
    pub fn to_dbentry(&self) -> DbEntry {
        // In the future this will do extra work to process uuid
        // into "attributes" suitable for dbentry storage.
        DbEntry {
            ent: DbEntryVers::V3 {
                changestate: self.valid.ecstate.to_db_changestate(),
                attrs: self
                    .attrs
                    .iter()
                    .map(|(k, vs)| {
                        let dbvs: DbValueSetV2 = vs.to_db_valueset_v2();
                        (k.clone(), dbvs)
                    })
                    .collect(),
            },
        }
    }

    #[inline]
    /// Given this entry, extract the set of strings that can uniquely identify this for authentication
    /// purposes. These strings are then indexed.
    fn get_name2uuid_cands(&self) -> Set<String> {
        // The cands are:
        // * spn
        // * name
        // * gidnumber

        let cands = [Attribute::Spn, Attribute::Name, Attribute::GidNumber];
        cands
            .iter()
            .filter_map(|c| {
                self.attrs
                    .get((*c).as_ref())
                    .map(|vs| vs.to_proto_string_clone_iter())
            })
            .flatten()
            .collect()
    }

    #[inline]
    /// Given this entry, extract the set of strings that can externally identify this
    /// entry for sync purposes. These strings are then indexed.
    fn get_externalid2uuid(&self) -> Option<String> {
        self.attrs
            .get(Attribute::SyncExternalId.as_ref())
            .and_then(|vs| vs.to_proto_string_single())
    }

    #[inline]
    /// Given this entry, extract it's primary security prinicple name, or if not present
    /// extract it's name, and if that's not present, extract it's uuid.
    pub(crate) fn get_uuid2spn(&self) -> Value {
        self.attrs
            .get("spn")
            .and_then(|vs| vs.to_value_single())
            .or_else(|| {
                self.attrs
                    .get(Attribute::Name.as_ref())
                    .and_then(|vs| vs.to_value_single())
            })
            .unwrap_or_else(|| Value::Uuid(self.get_uuid()))
    }

    #[inline]
    /// Given this entry, determine it's relative distinguished named for LDAP compatibility.
    pub(crate) fn get_uuid2rdn(&self) -> String {
        self.attrs
            .get("spn")
            .and_then(|vs| vs.to_proto_string_single().map(|v| format!("spn={v}")))
            .or_else(|| {
                self.attrs
                    .get(Attribute::Name.as_ref())
                    .and_then(|vs| vs.to_proto_string_single().map(|v| format!("name={v}")))
            })
            .unwrap_or_else(|| format!("uuid={}", self.get_uuid().as_hyphenated()))
    }

    /// Generate the required values for a name2uuid index. IE this is
    /// ALL possible names this entry COULD be known uniquely by!
    pub(crate) fn idx_name2uuid_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> (
        // Add
        Option<Set<String>>,
        // Remove
        Option<Set<String>>,
    ) {
        // needs to return gid for posix conversion
        match (pre, post) {
            (None, None) => {
                // No action required
                (None, None)
            }
            (None, Some(b)) => {
                // We are adding this entry (or restoring it),
                // so we need to add the values.
                (Some(b.get_name2uuid_cands()), None)
            }
            (Some(a), None) => {
                // Removing the entry, remove all values.
                (None, Some(a.get_name2uuid_cands()))
            }
            (Some(a), Some(b)) => {
                let pre_set = a.get_name2uuid_cands();
                let post_set = b.get_name2uuid_cands();

                // what is in post, but not pre (added)
                let add_set: Set<_> = post_set.difference(&pre_set).cloned().collect();
                // what is in pre, but not post (removed)
                let rem_set: Set<_> = pre_set.difference(&post_set).cloned().collect();
                (Some(add_set), Some(rem_set))
            }
        }
    }

    /// Generate the required values for externalid2uuid.
    pub(crate) fn idx_externalid2uuid_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> (Option<String>, Option<String>) {
        match (pre, post) {
            (None, None) => {
                // no action
                (None, None)
            }
            (None, Some(b)) => {
                // add
                (b.get_externalid2uuid(), None)
            }
            (Some(a), None) => {
                // remove
                (None, a.get_externalid2uuid())
            }
            (Some(a), Some(b)) => {
                let ia = a.get_externalid2uuid();
                let ib = b.get_externalid2uuid();
                if ia != ib {
                    // Note, we swap these since ib is the new post state
                    // we want to add, and ia is what we remove.
                    (ib, ia)
                } else {
                    // no action
                    (None, None)
                }
            }
        }
    }

    /// Generate a differential between a previous and current entry state, and what changes this
    /// means for the current set of spn's for this uuid.
    pub(crate) fn idx_uuid2spn_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> Option<Result<Value, ()>> {
        match (pre, post) {
            (None, None) => {
                // no action
                None
            }
            (None, Some(b)) => {
                // add
                Some(Ok(b.get_uuid2spn()))
            }
            (Some(_a), None) => {
                // remove
                Some(Err(()))
            }
            (Some(a), Some(b)) => {
                let ia = a.get_uuid2spn();
                let ib = b.get_uuid2spn();
                if ia != ib {
                    // Add (acts as replace)
                    Some(Ok(ib))
                } else {
                    // no action
                    None
                }
            }
        }
    }

    /// Generate a differential between a previous and current entry state, and what changes this
    /// means for the current set of LDAP relative distinguished names.
    pub(crate) fn idx_uuid2rdn_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> Option<Result<String, ()>> {
        match (pre, post) {
            (None, None) => {
                // no action
                None
            }
            (None, Some(b)) => {
                // add
                Some(Ok(b.get_uuid2rdn()))
            }
            (Some(_a), None) => {
                // remove
                Some(Err(()))
            }
            (Some(a), Some(b)) => {
                let ia = a.get_uuid2rdn();
                let ib = b.get_uuid2rdn();
                if ia != ib {
                    // Add (acts as replace)
                    Some(Ok(ib))
                } else {
                    // no action
                    None
                }
            }
        }
    }

    /// Given the previous and current state of this entry, determine the indexing differential
    /// that needs to be applied. i.e. what indexes must be created, modified and removed.
    pub(crate) fn idx_diff<'a>(
        idxmeta: &'a HashMap<IdxKey, IdxSlope>,
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> IdxDiff<'a> {
        // We yield a list of Result, where Ok() means "add",
        // and Err() means "remove".
        // the value inside the result, is a tuple of attr, itype, idx_key

        match (pre, post) {
            (None, None) => {
                // if both are none, yield empty list.
                Vec::new()
            }
            (Some(pre_e), None) => {
                // If we are none (?), yield our pre-state as removals.
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        let attr: Attribute = match Attribute::try_from(ikey.attr.as_str()) {
                            Ok(val) => val,
                            Err(err) => {
                                admin_error!(
                                    "Failed to convert '{}' to attribute: {:?}",
                                    ikey.attr,
                                    err
                                );
                                return Vec::new();
                            }
                        };
                        match pre_e.get_ava_set(attr) {
                            None => Vec::new(),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // We generate these keys out of the valueset now.
                                        vs.generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Err((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                changes
                            }
                        }
                    })
                    .collect()
            }
            (None, Some(post_e)) => {
                // If the pre-state is none, yield our additions.
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        let attr: Attribute = match Attribute::try_from(ikey.attr.as_str()) {
                            Ok(val) => val,
                            Err(err) => {
                                admin_error!(
                                    "Failed to convert '{}' to attribute: {:?}",
                                    ikey.attr,
                                    err
                                );
                                return Vec::new();
                            }
                        };
                        match post_e.get_ava_set(attr) {
                            None => Vec::new(),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => vs
                                        .generate_idx_eq_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Presence => {
                                        vec![Ok((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                // For each value
                                //
                                changes
                            }
                        }
                    })
                    .collect()
            }
            (Some(pre_e), Some(post_e)) => {
                assert!(pre_e.state.id == post_e.state.id);
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        let attr: Attribute = match Attribute::try_from(ikey.attr.as_str()) {
                            Ok(val) => val,
                            Err(err) => {
                                admin_error!(
                                    "Failed to convert '{}' to attribute: {:?}",
                                    ikey.attr,
                                    err
                                );
                                return Vec::new();
                            }
                        };
                        match (pre_e.get_ava_set(attr), post_e.get_ava_set(attr)) {
                            (None, None) => {
                                // Neither have it, do nothing.
                                Vec::new()
                            }
                            (Some(pre_vs), None) => {
                                // It existed before, but not anymore
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // Turn each idx_key to the tuple of
                                        // changes.
                                        pre_vs
                                            .generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Err((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                changes
                            }
                            (None, Some(post_vs)) => {
                                // It was added now.
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // Turn each idx_key to the tuple of
                                        // changes.
                                        post_vs
                                            .generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Ok((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => Vec::new(),
                                };
                                changes
                            }
                            (Some(pre_vs), Some(post_vs)) => {
                                // it exists in both, we need to work out the difference within the attr.

                                let mut pre_idx_keys = pre_vs.generate_idx_eq_keys();
                                pre_idx_keys.sort_unstable();
                                let mut post_idx_keys = post_vs.generate_idx_eq_keys();
                                post_idx_keys.sort_unstable();

                                let sz = if pre_idx_keys.len() > post_idx_keys.len() {
                                    pre_idx_keys.len()
                                } else {
                                    post_idx_keys.len()
                                };

                                let mut pre_iter = pre_idx_keys.iter();
                                let mut post_iter = post_idx_keys.iter();

                                let mut pre = pre_iter.next();
                                let mut post = post_iter.next();

                                let mut added_vs = Vec::with_capacity(sz);

                                let mut removed_vs = Vec::with_capacity(sz);

                                loop {
                                    match (pre, post) {
                                        (Some(a), Some(b)) => {
                                            match a.cmp(b) {
                                                Ordering::Less => {
                                                    removed_vs.push(a.clone());
                                                    pre = pre_iter.next();
                                                }
                                                Ordering::Equal => {
                                                    // In both - no action needed.
                                                    pre = pre_iter.next();
                                                    post = post_iter.next();
                                                }
                                                Ordering::Greater => {
                                                    added_vs.push(b.clone());
                                                    post = post_iter.next();
                                                }
                                            }
                                        }
                                        (Some(a), None) => {
                                            removed_vs.push(a.clone());
                                            pre = pre_iter.next();
                                        }
                                        (None, Some(b)) => {
                                            added_vs.push(b.clone());
                                            post = post_iter.next();
                                        }
                                        (None, None) => {
                                            break;
                                        }
                                    }
                                }

                                let mut diff =
                                    Vec::with_capacity(removed_vs.len() + added_vs.len());

                                match ikey.itype {
                                    IndexType::Equality => {
                                        removed_vs
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                            .for_each(|v| diff.push(v));
                                        added_vs
                                            .into_iter()
                                            .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                            .for_each(|v| diff.push(v));
                                    }
                                    IndexType::Presence => {
                                        // No action - we still are "present", so nothing to do!
                                    }
                                    IndexType::SubString => {}
                                };
                                // Return the diff
                                diff
                            }
                        }
                    })
                    .collect()
                // End diff of the entries
            }
        }
    }

    pub fn from_dbentry(db_e: DbEntry, id: u64) -> Option<Self> {
        // Convert attrs from db format to value

        let (attrs, ecstate) = match db_e.ent {
            DbEntryVers::V1(_) => {
                error!("Db V1 entry should have been migrated!");
                return None;
            }
            DbEntryVers::V2(v2) => {
                let r_attrs = v2
                    .attrs
                    .into_iter()
                    // Skip anything empty as new VS can't deal with it.
                    .filter(|(_k, vs)| !vs.is_empty())
                    .map(|(k, dbvs)| {
                        valueset::from_db_valueset_v2(dbvs)
                            .map(|vs: ValueSet| (k, vs))
                            .map_err(|e| {
                                error!(?e, "from_dbentry failed");
                            })
                    })
                    .collect::<Result<Eattrs, ()>>()
                    .ok()?;

                /*
                 * ⚠️  ==== The Hack Zoen ==== ⚠️
                 *
                 * For now to make replication work, we are synthesising an in-memory change
                 * log, pinned to "the last time the entry was modified" as it's "create time".
                 *
                 * This should only be done *once* on entry load.
                 */
                let cid = r_attrs
                    .get(Attribute::LastModifiedCid.as_ref())
                    .and_then(|vs| vs.as_cid_set())
                    .and_then(|set| set.iter().next().cloned())
                    .or_else(|| {
                        error!("Unable to access last modified cid of entry, unable to proceed");
                        None
                    })?;

                let ecstate = EntryChangeState::new_without_schema(&cid, &r_attrs);

                (r_attrs, ecstate)
            }

            DbEntryVers::V3 { changestate, attrs } => {
                let ecstate = EntryChangeState::from_db_changestate(changestate);

                let r_attrs = attrs
                    .into_iter()
                    // Skip anything empty as new VS can't deal with it.
                    .filter(|(_k, vs)| !vs.is_empty())
                    .map(|(k, dbvs)| {
                        valueset::from_db_valueset_v2(dbvs)
                            .map(|vs: ValueSet| (k, vs))
                            .map_err(|e| {
                                error!(?e, "from_dbentry failed");
                            })
                    })
                    .collect::<Result<Eattrs, ()>>()
                    .ok()?;

                (r_attrs, ecstate)
            }
        };

        let uuid = attrs
            .get(Attribute::Uuid.as_ref())
            .and_then(|vs| vs.to_uuid_single())?;

        Some(Entry {
            valid: EntrySealed { uuid, ecstate },
            state: EntryCommitted { id },
            attrs,
        })
    }

    /// ⚠️  This function bypasses the access control validation logic and should NOT
    /// be used without special care and attention to ensure that no private data
    /// is leaked incorrectly to clients. Generally this is ONLY used inside of
    /// the access control processing functions which correctly applies the reduction
    /// steps.
    ///
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(crate) fn into_reduced(self) -> Entry<EntryReduced, EntryCommitted> {
        Entry {
            valid: EntryReduced {
                uuid: self.valid.uuid,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    /// Given a set of attributes that are allowed to be seen on this entry, process and remove
    /// all other values that are NOT allowed in this query.
    pub fn reduce_attributes(
        &self,
        allowed_attrs: &BTreeSet<&str>,
    ) -> Entry<EntryReduced, EntryCommitted> {
        // Remove all attrs from our tree that are NOT in the allowed set.
        let f_attrs: Map<_, _> = self
            .attrs
            .iter()
            .filter_map(|(k, v)| {
                if allowed_attrs.contains(k.as_str()) {
                    Some((k.clone(), v.clone()))
                } else {
                    None
                }
            })
            .collect();

        let valid = EntryReduced {
            uuid: self.valid.uuid,
        };
        let state = self.state.clone();

        Entry {
            valid,
            state,
            attrs: f_attrs,
        }
    }

    /// Convert this recycled entry, into a tombstone ready for reaping.
    pub fn to_tombstone(&self, cid: Cid) -> Entry<EntryInvalid, EntryCommitted> {
        let mut ecstate = self.valid.ecstate.clone();
        // Duplicate this to a tombstone entry
        let mut attrs_new: Eattrs = Map::new();

        let class_ava = vs_iutf8![EntryClass::Object.into(), EntryClass::Tombstone.into()];
        let last_mod_ava = vs_cid![cid.clone()];

        attrs_new.insert(Attribute::Uuid.into(), vs_uuid![self.get_uuid()]);
        attrs_new.insert(Attribute::Class.into(), class_ava);
        attrs_new.insert(Attribute::LastModifiedCid.into(), last_mod_ava);

        // ⚠️  No return from this point!
        ecstate.tombstone(&cid);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: self.state.clone(),
            attrs: attrs_new,
        }
    }

    /// Given a current transaction change identifier, mark this entry as valid and committed.
    pub fn into_valid(self, ecstate: EntryChangeState) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self.valid.uuid,
                ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn verify(
        &self,
        schema: &dyn SchemaTransaction,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        self.valid
            .ecstate
            .verify(schema, &self.attrs, self.state.id, results);
    }
}

impl<STATE> Entry<EntryValid, STATE> {
    fn validate(&self, schema: &dyn SchemaTransaction) -> Result<(), SchemaError> {
        let schema_classes = schema.get_classes();
        let schema_attributes = schema.get_attributes();

        // Now validate it!
        trace!(?self.attrs, "Entry::validate -> target");

        // First, check we have class on the object ....
        if !self.attribute_pres(Attribute::Class) {
            // lrequest_error!("Missing attribute class");
            return Err(SchemaError::NoClassFound);
        }

        if self.attribute_equality(Attribute::Class, &EntryClass::Conflict.into()) {
            // Conflict entries are exempt from schema enforcement. Return true.
            trace!("Skipping schema validation on conflict entry");
            return Ok(());
        };

        // Are we in the recycle bin? We soften some checks if we are.
        let recycled = self.attribute_equality(Attribute::Class, &EntryClass::Recycled.into());

        // Do we have extensible? We still validate syntax of attrs but don't
        // check for valid object structures.
        let extensible =
            self.attribute_equality(Attribute::Class, &EntryClass::ExtensibleObject.into());

        let entry_classes = self.get_ava_set(Attribute::Class).ok_or_else(|| {
            admin_debug!("Attribute '{}' missing from entry", Attribute::Class);
            SchemaError::NoClassFound
        })?;
        let mut invalid_classes = Vec::with_capacity(0);

        let mut classes: Vec<&SchemaClass> = Vec::with_capacity(entry_classes.len());

        // We need to keep the btreeset of entry classes here so we can check the
        // requires and excludes.
        let entry_classes = if let Some(ec) = entry_classes.as_iutf8_set() {
            ec.iter()
                .for_each(|s| match schema_classes.get(s.as_str()) {
                    Some(x) => classes.push(x),
                    None => {
                        admin_debug!("invalid class: {:?}", s);
                        invalid_classes.push(s.to_string())
                    }
                });
            ec
        } else {
            admin_debug!("corrupt class attribute");
            return Err(SchemaError::NoClassFound);
        };

        if !invalid_classes.is_empty() {
            return Err(SchemaError::InvalidClass(invalid_classes));
        };

        // Now determine the set of excludes and requires we have, and then
        // assert we don't violate them.

        let supplements_classes: Vec<_> = classes
            .iter()
            .flat_map(|cls| cls.systemsupplements.iter().chain(cls.supplements.iter()))
            .collect();

        // So long as one supplement is present we can continue.
        let valid_supplements = if supplements_classes.is_empty() {
            // No need to check.
            true
        } else {
            supplements_classes
                .iter()
                .any(|class| entry_classes.contains(class.as_str()))
        };

        if !valid_supplements {
            admin_warn!(
                "Validation error, the following possible supplement classes are missing - {:?}",
                supplements_classes
            );
            let supplements_classes = supplements_classes.iter().map(|s| s.to_string()).collect();
            return Err(SchemaError::SupplementsNotSatisfied(supplements_classes));
        }

        let excludes_classes: Vec<_> = classes
            .iter()
            .flat_map(|cls| cls.systemexcludes.iter().chain(cls.excludes.iter()))
            .collect();

        let mut invalid_excludes = Vec::with_capacity(0);

        excludes_classes.iter().for_each(|class| {
            if entry_classes.contains(class.as_str()) {
                invalid_excludes.push(class.to_string())
            }
        });

        if !invalid_excludes.is_empty() {
            admin_warn!(
                "Validation error, the following excluded classes are present - {:?}",
                invalid_excludes
            );
            return Err(SchemaError::ExcludesNotSatisfied(invalid_excludes));
        }

        // What this is really doing is taking a set of classes, and building an
        // "overall" class that describes this exact object for checking. IE we
        // build a super must/may set from the small class must/may sets.

        //   for each class
        //      add systemmust/must and systemmay/may to their lists
        //      add anything from must also into may

        // Now from the set of valid classes make a list of must/may
        //
        // NOTE: We still need this on extensible, because we still need to satisfy
        // our other must conditions as well!
        let must: Result<Vec<&SchemaAttribute>, _> = classes
            .iter()
            // Join our class systemmmust + must into one iter
            .flat_map(|cls| cls.systemmust.iter().chain(cls.must.iter()))
            .map(|s| {
                // This should NOT fail - if it does, it means our schema is
                // in an invalid state!
                schema_attributes.get(s).ok_or(SchemaError::Corrupted)
            })
            .collect();

        let must = must?;

        // Check that all must are inplace
        //   for each attr in must, check it's present on our ent
        let mut missing_must = Vec::with_capacity(0);
        for attr in must.iter() {
            let attribute: Attribute = match Attribute::try_from(attr.name.as_str()) {
                Ok(val) => val,
                Err(err) => {
                    admin_error!(
                        "Failed to convert missing_must '{}' to attribute: {:?}",
                        attr.name,
                        err
                    );
                    return Err(SchemaError::InvalidAttribute(attr.name.to_string()));
                }
            };

            let avas = self.get_ava_set(attribute);
            if avas.is_none() {
                missing_must.push(attr.name.to_string());
            }
        }

        if !missing_must.is_empty() {
            admin_warn!(
                "Validation error, the following required ({}) (must) attributes are missing - {:?}",
                self.get_display_id(), missing_must
            );
            // We if are in the recycle bin, we don't hard error here. This can occur when
            // a migration occurs and we delete an acp, and then the related group. Because
            // this would trigger refint which purges the acp_receiver_group, then this
            // must value becomes unsatisfiable. So here we soften the check for recycled
            // entries because they are in a "nebulous" state anyway.
            if !recycled {
                return Err(SchemaError::MissingMustAttribute(missing_must));
            }
        }

        if extensible {
            self.attrs.iter().try_for_each(|(attr_name, avas)| {
                    match schema_attributes.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            if a_schema.phantom {
                                admin_warn!(
                                    "Rejecting attempt to add phantom attribute to extensible object: {}",
                                    attr_name
                                );
                                Err(SchemaError::PhantomAttribute(attr_name.to_string()))
                            } else {
                                a_schema.validate_ava(attr_name.as_str(), avas)
                                // .map_err(|e| lrequest_error!("Failed to validate: {}", attr_name);)
                            }
                        }
                        None => {
                            admin_error!(
                                "Invalid Attribute {}, undefined in schema_attributes",
                                attr_name.to_string()
                            );
                            Err(SchemaError::InvalidAttribute(
                                attr_name.to_string()
                            ))
                        }
                    }
                })?;
        } else {
            // Note - we do NOT need to check phantom attributes here because they are
            // not allowed to exist in the class, which means a phantom attribute can't
            // be in the may/must set, and would FAIL our normal checks anyway.

            // The set of "may" is a combination of may and must, since we have already
            // asserted that all must requirements are fulfilled. This allows us to
            // perform extended attribute checking in a single pass.
            let may: Result<Map<&AttrString, &SchemaAttribute>, _> = classes
                .iter()
                // Join our class systemmmust + must + systemmay + may into one.
                .flat_map(|cls| {
                    cls.systemmust
                        .iter()
                        .chain(cls.must.iter())
                        .chain(cls.systemmay.iter())
                        .chain(cls.may.iter())
                })
                .map(|s| {
                    // This should NOT fail - if it does, it means our schema is
                    // in an invalid state!
                    Ok((s, schema_attributes.get(s).ok_or(SchemaError::Corrupted)?))
                })
                .collect();

            let may = may?;

            // TODO #70: Error needs to say what is missing
            // We need to return *all* missing attributes, not just the first error
            // we find. This will probably take a rewrite of the function definition
            // to return a result<_, vec<schemaerror>> and for the schema errors to take
            // information about what is invalid. It's pretty nontrivial.

            // Check that any other attributes are in may
            //   for each attr on the object, check it's in the may+must set
            self.attrs.iter().try_for_each(|(attr_name, avas)| {
                    match may.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            a_schema.validate_ava(attr_name.as_str(), avas)
                            // .map_err(|e| lrequest_error!("Failed to validate: {}", attr_name);
                        }
                        None => {
                            admin_error!(
                                "{} {} - not found in the list of valid attributes for this set of classes {:?} - valid attributes are {:?}",

                                attr_name.to_string(),
                                self.get_display_id(),
                                entry_classes.iter().collect::<Vec<_>>(),
                                may.keys().collect::<Vec<_>>()
                            );
                            Err(SchemaError::AttributeNotValidForClass(
                                attr_name.to_string()
                            ))
                        }
                    }
                })?;
        }

        // Well, we got here, so okay!
        Ok(())
    }

    pub fn seal(self, schema: &dyn SchemaTransaction) -> Entry<EntrySealed, STATE> {
        let EntryValid { uuid, mut ecstate } = self.valid;

        // Remove anything from the ecstate that is not a replicated attribute in the schema.
        // This is to allow ecstate equality to work, but also to just prevent ruv updates and
        // replicating things that only touched or changed phantom attrs.
        ecstate.retain(|k, _| schema.is_replicated(k));

        Entry {
            valid: EntrySealed { uuid, ecstate },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }
}

impl<STATE> Entry<EntrySealed, STATE>
where
    STATE: Clone,
{
    pub fn invalidate(mut self, cid: Cid, trim_cid: &Cid) -> Entry<EntryInvalid, STATE> {
        // Trim attributes that require it. For most this is a no-op.
        for vs in self.attrs.values_mut() {
            vs.trim(trim_cid);
        }

        Entry {
            valid: EntryInvalid {
                cid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        }
        /* Setup our last changed time. */
        // We can't actually trigger last changed here. This creates a replication loop
        // inside of memberof plugin which invalidates. For now we treat last_changed
        // more as "create" so we only trigger it via assign_cid in the create path
        // and in conflict entry creation.
        /*
        trace!("trigger_last_changed - invalidate");
        ent.trigger_last_changed();
        ent
        */
    }

    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }

    pub fn get_changestate(&self) -> &EntryChangeState {
        &self.valid.ecstate
    }

    /// ⚠️  - Invalidate an entry by resetting it's change state to time-zero. This entry
    /// can never be replicated after this.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(crate) fn into_invalid(mut self) -> Entry<EntryInvalid, STATE> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());

        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryReduced, EntryCommitted> {
    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }

    /// Transform this reduced entry into a JSON protocol form that can be sent to clients.
    pub fn to_pe(&self, qs: &mut QueryServerReadTransaction) -> Result<ProtoEntry, OperationError> {
        // Turn values -> Strings.
        let attrs: Result<_, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| qs.resolve_valueset(vs).map(|pvs| (k.to_string(), pvs)))
            .collect();
        Ok(ProtoEntry { attrs: attrs? })
    }

    /// Transform this reduced entry into an LDAP form that can be sent to clients.
    pub fn to_ldap(
        &self,
        qs: &mut QueryServerReadTransaction,
        basedn: &str,
        // Did the client request all attributes?
        all_attrs: bool,
        // Did the ldap client request any sperific attribute names? If so,
        // we need to remap everything to match.
        l_attrs: &[String],
    ) -> Result<LdapSearchResultEntry, OperationError> {
        let rdn = qs.uuid_to_rdn(self.get_uuid())?;

        let dn = format!("{rdn},{basedn}");

        // Everything in our attrs set is "what was requested". So we can transform that now
        // so they are all in "ldap forms" which makes our next stage a bit easier.

        // Stage 1 - transform our results to a map of kani attr -> ldap value.
        let attr_map: Result<Map<&str, Vec<Vec<u8>>>, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| {
                qs.resolve_valueset_ldap(vs, basedn)
                    .map(|pvs| (k.as_str(), pvs))
            })
            .collect();
        let attr_map = attr_map?;

        // Stage 2 - transform and get all our attr - names out that we need to return.
        //                  ldap a, kani a
        let attr_names: Vec<(&str, &str)> = if all_attrs {
            // Join the set of attr keys, and our requested attrs.
            self.attrs
                .keys()
                .map(|k| (k.as_str(), k.as_str()))
                .chain(
                    l_attrs
                        .iter()
                        .map(|k| (k.as_str(), ldap_vattr_map(k.as_str()).unwrap_or(k.as_str()))),
                )
                .collect()
        } else {
            // Just get the requested ones.
            l_attrs
                .iter()
                .map(|k| (k.as_str(), ldap_vattr_map(k.as_str()).unwrap_or(k.as_str())))
                .collect()
        };

        // Stage 3 - given our map, generate the final result.
        let attributes: Vec<_> = attr_names
            .into_iter()
            .filter_map(|(ldap_a, kani_a)| {
                // In some special cases, we may need to transform or rewrite the values.
                match ldap_a {
                    LDAP_ATTR_DN => Some(LdapPartialAttribute {
                        atype: LDAP_ATTR_DN.to_string(),
                        vals: vec![dn.as_bytes().to_vec()],
                    }),
                    LDAP_ATTR_ENTRYDN => Some(LdapPartialAttribute {
                        atype: LDAP_ATTR_ENTRYDN.to_string(),
                        vals: vec![dn.as_bytes().to_vec()],
                    }),
                    LDAP_ATTR_MAIL_PRIMARY | LDAP_ATTR_EMAIL_PRIMARY => {
                        attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                            atype: ldap_a.to_string(),
                            vals: pvs
                                .first()
                                .map(|first| vec![first.clone()])
                                .unwrap_or_default(),
                        })
                    }
                    LDAP_ATTR_MAIL_ALTERNATIVE | LDAP_ATTR_EMAIL_ALTERNATIVE => {
                        attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                            atype: ldap_a.to_string(),
                            vals: pvs
                                .split_first()
                                .map(|(_, rest)| rest.to_vec())
                                .unwrap_or_default(),
                        })
                    }
                    _ => attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                        atype: ldap_a.to_string(),
                        vals: pvs.clone(),
                    }),
                }
            })
            .collect();

        Ok(LdapSearchResultEntry { dn, attributes })
    }
}

// impl<STATE> Entry<EntryValid, STATE> {
impl<VALID, STATE> Entry<VALID, STATE> {
    /// This internally adds an AVA to the entry. If the entry was newly added, then true is returned.
    /// If the value already existed, or was unable to be added, false is returned. Alternately,
    /// you can think of this boolean as "if a write occurred to the structure", true indicating that
    /// a change occurred.
    fn add_ava_int(&mut self, attr: Attribute, value: Value) -> bool {
        if let Some(vs) = self.attrs.get_mut(attr.as_ref()) {
            let r = vs.insert_checked(value);
            debug_assert!(r.is_ok());
            // Default to the value not being present if wrong typed.
            r.unwrap_or(false)
        } else {
            #[allow(clippy::expect_used)]
            let vs = valueset::from_value_iter(std::iter::once(value))
                .expect("Unable to fail - non-zero iter, and single value type!");
            self.attrs.insert(attr.into(), vs);
            // The attribute did not exist before.
            true
        }
        // Doesn't matter if it already exists, equality will replace.
    }

    /// Overwrite the current set of values for an attribute, with this new set.
    fn set_ava_iter_int<T>(&mut self, attr: Attribute, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        let Ok(vs) = valueset::from_value_iter(iter.into_iter()) else {
            trace!("set_ava_iter_int - empty from_value_iter, skipping");
            return;
        };

        if let Some(existing_vs) = self.attrs.get_mut(attr.as_ref()) {
            // This is the suboptimal path. This can only exist in rare cases.
            let _ = existing_vs.merge(&vs);
        } else {
            // Normally this is what's taken.
            self.attrs.insert(AttrString::from(attr), vs);
        }
    }

    /// Update the last_changed flag of this entry to the given change identifier.
    #[cfg(test)]
    fn set_last_changed(&mut self, cid: Cid) {
        let cv = vs_cid![cid];
        let _ = self.attrs.insert(Attribute::LastModifiedCid.into(), cv);
    }

    pub(crate) fn get_display_id(&self) -> String {
        self.attrs
            .get(Attribute::Spn.as_ref())
            .and_then(|vs| vs.to_value_single())
            .or_else(|| {
                self.attrs
                    .get(Attribute::Name.as_ref())
                    .and_then(|vs| vs.to_value_single())
            })
            .or_else(|| {
                self.attrs
                    .get(Attribute::Uuid.as_ref())
                    .and_then(|vs| vs.to_value_single())
            })
            .map(|value| value.to_proto_string_clone())
            .unwrap_or_else(|| "no entry id available".to_string())
    }

    #[inline(always)]
    /// Get an iterator over the current set of attribute names that this entry contains.
    pub fn get_ava_names(&self) -> impl Iterator<Item = &str> {
        // Get the set of all attribute names in the entry
        self.attrs.keys().map(|a| a.as_str())
    }

    #[inline(always)]
    /// Get an iterator over the current set of values for an attribute name.
    pub fn get_ava(&self) -> &Eattrs {
        &self.attrs
    }

    #[inline(always)]
    pub fn get_ava_iter(&self) -> impl Iterator<Item = (&AttrString, &ValueSet)> {
        self.attrs.iter()
    }

    #[inline(always)]
    /// Return a reference to the current set of values that are associated to this attribute.
    pub fn get_ava_set(&self, attr: Attribute) -> Option<&ValueSet> {
        self.attrs.get(attr.as_ref())
    }

    pub fn get_ava_refer(&self, attr: Attribute) -> Option<&BTreeSet<Uuid>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_refer_set())
    }

    #[inline(always)]
    pub fn get_ava_as_iutf8_iter(&self, attr: Attribute) -> Option<impl Iterator<Item = &str>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_iutf8_iter())
    }

    #[inline(always)]
    pub fn get_ava_as_iutf8(&self, attr: Attribute) -> Option<&BTreeSet<String>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_iutf8_set())
    }

    #[inline(always)]
    pub fn get_ava_as_image(&self, attr: Attribute) -> Option<&HashSet<ImageValue>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_imageset())
    }

    #[inline(always)]
    pub fn get_ava_single_image(&self, attr: Attribute) -> Option<ImageValue> {
        let images = self
            .attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_imageset())?;
        images.iter().next().cloned()
    }

    #[inline(always)]
    pub fn get_ava_single_credential_type(&self, attr: Attribute) -> Option<CredentialType> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_credentialtype_single())
    }

    #[inline(always)]
    pub fn get_ava_as_oauthscopes(&self, attr: Attribute) -> Option<impl Iterator<Item = &str>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_oauthscope_iter())
    }

    #[inline(always)]
    pub fn get_ava_as_oauthscopemaps(
        &self,
        attr: Attribute,
    ) -> Option<&std::collections::BTreeMap<Uuid, std::collections::BTreeSet<String>>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_oauthscopemap())
    }

    #[inline(always)]
    pub fn get_ava_as_intenttokens(
        &self,
        attr: Attribute,
    ) -> Option<&std::collections::BTreeMap<String, IntentTokenState>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_intenttoken_map())
    }

    #[inline(always)]
    pub fn get_ava_as_session_map(
        &self,
        attr: Attribute,
    ) -> Option<&std::collections::BTreeMap<Uuid, Session>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_session_map())
    }

    #[inline(always)]
    pub fn get_ava_as_apitoken_map(
        &self,
        attr: Attribute,
    ) -> Option<&std::collections::BTreeMap<Uuid, ApiToken>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_apitoken_map())
    }

    #[inline(always)]
    pub fn get_ava_as_oauth2session_map(
        &self,
        attr: Attribute,
    ) -> Option<&std::collections::BTreeMap<Uuid, Oauth2Session>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_oauth2session_map())
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of values transformed into a `&str`.
    pub fn get_ava_iter_iname(&self, attr: Attribute) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_iname_iter())
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of values transformed into a `&str`.
    pub fn get_ava_iter_iutf8(&self, attr: Attribute) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_iutf8_iter())
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of values transformed into a `Uuid`.
    pub fn get_ava_as_refuuid(
        &self,
        attr: Attribute,
    ) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // If any value is NOT a reference, it's filtered out.
        self.get_ava_set(attr).and_then(|vs| vs.as_ref_uuid_iter())
    }

    #[inline(always)]
    /// If possible, return an iterator over the set of ssh key values transformed into a `&str`.
    pub fn get_ava_iter_sshpubkeys(
        &self,
        attr: Attribute,
    ) -> Option<impl Iterator<Item = String> + '_> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_sshpubkey_string_iter())
    }

    // These are special types to allow returning typed values from
    // an entry, if we "know" what we expect to receive.

    /// This returns an array of IndexTypes, when the type is an Optional
    /// multivalue in schema - IE this will *not* fail if the attribute is
    /// empty, yielding and empty array instead.
    ///
    /// However, the conversion to IndexType is fallible, so in case of a failure
    /// to convert, an empty vec is returned
    #[inline(always)]
    pub(crate) fn get_ava_opt_index(&self, attr: Attribute) -> Option<Vec<IndexType>> {
        if let Some(vs) = self.get_ava_set(attr) {
            vs.as_indextype_iter().map(|i| i.collect())
        } else {
            // Empty, but consider as valid.
            Some(vec![])
        }
    }

    /// Return a single value of this attributes name, or `None` if it is NOT present, or
    /// there are multiple values present (ambiguous).
    #[inline(always)]
    pub fn get_ava_single(&self, attr: Attribute) -> Option<Value> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_value_single())
    }

    pub fn get_ava_single_proto_string(&self, attr: Attribute) -> Option<String> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_proto_string_single())
    }

    #[inline(always)]
    /// Return a single bool, if valid to transform this value into a boolean.
    pub fn get_ava_single_bool(&self, attr: Attribute) -> Option<bool> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_bool_single())
    }

    #[inline(always)]
    /// Return a single uint32, if valid to transform this value.
    pub fn get_ava_single_uint32(&self, attr: Attribute) -> Option<u32> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_uint32_single())
    }

    #[inline(always)]
    /// Return a single syntax type, if valid to transform this value.
    pub fn get_ava_single_syntax(&self, attr: Attribute) -> Option<SyntaxType> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_syntaxtype_single())
    }

    #[inline(always)]
    /// Return a single credential, if valid to transform this value.
    pub fn get_ava_single_credential(&self, attr: Attribute) -> Option<&Credential> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_credential_single())
    }

    #[inline(always)]
    /// Get the set of passkeys on this account, if any are present.
    pub fn get_ava_passkeys(
        &self,
        attr: Attribute,
    ) -> Option<&BTreeMap<Uuid, (String, PasskeyV4)>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_passkey_map())
    }

    #[inline(always)]
    /// Get the set of devicekeys on this account, if any are present.
    pub fn get_ava_attestedpasskeys(
        &self,
        attr: Attribute,
    ) -> Option<&BTreeMap<Uuid, (String, AttestedPasskeyV4)>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_attestedpasskey_map())
    }

    #[inline(always)]
    /// Get the set of uihints on this account, if any are present.
    pub fn get_ava_uihint(&self, attr: Attribute) -> Option<&BTreeSet<UiHint>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_uihint_set())
    }

    #[inline(always)]
    /// Return a single secret value, if valid to transform this value.
    pub fn get_ava_single_secret(&self, attr: Attribute) -> Option<&str> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_secret_single())
    }

    #[inline(always)]
    /// Return a single datetime, if valid to transform this value.
    pub fn get_ava_single_datetime(&self, attr: Attribute) -> Option<OffsetDateTime> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_datetime_single())
    }

    #[inline(always)]
    /// Return a single `&str`, if valid to transform this value.
    pub(crate) fn get_ava_single_utf8(&self, attr: Attribute) -> Option<&str> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_utf8_single())
    }

    #[inline(always)]
    /// Return a single `&str`, if valid to transform this value.
    pub(crate) fn get_ava_single_iutf8(&self, attr: Attribute) -> Option<&str> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_iutf8_single())
    }

    #[inline(always)]
    /// Return a single `&str`, if valid to transform this value.
    pub(crate) fn get_ava_single_iname(&self, attr: Attribute) -> Option<&str> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_iname_single())
    }

    #[inline(always)]
    /// Return a single `&Url`, if valid to transform this value.
    pub fn get_ava_single_url(&self, attr: Attribute) -> Option<&Url> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_url_single())
    }

    pub fn get_ava_single_uuid(&self, attr: Attribute) -> Option<Uuid> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_uuid_single())
    }

    pub fn get_ava_single_refer(&self, attr: Attribute) -> Option<Uuid> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_refer_single())
    }

    pub fn get_ava_mail_primary(&self, attr: Attribute) -> Option<&str> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_email_address_primary_str())
    }

    pub fn get_ava_iter_mail(&self, attr: Attribute) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_email_str_iter())
    }

    #[inline(always)]
    /// Return a single protocol filter, if valid to transform this value.
    pub fn get_ava_single_protofilter(&self, attr: Attribute) -> Option<&ProtoFilter> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_json_filter_single())
    }

    pub fn get_ava_single_private_binary(&self, attr: Attribute) -> Option<&[u8]> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_private_binary_single())
    }

    pub fn get_ava_single_jws_key_es256(&self, attr: Attribute) -> Option<&JwsEs256Signer> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_jws_key_es256_single())
    }

    pub fn get_ava_single_eckey_private(&self, attr: Attribute) -> Option<&EcKey<Private>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_eckey_private_single())
    }

    pub fn get_ava_single_eckey_public(&self, attr: Attribute) -> Option<&EcKey<Public>> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.to_eckey_public_single())
    }

    pub fn get_ava_webauthn_attestation_ca_list(
        &self,
        attr: Attribute,
    ) -> Option<&AttestationCaList> {
        self.attrs
            .get(attr.as_ref())
            .and_then(|vs| vs.as_webauthn_attestation_ca_list())
    }

    #[inline(always)]
    /// Return a single security principle name, if valid to transform this value.
    pub(crate) fn generate_spn(&self, domain_name: &str) -> Option<Value> {
        self.get_ava_single_iname(Attribute::Name)
            .map(|name| Value::new_spn_str(name, domain_name))
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present on this entry.
    pub fn attribute_pres(&self, attr: Attribute) -> bool {
        self.attrs.contains_key(attr.as_ref())
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of its values contains
    /// an exact match of this partial value.
    pub fn attribute_equality(&self, attr: Attribute, value: &PartialValue) -> bool {
        // we assume based on schema normalisation on the way in
        // that the equality here of the raw values MUST be correct.
        // We also normalise filters, to ensure that their values are
        // syntax valid and will correctly match here with our indexes.
        match self.attrs.get(attr.as_ref()) {
            Some(v_list) => v_list.contains(value),
            None => false,
        }
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of it's values contains
    /// the following substring, if possible to perform the substring comparison.
    pub fn attribute_substring(&self, attr: Attribute, subvalue: &PartialValue) -> bool {
        self.attrs
            .get(attr.as_ref())
            .map(|vset| vset.substring(subvalue))
            .unwrap_or(false)
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of its values startswith
    /// the following string, if possible to perform the comparison.
    pub fn attribute_startswith(&self, attr: Attribute, subvalue: &PartialValue) -> bool {
        self.attrs
            .get(attr.as_ref())
            .map(|vset| vset.startswith(subvalue))
            .unwrap_or(false)
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of its values startswith
    /// the following string, if possible to perform the comparison.
    pub fn attribute_endswith(&self, attr: Attribute, subvalue: &PartialValue) -> bool {
        self.attrs
            .get(attr.as_ref())
            .map(|vset| vset.endswith(subvalue))
            .unwrap_or(false)
    }

    #[inline(always)]
    /// Assert if an attribute of this name is present, and one of its values is less than
    /// the following partial value
    pub fn attribute_lessthan(&self, attr: Attribute, subvalue: &PartialValue) -> bool {
        self.attrs
            .get(attr.as_ref())
            .map(|vset| vset.lessthan(subvalue))
            .unwrap_or(false)
    }

    // Since EntryValid/Invalid is just about class adherenece, not Value correctness, we
    // can now apply filters to invalid entries - why? Because even if they aren't class
    // valid, we still have strict typing checks between the filter -> entry to guarantee
    // they should be functional. We'll never match something that isn't syntactially valid.
    #[inline(always)]
    #[instrument(level = "trace", name = "entry::entry_match_no_index", skip(self))]
    /// Test if the following filter applies to and matches this entry.
    pub fn entry_match_no_index(&self, filter: &Filter<FilterValidResolved>) -> bool {
        self.entry_match_no_index_inner(filter.to_inner())
    }

    // This is private, but exists on all types, so that valid and normal can then
    // expose the simpler wrapper for entry_match_no_index only.
    // Assert if this filter matches the entry (no index)
    fn entry_match_no_index_inner(&self, filter: &FilterResolved) -> bool {
        // Go through the filter components and check them in the entry.
        // This is recursive!!!!
        match filter {
            FilterResolved::Eq(attr, value, _) => match attr.try_into() {
                Ok(a) => self.attribute_equality(a, value),
                Err(_) => {
                    admin_error!("Failed to convert {} to attribute!", attr);
                    false
                }
            },
            FilterResolved::Cnt(attr, subvalue, _) => match attr.try_into() {
                Ok(a) => self.attribute_substring(a, subvalue),
                Err(_) => {
                    admin_error!("Failed to convert {} to attribute!", attr);
                    false
                }
            },
            FilterResolved::Stw(attr, subvalue, _) => match attr.try_into() {
                Ok(a) => self.attribute_startswith(a, subvalue),
                Err(_) => {
                    admin_error!("Failed to convert {} to attribute!", attr);
                    false
                }
            },
            FilterResolved::Enw(attr, subvalue, _) => match attr.try_into() {
                Ok(a) => self.attribute_endswith(a, subvalue),
                Err(_) => {
                    admin_error!("Failed to convert {} to attribute!", attr);
                    false
                }
            },
            FilterResolved::Pres(attr, _) => match attr.try_into() {
                Ok(a) => self.attribute_pres(a),
                Err(_) => {
                    admin_error!("Failed to convert {} to attribute!", attr);
                    false
                }
            },
            FilterResolved::LessThan(attr, subvalue, _) => match attr.try_into() {
                Ok(a) => self.attribute_lessthan(a, subvalue),
                Err(_) => {
                    admin_error!("Failed to convert {} to attribute!", attr);
                    false
                }
            },
            // Check with ftweedal about or filter zero len correctness.
            FilterResolved::Or(l, _) => l.iter().any(|f| self.entry_match_no_index_inner(f)),
            // Check with ftweedal about and filter zero len correctness.
            FilterResolved::And(l, _) => l.iter().all(|f| self.entry_match_no_index_inner(f)),
            FilterResolved::Inclusion(_, _) => {
                // An inclusion doesn't make sense on an entry in isolation!
                // Inclusions are part of exists queries, on search they mean
                // nothing!
                false
            }
            FilterResolved::AndNot(f, _) => !self.entry_match_no_index_inner(f),
        }
    }

    /// Given this entry, generate a filter containing the requested attributes strings as
    /// equality components.
    pub fn filter_from_attrs(&self, attrs: &[AttrString]) -> Option<Filter<FilterInvalid>> {
        // Because we are a valid entry, a filter we create still may not
        // be valid because the internal server entry templates are still
        // created by humans! Plus double checking something already valid
        // is not bad ...
        //
        // Generate a filter from the attributes requested and defined.
        // Basically, this is a series of nested and's (which will be
        // optimised down later: but if someone wants to solve flatten() ...)

        // Take name: (a, b), name: (c, d) -> (name, a), (name, b), (name, c), (name, d)

        let mut pairs: Vec<(&str, PartialValue)> = Vec::new();

        for attr in attrs {
            match self.attrs.get(attr) {
                Some(values) => values
                    .to_partialvalue_iter()
                    .for_each(|pv| pairs.push((attr, pv))),
                None => return None,
            }
        }

        let res: Vec<FC<'_>> = pairs
            .into_iter()
            .map(|(attr, pv)| FC::Eq(attr, pv))
            .collect();
        Some(filter_all!(f_and(res)))
    }

    /// Given this entry, generate a modification list that would "assert"
    /// another entry is in the same/identical attribute state.
    pub fn gen_modlist_assert(
        &self,
        schema: &dyn SchemaTransaction,
    ) -> Result<ModifyList<ModifyInvalid>, SchemaError> {
        // Create a modlist from this entry. We make this assuming we want the entry
        // to have this one as a subset of values. This means if we have single
        // values, we'll replace, if they are multivalue, we present them.
        let mut mods = ModifyList::new();

        for (k, vs) in self.attrs.iter() {
            // WHY?! We skip uuid here because it is INVALID for a UUID
            // to be in a modlist, and the base.rs plugin will fail if it
            // is there. This actually doesn't matter, because to apply the
            // modlist in these situations we already know the entry MUST
            // exist with that UUID, we only need to conform it's other
            // attributes into the same state.
            //
            // In the future, if we make uuid a real entry type, then this
            // check can "go away" because uuid will never exist as an ava.
            //
            // NOTE: Remove this check when uuid becomes a real attribute.
            // UUID is now a real attribute, but it also has an ava for db_entry
            // conversion - so what do? If we remove it here, we could have CSN issue with
            // repl on uuid conflict, but it probably shouldn't be an ava either ...
            // as a result, I think we need to keep this continue line to not cause issues.
            if k == Attribute::Uuid.as_ref() {
                continue;
            }
            // Get the schema attribute type out.
            match schema.is_multivalue(k) {
                Ok(r) => {
                    if !r || k == "systemmust" || k == "systemmay" {
                        // As this is single value, purge then present to maintain this
                        // invariant. The other situation we purge is within schema with
                        // the system types where we need to be able to express REMOVAL
                        // of attributes, thus we need the purge.
                        mods.push_mod(Modify::Purged(k.clone()));
                    }
                }
                // A schema error happened, fail the whole operation.
                Err(e) => return Err(e),
            }
            for v in vs.to_value_iter() {
                mods.push_mod(Modify::Present(k.clone(), v.clone()));
            }
        }

        Ok(mods)
    }

    /// Determine if this entry is recycled or a tombstone, and map that to "None". This allows
    /// filter_map to effectively remove entries that should not be considered as "alive".
    pub fn mask_recycled_ts(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else always Some(self).
        match self.attrs.get(Attribute::Class.as_ref()) {
            Some(cls) => {
                if cls.contains(&EntryClass::Tombstone.to_partialvalue())
                    || cls.contains(&EntryClass::Recycled.to_partialvalue())
                {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }

    /// Determine if this entry is recycled, and map that to "None". This allows
    /// filter_map to effectively remove entries that are recycled in some cases.
    pub fn mask_recycled(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else lways Some(self).
        match self.attrs.get(Attribute::Class.as_ref()) {
            Some(cls) => {
                if cls.contains(&EntryClass::Recycled.to_partialvalue()) {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }

    /// Determine if this entry is a tombstone, and map that to "None". This allows
    /// filter_map to effectively remove entries that are tombstones in some cases.
    pub fn mask_tombstone(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else lways Some(self).
        match self.attrs.get(Attribute::Class.as_ref()) {
            Some(cls) => {
                if cls.contains(&EntryClass::Tombstone.to_partialvalue()) {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }
}

impl<STATE> Entry<EntryInvalid, STATE>
where
    STATE: Clone,
{
    fn trigger_last_changed(&mut self) {
        self.valid
            .ecstate
            .change_ava(&self.valid.cid, Attribute::LastModifiedCid);
        let cv = vs_cid![self.valid.cid.clone()];
        let _ = self.attrs.insert(Attribute::LastModifiedCid.into(), cv);
    }

    // This should always work? It's only on validate that we'll build
    // a list of syntax violations ...
    // If this already exists, we silently drop the event. This is because
    // we need this to be *state* based where we assert presence.
    pub fn add_ava(&mut self, attr: Attribute, value: Value) {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);
        self.add_ava_int(attr, value);
    }

    pub fn add_ava_if_not_exist(&mut self, attr: Attribute, value: Value) {
        // This returns true if the value WAS changed! See add_ava_int.
        if self.add_ava_int(attr, value) {
            // In this case, we ONLY update the changestate if the value was already present!
            self.valid.ecstate.change_ava(&self.valid.cid, attr);
        }
    }

    fn assert_ava(&mut self, attr: Attribute, value: &PartialValue) -> Result<(), OperationError> {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);

        if self.attribute_equality(attr, value) {
            Ok(())
        } else {
            Err(OperationError::ModifyAssertionFailed)
        }
    }

    /// Remove an attribute-value pair from this entry. If the ava doesn't exist, we
    /// don't do anything else since we are asserting the absence of a value.
    pub(crate) fn remove_ava(&mut self, attr: Attribute, value: &PartialValue) {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);

        let rm = if let Some(vs) = self.attrs.get_mut(attr.as_ref()) {
            vs.remove(value, &self.valid.cid);
            vs.is_empty()
        } else {
            false
        };
        if rm {
            self.attrs.remove(attr.as_ref());
        };
    }

    pub(crate) fn remove_avas(&mut self, attr: Attribute, values: &BTreeSet<PartialValue>) {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);

        let rm = if let Some(vs) = self.attrs.get_mut(attr.as_ref()) {
            values.iter().for_each(|k| {
                vs.remove(k, &self.valid.cid);
            });
            vs.is_empty()
        } else {
            false
        };
        if rm {
            self.attrs.remove(attr.as_ref());
        };
    }

    /// Remove all values of this attribute from the entry. If it doesn't exist, this
    /// asserts that no content of that attribute exist.
    pub(crate) fn purge_ava(&mut self, attr: Attribute) {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);
        // self.valid.eclog.purge_ava(&self.valid.cid, attr);

        let can_remove = self
            .attrs
            .get_mut(attr.as_ref())
            .map(|vs| vs.purge(&self.valid.cid))
            // Default to false since a missing attr can't be removed!
            .unwrap_or_default();
        if can_remove {
            self.attrs.remove(attr.as_ref());
        }
    }

    /// Remove this value set from the entry, returning the value set at the time of removal.
    pub fn pop_ava(&mut self, attr: Attribute) -> Option<ValueSet> {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);

        let mut vs = self.attrs.remove(attr.as_ref())?;
        if vs.purge(&self.valid.cid) {
            // Can return as is.
            Some(vs)
        } else {
            // This type may need special handling. Clone and reinsert.
            let r_vs = vs.clone();
            self.attrs.insert(attr.into(), vs);
            Some(r_vs)
        }
    }

    /// Unlike pop or purge, this does NOT respect the attributes purge settings, meaning
    /// that this can break replication by force clearing the state of an attribute. It's
    /// useful for things like "session" to test the grace window by removing the revoked
    /// sessions from the value set that you otherwise, could not.
    #[cfg(test)]
    pub(crate) fn force_trim_ava(&mut self, attr: Attribute) -> Option<ValueSet> {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);
        self.attrs.remove(attr.as_ref())
    }

    /// Replace the content of this attribute with the values from this
    /// iterator. If the iterator is empty, the attribute is purged.
    pub fn set_ava<T>(&mut self, attr: Attribute, iter: T)
    where
        T: Clone + IntoIterator<Item = Value>,
    {
        self.purge_ava(attr);
        self.set_ava_iter_int(attr, iter)
    }

    /// Replace the content of this attribute with a new value set. Effectively this is
    /// a a "purge and set".
    pub fn set_ava_set(&mut self, attr: Attribute, vs: ValueSet) {
        self.purge_ava(attr);
        if let Some(existing_vs) = self.attrs.get_mut(attr.as_ref()) {
            let _ = existing_vs.merge(&vs);
        } else {
            self.attrs.insert(attr.into(), vs);
        }
    }

    /// Apply the content of this modlist to this entry, enforcing the expressed state.
    pub fn apply_modlist(
        &mut self,
        modlist: &ModifyList<ModifyValid>,
    ) -> Result<(), OperationError> {
        for modify in modlist {
            match modify {
                Modify::Present(attr, value) => {
                    self.add_ava(Attribute::try_from(attr)?, value.clone());
                }
                Modify::Removed(attr, value) => {
                    self.remove_ava(Attribute::try_from(attr)?, value);
                }
                Modify::Purged(attr) => {
                    self.purge_ava(Attribute::try_from(attr)?);
                }
                Modify::Assert(attr, value) => {
                    self.assert_ava(attr.to_owned(), value).map_err(|e| {
                        error!("Modification assertion was not met. {} {:?}", attr, value);
                        e
                    })?;
                }
            }
        }
        Ok(())
    }
}

impl<VALID, STATE> PartialEq for Entry<VALID, STATE> {
    fn eq(&self, rhs: &Entry<VALID, STATE>) -> bool {
        // This may look naive - but it is correct. This is because
        // all items that end up in an item MUST have passed through
        // schema validation and normalisation so we can assume that
        // all rules were applied correctly. Thus we can just simply
        // do a char-compare like this.
        //
        // Of course, this is only true on the "Valid" types ... the others
        // are not guaranteed to support this ... but more likely that will
        // just end in eager false-results. We'll never say something is true
        // that should NOT be.
        compare_attrs(&self.attrs, &rhs.attrs)
    }
}

impl From<&SchemaAttribute> for Entry<EntryInit, EntryNew> {
    fn from(s: &SchemaAttribute) -> Self {
        // Convert an Attribute to an entry ... make it good!
        let uuid_v = vs_uuid![s.uuid];
        let name_v = vs_iutf8![s.name.as_str()];
        let desc_v = vs_utf8![s.description.to_owned()];

        let multivalue_v = vs_bool![s.multivalue];
        let sync_allowed_v = vs_bool![s.sync_allowed];
        let replicated_v = vs_bool![s.replicated];
        let phantom_v = vs_bool![s.phantom];
        let unique_v = vs_bool![s.unique];

        let index_v = ValueSetIndex::from_iter(s.index.iter().copied());

        let syntax_v = vs_syntax![s.syntax];

        // Build the Map of the attributes relevant
        // let mut attrs: Map<AttrString, Set<Value>> = Map::with_capacity(8);
        let mut attrs: Map<AttrString, ValueSet> = Map::new();
        attrs.insert(Attribute::AttributeName.into(), name_v);
        attrs.insert(Attribute::Description.into(), desc_v);
        attrs.insert(Attribute::Uuid.into(), uuid_v);
        attrs.insert(Attribute::MultiValue.into(), multivalue_v);
        attrs.insert(Attribute::Phantom.into(), phantom_v);
        attrs.insert(Attribute::SyncAllowed.into(), sync_allowed_v);
        attrs.insert(Attribute::Replicated.into(), replicated_v);
        attrs.insert(Attribute::Unique.into(), unique_v);
        if let Some(vs) = index_v {
            attrs.insert(Attribute::Index.into(), vs);
        }
        attrs.insert(Attribute::Syntax.into(), syntax_v);
        attrs.insert(
            Attribute::Class.into(),
            vs_iutf8![
                EntryClass::Object.into(),
                EntryClass::System.into(),
                EntryClass::AttributeType.into()
            ],
        );

        // Insert stuff.

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

impl From<&SchemaClass> for Entry<EntryInit, EntryNew> {
    fn from(s: &SchemaClass) -> Self {
        let uuid_v = vs_uuid![s.uuid];
        let name_v = vs_iutf8![s.name.as_str()];
        let desc_v = vs_utf8![s.description.to_owned()];
        let sync_allowed_v = vs_bool![s.sync_allowed];

        // let mut attrs: Map<AttrString, Set<Value>> = Map::with_capacity(8);
        let mut attrs: Map<AttrString, ValueSet> = Map::new();
        attrs.insert(Attribute::ClassName.into(), name_v);
        attrs.insert(Attribute::Description.into(), desc_v);
        attrs.insert(Attribute::SyncAllowed.into(), sync_allowed_v);
        attrs.insert(Attribute::Uuid.into(), uuid_v);
        attrs.insert(
            Attribute::Class.into(),
            vs_iutf8![
                EntryClass::Object.into(),
                EntryClass::System.into(),
                EntryClass::ClassType.into()
            ],
        );

        let vs_systemmay = ValueSetIutf8::from_iter(s.systemmay.iter().map(|sm| sm.as_str()));
        if let Some(vs) = vs_systemmay {
            attrs.insert(Attribute::SystemMay.into(), vs);
        }

        let vs_systemmust = ValueSetIutf8::from_iter(s.systemmust.iter().map(|sm| sm.as_str()));

        if let Some(vs) = vs_systemmust {
            attrs.insert(Attribute::SystemMust.into(), vs);
        }

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::collections::BTreeSet as Set;

    use hashbrown::HashMap;

    use crate::be::{IdxKey, IdxSlope};
    use crate::entry::{Entry, EntryInit, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::value::{IndexType, PartialValue, Value};

    #[test]
    fn test_entry_basic() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava(Attribute::UserId, Value::from("william"));
    }

    #[test]
    fn test_entry_dup_value() {
        // Schema doesn't matter here because we are duplicating a value
        // it should fail!

        // We still probably need schema here anyway to validate what we
        // are adding ... Or do we validate after the changes are made in
        // total?
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId.into(), Value::from("william"));
        e.add_ava(Attribute::UserId.into(), Value::from("william"));

        let values = e.get_ava_set(Attribute::UserId).expect("Failed to get ava");
        // Should only be one value!
        assert_eq!(values.len(), 1)
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId.into(), Value::from("william"));

        assert!(e.attribute_pres(Attribute::UserId));
        assert!(!e.attribute_pres(Attribute::Name));
    }

    #[test]
    fn test_entry_equality() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava(Attribute::UserId.into(), Value::from("william"));

        assert!(e.attribute_equality(
            Attribute::UserId.into(),
            &PartialValue::new_utf8s("william")
        ));
        assert!(!e.attribute_equality(Attribute::UserId, &PartialValue::new_utf8s("test")));
        assert!(!e.attribute_equality(
            Attribute::NonExist.into(),
            &PartialValue::new_utf8s("william")
        ));
        // Also test non-matching attr syntax
        assert!(!e.attribute_equality(
            Attribute::UserId.into(),
            &PartialValue::new_iutf8("william")
        ));
    }

    #[test]
    fn test_entry_substring() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava(Attribute::UserId.into(), Value::from("william"));

        assert!(e.attribute_substring(
            Attribute::UserId.into(),
            &PartialValue::new_utf8s("william")
        ));
        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("will")));
        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("liam")));
        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("wl")));

        assert!(e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("will")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("liam")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("wl")));

        assert!(e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("liam")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("will")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("wl")));
    }

    #[test]
    fn test_entry_lessthan() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();

        let pv2 = PartialValue::new_uint32(2);
        let pv8 = PartialValue::new_uint32(8);
        let pv10 = PartialValue::new_uint32(10);
        let pv15 = PartialValue::new_uint32(15);

        e1.add_ava(Attribute::TestAttr, Value::new_uint32(10));

        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv2));
        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv8));
        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv10));
        assert!(e1.attribute_lessthan(Attribute::TestAttr, &pv15));

        e1.add_ava(Attribute::TestAttr, Value::new_uint32(8));

        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv2));
        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv8));
        assert!(e1.attribute_lessthan(Attribute::TestAttr, &pv10));
        assert!(e1.attribute_lessthan(Attribute::TestAttr, &pv15));
    }

    #[test]
    fn test_entry_apply_modlist() {
        // Test application of changes to an entry.
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new().into_invalid_new();

        e.add_ava(Attribute::UserId.into(), Value::from("william"));

        let present_single_mods = ModifyList::new_valid_list(vec![Modify::Present(
            Attribute::Attr.into(),
            Value::new_iutf8("value"),
        )]);

        assert!(e.apply_modlist(&present_single_mods).is_ok());

        // Assert the changes are there
        assert!(e.attribute_equality(
            Attribute::UserId.into(),
            &PartialValue::new_utf8s("william")
        ));
        assert!(e.attribute_equality(Attribute::Attr, &PartialValue::new_iutf8("value")));

        // Assert present for multivalue
        let present_multivalue_mods = ModifyList::new_valid_list(vec![
            Modify::Present(Attribute::Class.into(), Value::new_iutf8("test")),
            Modify::Present(Attribute::Class.into(), Value::new_iutf8("multi_test")),
        ]);

        assert!(e.apply_modlist(&present_multivalue_mods).is_ok());

        assert!(e.attribute_equality(Attribute::Class, &PartialValue::new_iutf8("test")));
        assert!(e.attribute_equality(
            Attribute::Class.into(),
            &PartialValue::new_iutf8("multi_test")
        ));

        // Assert purge on single/multi/empty value
        let purge_single_mods =
            ModifyList::new_valid_list(vec![Modify::Purged(Attribute::Attr.into())]);

        assert!(e.apply_modlist(&purge_single_mods).is_ok());

        assert!(!e.attribute_pres(Attribute::Attr));

        let purge_multi_mods =
            ModifyList::new_valid_list(vec![Modify::Purged(Attribute::Class.into())]);

        assert!(e.apply_modlist(&purge_multi_mods).is_ok());

        assert!(!e.attribute_pres(Attribute::Class));

        let purge_empty_mods = purge_single_mods;

        assert!(e.apply_modlist(&purge_empty_mods).is_ok());

        // Assert removed on value that exists and doesn't exist
        let remove_mods = ModifyList::new_valid_list(vec![Modify::Removed(
            Attribute::Attr.into(),
            PartialValue::new_iutf8("value"),
        )]);

        assert!(e.apply_modlist(&present_single_mods).is_ok());
        assert!(e.attribute_equality(Attribute::Attr, &PartialValue::new_iutf8("value")));
        assert!(e.apply_modlist(&remove_mods).is_ok());
        assert!(e.attrs.get(Attribute::Attr.as_ref()).is_none());

        let remove_empty_mods = remove_mods;

        assert!(e.apply_modlist(&remove_empty_mods).is_ok());

        assert!(e.attrs.get(Attribute::Attr.as_ref()).is_none());
    }

    #[test]
    fn test_entry_idx_diff() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(Attribute::UserId, Value::from("william"));
        let mut e1_mod = e1.clone();
        e1_mod.add_ava(Attribute::Extra.into(), Value::from("test"));

        let e1 = e1.into_sealed_committed();
        let e1_mod = e1_mod.into_sealed_committed();

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(Attribute::UserId, Value::from("claire"));
        let e2 = e2.into_sealed_committed();

        let mut idxmeta = HashMap::with_capacity(8);
        idxmeta.insert(
            IdxKey {
                attr: Attribute::UserId.into(),
                itype: IndexType::Equality,
            },
            IdxSlope::MAX,
        );
        idxmeta.insert(
            IdxKey {
                attr: Attribute::UserId.into(),
                itype: IndexType::Presence,
            },
            IdxSlope::MAX,
        );
        idxmeta.insert(
            IdxKey {
                attr: Attribute::Extra.into(),
                itype: IndexType::Equality,
            },
            IdxSlope::MAX,
        );

        // When we do None, None, we get nothing back.
        let r1 = Entry::idx_diff(&idxmeta, None, None);
        eprintln!("{r1:?}");
        assert!(r1 == Vec::new());

        // Check generating a delete diff
        let mut del_r = Entry::idx_diff(&idxmeta, Some(&e1), None);
        del_r.sort_unstable();
        eprintln!("del_r {del_r:?}");
        assert!(
            del_r[0]
                == Err((
                    &Attribute::UserId.into(),
                    IndexType::Equality,
                    "william".to_string()
                ))
        );
        assert!(
            del_r[1]
                == Err((
                    &Attribute::UserId.into(),
                    IndexType::Presence,
                    "_".to_string()
                ))
        );

        // Check generating an add diff
        let mut add_r = Entry::idx_diff(&idxmeta, None, Some(&e1));
        add_r.sort_unstable();
        eprintln!("{add_r:?}");
        assert!(
            add_r[0]
                == Ok((
                    &Attribute::UserId.into(),
                    IndexType::Equality,
                    "william".to_string()
                ))
        );
        assert!(
            add_r[1]
                == Ok((
                    &Attribute::UserId.into(),
                    IndexType::Presence,
                    "_".to_string()
                ))
        );

        // Check the mod cases now

        // Check no changes
        let no_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1));
        assert!(no_r.is_empty());

        // Check "adding" an attribute.
        let add_a_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1_mod));
        assert!(
            add_a_r[0]
                == Ok((
                    &Attribute::Extra.into(),
                    IndexType::Equality,
                    "test".to_string()
                ))
        );

        // Check "removing" an attribute.
        let del_a_r = Entry::idx_diff(&idxmeta, Some(&e1_mod), Some(&e1));
        assert!(
            del_a_r[0]
                == Err((
                    &Attribute::Extra.into(),
                    IndexType::Equality,
                    "test".to_string()
                ))
        );

        // Change an attribute.
        let mut chg_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e2));
        chg_r.sort_unstable();
        eprintln!("{chg_r:?}");
        assert!(
            chg_r[1]
                == Err((
                    &Attribute::UserId.into(),
                    IndexType::Equality,
                    "william".to_string()
                ))
        );

        assert!(
            chg_r[0]
                == Ok((
                    &Attribute::UserId.into(),
                    IndexType::Equality,
                    "claire".to_string()
                ))
        );
    }

    #[test]
    fn test_entry_mask_recycled_ts() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(Attribute::Class, EntryClass::Person.to_value());
        let e1 = e1.into_sealed_committed();
        assert!(e1.mask_recycled_ts().is_some());

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(Attribute::Class, EntryClass::Person.to_value());
        e2.add_ava(Attribute::Class, EntryClass::Recycled.into());
        let e2 = e2.into_sealed_committed();
        assert!(e2.mask_recycled_ts().is_none());

        let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
        e3.add_ava(Attribute::Class, EntryClass::Tombstone.into());
        let e3 = e3.into_sealed_committed();
        assert!(e3.mask_recycled_ts().is_none());
    }

    #[test]
    fn test_entry_idx_name2uuid_diff() {
        // none, none,
        let r = Entry::idx_name2uuid_diff(None, None);
        assert!(r == (None, None));

        // none, some - test adding an entry gives back add sets
        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::Class, EntryClass::Person.to_value());
            let e = e.into_sealed_committed();

            assert!(Entry::idx_name2uuid_diff(None, Some(&e)) == (Some(Set::new()), None));
        }

        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e.add_ava(Attribute::GidNumber, Value::new_uint32(1300));
            e.add_ava(Attribute::Name, Value::new_iname("testperson"));
            e.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            e.add_ava(
                Attribute::Uuid,
                Value::Uuid(uuid!("9fec0398-c46c-4df4-9df5-b0016f7d563f")),
            );
            let e = e.into_sealed_committed();

            // Note the uuid isn't present!
            assert!(
                Entry::idx_name2uuid_diff(None, Some(&e))
                    == (
                        Some(btreeset![
                            "1300".to_string(),
                            "testperson".to_string(),
                            "testperson@example.com".to_string()
                        ]),
                        None
                    )
            );
            // some, none,
            // Check delete, swap the order of args
            assert!(
                Entry::idx_name2uuid_diff(Some(&e), None)
                    == (
                        None,
                        Some(btreeset![
                            "1300".to_string(),
                            "testperson".to_string(),
                            "testperson@example.com".to_string()
                        ])
                    )
            );

            // some, some (same), should be empty changes.
            assert!(
                Entry::idx_name2uuid_diff(Some(&e), Some(&e))
                    == (Some(Set::new()), Some(Set::new()))
            );
        }
        // some, some (diff)

        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e1.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            let e1 = e1.into_sealed_committed();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e2.add_ava(Attribute::Name, Value::new_iname("testperson"));
            e2.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            let e2 = e2.into_sealed_committed();

            // One attr added
            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (Some(btreeset!["testperson".to_string()]), Some(Set::new()))
            );

            // One removed
            assert!(
                Entry::idx_name2uuid_diff(Some(&e2), Some(&e1))
                    == (Some(Set::new()), Some(btreeset!["testperson".to_string()]))
            );
        }

        // Value changed, remove old, add new.
        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e1.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            let e1 = e1.into_sealed_committed();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e2.add_ava(
                Attribute::Spn,
                Value::new_spn_str("renameperson", "example.com"),
            );
            let e2 = e2.into_sealed_committed();

            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (
                        Some(btreeset!["renameperson@example.com".to_string()]),
                        Some(btreeset!["testperson@example.com".to_string()])
                    )
            );
        }
    }

    #[test]
    fn test_entry_idx_uuid2spn_diff() {
        assert!(Entry::idx_uuid2spn_diff(None, None).is_none());

        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(
            Attribute::Spn,
            Value::new_spn_str("testperson", "example.com"),
        );
        let e1 = e1.into_sealed_committed();

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(
            Attribute::Spn,
            Value::new_spn_str("renameperson", "example.com"),
        );
        let e2 = e2.into_sealed_committed();

        assert!(
            Entry::idx_uuid2spn_diff(None, Some(&e1))
                == Some(Ok(Value::new_spn_str("testperson", "example.com")))
        );
        assert!(Entry::idx_uuid2spn_diff(Some(&e1), None) == Some(Err(())));
        assert!(Entry::idx_uuid2spn_diff(Some(&e1), Some(&e1)).is_none());
        assert!(
            Entry::idx_uuid2spn_diff(Some(&e1), Some(&e2))
                == Some(Ok(Value::new_spn_str("renameperson", "example.com")))
        );
    }

    #[test]
    fn test_entry_idx_uuid2rdn_diff() {
        assert!(Entry::idx_uuid2rdn_diff(None, None).is_none());

        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(
            Attribute::Spn,
            Value::new_spn_str("testperson", "example.com"),
        );
        let e1 = e1.into_sealed_committed();

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(
            Attribute::Spn,
            Value::new_spn_str("renameperson", "example.com"),
        );
        let e2 = e2.into_sealed_committed();

        assert!(
            Entry::idx_uuid2rdn_diff(None, Some(&e1))
                == Some(Ok("spn=testperson@example.com".to_string()))
        );
        assert!(Entry::idx_uuid2rdn_diff(Some(&e1), None) == Some(Err(())));
        assert!(Entry::idx_uuid2rdn_diff(Some(&e1), Some(&e1)).is_none());
        assert!(
            Entry::idx_uuid2rdn_diff(Some(&e1), Some(&e2))
                == Some(Ok("spn=renameperson@example.com".to_string()))
        );
    }
}

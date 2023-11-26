//! [`Filter`]s are one of the three foundational concepts of the design in kanidm.
//! They are used in nearly every aspect of the server to provide searching of
//! datasets and assertion of entry properties.
//!
//! A filter is a logical statement of properties that an [`Entry`] and its
//! AVAs must uphold to be considered true.
//!
//! [`Filter`]: struct.Filter.html
//! [`Entry`]: ../entry/struct.Entry.html

use std::cmp::{Ordering, PartialOrd};
use std::collections::BTreeSet;
use std::fmt;
use std::hash::Hash;
use std::iter;
use std::num::NonZeroU8;

use concread::arcache::ARCacheReadTxn;
use hashbrown::HashMap;
#[cfg(test)]
use hashbrown::HashSet;
use kanidm_proto::constants::ATTR_UUID;
use kanidm_proto::v1::{Filter as ProtoFilter, OperationError, SchemaError};
use ldap3_proto::proto::{LdapFilter, LdapSubstringFilter};
// use smartstring::alias::String as AttrString;
use serde::Deserialize;
use uuid::Uuid;

use crate::be::{IdxKey, IdxKeyRef, IdxKeyToRef, IdxMeta, IdxSlope};
use crate::idm::ldap::ldap_attr_filter_map;
use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::value::{IndexType, PartialValue};

const FILTER_DEPTH_MAX: usize = 16;

// Default filter is safe, ignores all hidden types!

// This is &Value so we can lazy const then clone, but perhaps we can reconsider
// later if this should just take Value.
pub fn f_eq<'a>(a: Attribute, v: PartialValue) -> FC<'a> {
    FC::Eq(a.into(), v)
}

pub fn f_sub<'a>(a: Attribute, v: PartialValue) -> FC<'a> {
    FC::Cnt(a.into(), v)
}

pub fn f_pres<'a>(a: Attribute) -> FC<'a> {
    FC::Pres(a.into())
}

pub fn f_lt<'a>(a: Attribute, v: PartialValue) -> FC<'a> {
    FC::LessThan(a.into(), v)
}

pub fn f_or(vs: Vec<FC>) -> FC {
    FC::Or(vs)
}

pub fn f_and(vs: Vec<FC>) -> FC {
    FC::And(vs)
}

pub fn f_inc(vs: Vec<FC>) -> FC {
    FC::Inclusion(vs)
}

pub fn f_andnot(fc: FC) -> FC {
    FC::AndNot(Box::new(fc))
}

pub fn f_self<'a>() -> FC<'a> {
    FC::SelfUuid
}

pub fn f_id(uuid: &str) -> FC<'static> {
    let uf = Uuid::parse_str(uuid)
        .ok()
        .map(|u| FC::Eq(Attribute::Uuid.as_ref(), PartialValue::Uuid(u)));
    let spnf = PartialValue::new_spn_s(uuid).map(|spn| FC::Eq(Attribute::Spn.as_ref(), spn));
    let nf = FC::Eq(Attribute::Name.as_ref(), PartialValue::new_iname(uuid));
    let f: Vec<_> = iter::once(uf)
        .chain(iter::once(spnf))
        .flatten()
        .chain(iter::once(nf))
        .collect();
    FC::Or(f)
}

pub fn f_spn_name(id: &str) -> FC<'static> {
    let spnf = PartialValue::new_spn_s(id).map(|spn| FC::Eq(Attribute::Spn.as_ref(), spn));
    let nf = FC::Eq(Attribute::Name.as_ref(), PartialValue::new_iname(id));
    let f: Vec<_> = iter::once(spnf).flatten().chain(iter::once(nf)).collect();
    FC::Or(f)
}

/// This is the short-form for tests and internal filters that can then
/// be transformed into a filter for the server to use.
#[derive(Clone, Debug, Deserialize)]
pub enum FC<'a> {
    Eq(&'a str, PartialValue),
    Cnt(&'a str, PartialValue),
    Pres(&'a str),
    LessThan(&'a str, PartialValue),
    Or(Vec<FC<'a>>),
    And(Vec<FC<'a>>),
    Inclusion(Vec<FC<'a>>),
    AndNot(Box<FC<'a>>),
    SelfUuid,
    // Not(Box<FC>),
}

/// This is the filters internal representation
#[derive(Clone, Hash, PartialEq, PartialOrd, Ord, Eq)]
enum FilterComp {
    // This is attr - value
    Eq(AttrString, PartialValue),
    Cnt(AttrString, PartialValue),
    Stw(AttrString, PartialValue),
    Enw(AttrString, PartialValue),
    Pres(AttrString),
    LessThan(AttrString, PartialValue),
    Or(Vec<FilterComp>),
    And(Vec<FilterComp>),
    Inclusion(Vec<FilterComp>),
    AndNot(Box<FilterComp>),
    SelfUuid,
    // Does this mean we can add a true not to the type now?
    // Not(Box<FilterComp>),
}

impl fmt::Debug for FilterComp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterComp::Eq(attr, pv) => {
                write!(f, "{} eq {:?}", attr, pv)
            }
            FilterComp::Cnt(attr, pv) => {
                write!(f, "{} cnt {:?}", attr, pv)
            }
            FilterComp::Stw(attr, pv) => {
                write!(f, "{} stw {:?}", attr, pv)
            }
            FilterComp::Enw(attr, pv) => {
                write!(f, "{} enw {:?}", attr, pv)
            }
            FilterComp::Pres(attr) => {
                write!(f, "{} pres", attr)
            }
            FilterComp::LessThan(attr, pv) => {
                write!(f, "{} lt {:?}", attr, pv)
            }
            FilterComp::And(list) => {
                write!(f, "(")?;
                for (i, fc) in list.iter().enumerate() {
                    write!(f, "{:?}", fc)?;
                    if i != list.len() - 1 {
                        write!(f, " and ")?;
                    }
                }
                write!(f, ")")
            }
            FilterComp::Or(list) => {
                write!(f, "(")?;
                for (i, fc) in list.iter().enumerate() {
                    write!(f, "{:?}", fc)?;
                    if i != list.len() - 1 {
                        write!(f, " or ")?;
                    }
                }
                write!(f, ")")
            }
            FilterComp::Inclusion(list) => {
                write!(f, "(")?;
                for (i, fc) in list.iter().enumerate() {
                    write!(f, "{:?}", fc)?;
                    if i != list.len() - 1 {
                        write!(f, " inc ")?;
                    }
                }
                write!(f, ")")
            }
            FilterComp::AndNot(inner) => {
                write!(f, "not ( {:?} )", inner)
            }
            FilterComp::SelfUuid => {
                write!(f, "uuid eq self")
            }
        }
    }
}

/// This is the fully resolved internal representation. Note the lack of Not and selfUUID
/// because these are resolved into And(Pres(class), AndNot(term)) and Eq(uuid, ...).
/// Importantly, we make this accessible to Entry so that it can then match on filters
/// internally.
///
/// Each filter that has been resolved also has been enriched with metadata about its
/// index, and index slope. For the purpose of this module, consider slope as a "weight"
/// where small value - faster index, larger value - slower index. This metadata is extremely
/// important for the query optimiser to make decisions about how to re-arrange queries
/// correctly.
#[derive(Clone, Eq)]
pub enum FilterResolved {
    // This is attr - value - indexed slope factor
    Eq(AttrString, PartialValue, Option<NonZeroU8>),
    Cnt(AttrString, PartialValue, Option<NonZeroU8>),
    Stw(AttrString, PartialValue, Option<NonZeroU8>),
    Enw(AttrString, PartialValue, Option<NonZeroU8>),
    Pres(AttrString, Option<NonZeroU8>),
    LessThan(AttrString, PartialValue, Option<NonZeroU8>),
    Or(Vec<FilterResolved>, Option<NonZeroU8>),
    And(Vec<FilterResolved>, Option<NonZeroU8>),
    // All terms must have 1 or more items, or the inclusion is false!
    Inclusion(Vec<FilterResolved>, Option<NonZeroU8>),
    AndNot(Box<FilterResolved>, Option<NonZeroU8>),
}

impl fmt::Debug for FilterResolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterResolved::Eq(attr, pv, idx) => {
                write!(
                    f,
                    "(s{} {} eq {:?})",
                    idx.unwrap_or(NonZeroU8::MAX),
                    attr,
                    pv
                )
            }
            FilterResolved::Cnt(attr, pv, idx) => {
                write!(
                    f,
                    "(s{} {} cnt {:?})",
                    idx.unwrap_or(NonZeroU8::MAX),
                    attr,
                    pv
                )
            }
            FilterResolved::Stw(attr, pv, idx) => {
                write!(
                    f,
                    "(s{} {} stw {:?})",
                    idx.unwrap_or(NonZeroU8::MAX),
                    attr,
                    pv
                )
            }
            FilterResolved::Enw(attr, pv, idx) => {
                write!(
                    f,
                    "(s{} {} enw {:?})",
                    idx.unwrap_or(NonZeroU8::MAX),
                    attr,
                    pv
                )
            }
            FilterResolved::Pres(attr, idx) => {
                write!(f, "(s{} {} pres)", idx.unwrap_or(NonZeroU8::MAX), attr)
            }
            FilterResolved::LessThan(attr, pv, idx) => {
                write!(
                    f,
                    "(s{} {} lt {:?})",
                    idx.unwrap_or(NonZeroU8::MAX),
                    attr,
                    pv
                )
            }
            FilterResolved::And(list, idx) => {
                write!(f, "(s{} ", idx.unwrap_or(NonZeroU8::MAX))?;
                for (i, fc) in list.iter().enumerate() {
                    write!(f, "{:?}", fc)?;
                    if i != list.len() - 1 {
                        write!(f, " and ")?;
                    }
                }
                write!(f, ")")
            }
            FilterResolved::Or(list, idx) => {
                write!(f, "(s{} ", idx.unwrap_or(NonZeroU8::MAX))?;
                for (i, fc) in list.iter().enumerate() {
                    write!(f, "{:?}", fc)?;
                    if i != list.len() - 1 {
                        write!(f, " or ")?;
                    }
                }
                write!(f, ")")
            }
            FilterResolved::Inclusion(list, idx) => {
                write!(f, "(s{} ", idx.unwrap_or(NonZeroU8::MAX))?;
                for (i, fc) in list.iter().enumerate() {
                    write!(f, "{:?}", fc)?;
                    if i != list.len() - 1 {
                        write!(f, " inc ")?;
                    }
                }
                write!(f, ")")
            }
            FilterResolved::AndNot(inner, idx) => {
                write!(f, "not (s{} {:?})", idx.unwrap_or(NonZeroU8::MAX), inner)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A filter before it's gone through schema validation
pub struct FilterInvalid {
    inner: FilterComp,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
/// A filter after it's gone through schema validation
pub struct FilterValid {
    inner: FilterComp,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FilterValidResolved {
    inner: FilterResolved,
}

#[derive(Debug)]
pub enum FilterPlan {
    Invalid,
    EqIndexed(AttrString, String),
    EqUnindexed(AttrString),
    EqCorrupt(AttrString),
    SubIndexed(AttrString, String),
    SubUnindexed(AttrString),
    SubCorrupt(AttrString),
    PresIndexed(AttrString),
    PresUnindexed(AttrString),
    PresCorrupt(AttrString),
    LessThanUnindexed(AttrString),
    OrUnindexed(Vec<FilterPlan>),
    OrIndexed(Vec<FilterPlan>),
    OrPartial(Vec<FilterPlan>),
    OrPartialThreshold(Vec<FilterPlan>),
    AndEmptyCand(Vec<FilterPlan>),
    AndIndexed(Vec<FilterPlan>),
    AndUnindexed(Vec<FilterPlan>),
    AndPartial(Vec<FilterPlan>),
    AndPartialThreshold(Vec<FilterPlan>),
    AndNot(Box<FilterPlan>),
    InclusionInvalid(Vec<FilterPlan>),
    InclusionIndexed(Vec<FilterPlan>),
}

/// A `Filter` is a logical set of assertions about the state of an [`Entry`] and
/// it's avas. `Filter`s are built from a set of possible assertions.
///
/// * `Pres`ence. An ava of that attribute's name exists, with any value on the [`Entry`].
/// * `Eq`uality. An ava of the attribute exists and contains this matching value.
/// * `Sub`string. An ava of the attribute exists and has a substring containing the requested value.
/// * `Or`. Contains multiple filters and asserts at least one is true.
/// * `And`. Contains multiple filters and asserts all of them are true.
/// * `AndNot`. This is different to a "logical not" operation. This asserts that a condition is not
/// true in the current candidate set. A search of `AndNot` alone will yield not results, but an
/// `AndNot` in an `And` query will assert that a condition can not hold.
///
/// `Filter`s for security reasons are validated by the schema to assert all requested attributes
/// are valid and exist in the schema so that they can have their indexes correctly used. This avoids
/// a denial of service attack that may lead to full-table scans.
///
/// This `Filter` validation state is in the `STATE` attribute and will be either `FilterInvalid`
/// or `FilterValid`. The `Filter` must be checked by the schema to move to `FilterValid`. This
/// helps to prevent errors at compile time to assert `Filters` are secuerly. checked
///
/// [`Entry`]: ../entry/struct.Entry.html
#[derive(Clone, Hash, Ord, Eq, PartialOrd, PartialEq)]
pub struct Filter<STATE> {
    state: STATE,
}

impl fmt::Debug for Filter<FilterValidResolved> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Filter(Valid) {:?}", self.state.inner)
    }
}

impl fmt::Debug for Filter<FilterValid> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Filter(Valid) {:?}", self.state.inner)
    }
}

impl fmt::Debug for Filter<FilterInvalid> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Filter(Invalid) {:?}", self.state.inner)
    }
}

impl Filter<FilterValidResolved> {
    // Does this need mut self? Aren't we returning
    // a new copied filter?

    #[cfg(test)]
    fn optimise(&self) -> Self {
        // Apply optimisations to the filter
        // An easy way would be imple partialOrd
        // then do sort on the or/and/not
        // as the general conditions we want
        // to optimise on are in those ...
        //
        // The other big one is folding redundant
        // terms down.
        //
        // If an or/not/and condition has no items, remove it
        //
        // If its the root item?

        Filter {
            state: FilterValidResolved {
                inner: self.state.inner.optimise(),
            },
        }
    }

    // It's not possible to invalid a resolved filter, because we don't know
    // what the origin of the Self or Not keywords were.
    //
    // Saying this, we have entry -> filter_from_attrs. Should that return
    // a valid or validResolved? If it does valid resolved we need invalidate
    // so we can down cast and then re-validate and re-resolve ...

    // Allow the entry crate to read the internals of the filter.
    // more likely, we should move entry matching HERE ...
    pub fn to_inner(&self) -> &FilterResolved {
        &self.state.inner
    }
}

impl Filter<FilterValid> {
    pub fn invalidate(self) -> Filter<FilterInvalid> {
        // Just move the state.
        Filter {
            state: FilterInvalid {
                inner: self.state.inner,
            },
        }
    }

    pub fn resolve(
        &self,
        ev: &Identity,
        idxmeta: Option<&IdxMeta>,
        mut rsv_cache: Option<
            &mut ARCacheReadTxn<
                '_,
                (IdentityId, Filter<FilterValid>),
                Filter<FilterValidResolved>,
                (),
            >,
        >,
    ) -> Result<Filter<FilterValidResolved>, OperationError> {
        // Given a filter, resolve Not and SelfUuid to real terms.
        //
        // The benefit of moving optimisation to this step is from various inputs, we can
        // get to a resolved + optimised filter, and then we can cache those outputs in many
        // cases!

        // do we have a cache?
        let cache_key = if let Some(rcache) = rsv_cache.as_mut() {
            // construct the key. For now it's expensive because we have to clone, but ... eh.
            let cache_key = (ev.get_event_origin_id(), self.clone());
            if let Some(f) = rcache.get(&cache_key) {
                // Got it? Shortcut and return!
                return Ok(f.clone());
            };
            // Not in cache? Set the cache_key.
            Some(cache_key)
        } else {
            None
        };

        // If we got here, nothing in cache - resolve it the hard way.

        let resolved_filt = Filter {
            state: FilterValidResolved {
                inner: match idxmeta {
                    Some(idx) => {
                        FilterResolved::resolve_idx(self.state.inner.clone(), ev, &idx.idxkeys)
                    }
                    None => FilterResolved::resolve_no_idx(self.state.inner.clone(), ev),
                }
                .map(|f| {
                    match idxmeta {
                        // Do a proper optimise if we have idxmeta.
                        Some(_) => f.optimise(),
                        // Only do this if we don't have idxmeta.
                        None => f.fast_optimise(),
                    }
                })
                .ok_or(OperationError::FilterUuidResolution)?,
            },
        };

        // Now it's computed, inject it.
        if let Some(rcache) = rsv_cache.as_mut() {
            if let Some(cache_key) = cache_key {
                rcache.insert(cache_key, resolved_filt.clone());
            }
        }

        Ok(resolved_filt)
    }

    pub fn get_attr_set(&self) -> BTreeSet<&str> {
        // Recurse through the filter getting an attribute set.
        let mut r_set = BTreeSet::new();
        self.state.inner.get_attr_set(&mut r_set);
        r_set
    }

    /*
     * CORRECTNESS: This is a transform on the "immutable" filtervalid type.
     * We know this is correct because internally we can assert that the hidden
     * and recycled types *must* be valid.
     */

    pub fn into_ignore_hidden(self) -> Self {
        // Destructure the former filter, and surround it with an ignore_hidden.
        Filter {
            state: FilterValid {
                inner: FilterComp::new_ignore_hidden(self.state.inner),
            },
        }
    }

    pub fn into_recycled(self) -> Self {
        // Destructure the former filter and surround it with a recycled only query
        Filter {
            state: FilterValid {
                inner: FilterComp::new_recycled(self.state.inner),
            },
        }
    }
}

impl Filter<FilterInvalid> {
    pub fn new(inner: FC) -> Self {
        let fc = FilterComp::new(inner);
        Filter {
            state: FilterInvalid { inner: fc },
        }
    }

    pub fn new_ignore_hidden(inner: FC) -> Self {
        let fc = FilterComp::new(inner);
        Filter {
            state: FilterInvalid {
                inner: FilterComp::new_ignore_hidden(fc),
            },
        }
    }

    pub fn new_recycled(inner: FC) -> Self {
        // Create a filter that searches recycled items only.
        let fc = FilterComp::new(inner);
        Filter {
            state: FilterInvalid {
                inner: FilterComp::new_recycled(fc),
            },
        }
    }

    pub fn join_parts_and(a: Self, b: Self) -> Self {
        // I regret this function so much, but then again ...
        Filter {
            state: FilterInvalid {
                inner: FilterComp::And(vec![a.state.inner, b.state.inner]),
            },
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_resolved(self) -> Filter<FilterValidResolved> {
        // There is a good reason this function only exists in tests ...
        //
        // YOLO.
        // tl;dr - panic if there is a Self term because we don't have the QS
        // to resolve the uuid. Perhaps in the future we can provide a uuid
        // to this for the resolving to make it safer and test case usable.

        // First we make a fake idx meta, which is meant to be "just enough" to make
        // some core test idxs faster. This is never used in production, it's JUST for
        // test case speedups.
        let idxmeta = vec![
            (Attribute::Uuid.into(), IndexType::Equality),
            (Attribute::Uuid.into(), IndexType::Presence),
            (Attribute::Name.into(), IndexType::Equality),
            (Attribute::Name.into(), IndexType::SubString),
            (Attribute::Name.into(), IndexType::Presence),
            (Attribute::Class.into(), IndexType::Equality),
            (Attribute::Class.into(), IndexType::Presence),
            (Attribute::Member.into(), IndexType::Equality),
            (Attribute::Member.into(), IndexType::Presence),
            (Attribute::MemberOf.into(), IndexType::Equality),
            (Attribute::MemberOf.into(), IndexType::Presence),
            (Attribute::DirectMemberOf.into(), IndexType::Equality),
            (Attribute::DirectMemberOf.into(), IndexType::Presence),
        ];

        let idxmeta_ref = idxmeta.iter().map(|(attr, itype)| (attr, itype)).collect();

        Filter {
            state: FilterValidResolved {
                inner: FilterResolved::from_invalid(self.state.inner, &idxmeta_ref),
            },
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid(self) -> Filter<FilterValid> {
        // There is a good reason this function only exists in tests ...
        //
        // YOLO.
        // tl;dr - blindly accept that this filter and it's ava's MUST have
        // been normalised and exist in schema. If they don't things may subtely
        // break, fail, or explode. As subtle as an explosion can be.
        Filter {
            state: FilterValid {
                inner: self.state.inner,
            },
        }
    }

    /// ⚠️  - Blindly accept a filter from a string, panicking if it fails to parse.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn from_str(fc: &str) -> Self {
        let f: FC = serde_json::from_str(fc).expect("Failure parsing filter!");
        Filter {
            state: FilterInvalid {
                inner: FilterComp::new(f),
            },
        }
    }

    pub fn validate(
        &self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Filter<FilterValid>, SchemaError> {
        // TODO: Add a schema validation cache that can return pre-validated filters.

        Ok(Filter {
            state: FilterValid {
                inner: self.state.inner.validate(schema)?,
            },
        })
    }

    // This has to have two versions to account for ro/rw traits, because RS can't
    // monomorphise on the trait to call clone_value. An option is to make a fn that
    // takes "clone_value(t, a, v) instead, but that may have a similar issue.
    #[instrument(name = "filter::from_ro", level = "debug", skip_all)]
    pub fn from_ro(
        ev: &Identity,
        f: &ProtoFilter,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let depth = FILTER_DEPTH_MAX;
        let mut elems = ev.limits.filter_max_elements;
        Ok(Filter {
            state: FilterInvalid {
                inner: FilterComp::from_ro(f, qs, depth, &mut elems)?,
            },
        })
    }

    #[instrument(name = "filter::from_rw", level = "debug", skip_all)]
    pub fn from_rw(
        ev: &Identity,
        f: &ProtoFilter,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let depth = FILTER_DEPTH_MAX;
        let mut elems = ev.limits.filter_max_elements;
        Ok(Filter {
            state: FilterInvalid {
                inner: FilterComp::from_rw(f, qs, depth, &mut elems)?,
            },
        })
    }

    #[instrument(name = "filter::from_ldap_ro", level = "debug", skip_all)]
    pub fn from_ldap_ro(
        ev: &Identity,
        f: &LdapFilter,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let depth = FILTER_DEPTH_MAX;
        let mut elems = ev.limits.filter_max_elements;
        Ok(Filter {
            state: FilterInvalid {
                inner: FilterComp::from_ldap_ro(f, qs, depth, &mut elems)?,
            },
        })
    }
}

impl FilterComp {
    fn new(fc: FC) -> Self {
        match fc {
            FC::Eq(a, v) => FilterComp::Eq(AttrString::from(a), v),
            FC::Cnt(a, v) => FilterComp::Cnt(AttrString::from(a), v),
            FC::Pres(a) => FilterComp::Pres(AttrString::from(a)),
            FC::LessThan(a, v) => FilterComp::LessThan(AttrString::from(a), v),
            FC::Or(v) => FilterComp::Or(v.into_iter().map(FilterComp::new).collect()),
            FC::And(v) => FilterComp::And(v.into_iter().map(FilterComp::new).collect()),
            FC::Inclusion(v) => FilterComp::Inclusion(v.into_iter().map(FilterComp::new).collect()),
            FC::AndNot(b) => FilterComp::AndNot(Box::new(FilterComp::new(*b))),
            FC::SelfUuid => FilterComp::SelfUuid,
        }
    }

    fn new_ignore_hidden(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::AndNot(Box::new(FilterComp::Or(vec![
                FilterComp::Eq(Attribute::Class.into(), EntryClass::Tombstone.into()),
                FilterComp::Eq(Attribute::Class.into(), EntryClass::Recycled.into()),
            ]))),
            fc,
        ])
    }

    fn new_recycled(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::Eq(Attribute::Class.into(), EntryClass::Recycled.into()),
            fc,
        ])
    }

    fn get_attr_set<'a>(&'a self, r_set: &mut BTreeSet<&'a str>) {
        match self {
            FilterComp::Eq(attr, _)
            | FilterComp::Cnt(attr, _)
            | FilterComp::Stw(attr, _)
            | FilterComp::Enw(attr, _)
            | FilterComp::Pres(attr)
            | FilterComp::LessThan(attr, _) => {
                r_set.insert(attr.as_str());
            }
            FilterComp::Or(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::And(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::Inclusion(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::AndNot(f) => f.get_attr_set(r_set),
            FilterComp::SelfUuid => {
                r_set.insert(ATTR_UUID);
            }
        }
    }

    fn validate(&self, schema: &dyn SchemaTransaction) -> Result<FilterComp, SchemaError> {
        // Optimisation is done at another stage.

        // This probably needs some rework

        // Getting this each recursion could be slow. Maybe
        // we need an inner function that passes the reference?
        let schema_attributes = schema.get_attributes();
        // We used to check the attr_name by normalising it (lowercasing)
        // but should we? I think we actually should just call a special
        // handler on schema to fix it up.

        match self {
            FilterComp::Eq(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(attr_norm.as_str(), value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Eq(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Cnt(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(attr_norm.as_str(), value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Cnt(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Stw(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(attr_norm.as_str(), value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Stw(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Enw(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(attr_norm.as_str(), value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Enw(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Pres(attr) => {
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(_attr_name) => {
                        // Return our valid data
                        Ok(FilterComp::Pres(attr_norm))
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::LessThan(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(attr_norm.as_str(), value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::LessThan(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Or(filters) => {
                // * If all filters are okay, return Ok(Filter::Or())
                // * Any filter is invalid, return the error.
                // * An empty "or" is a valid filter in mathematical terms, but we throw an
                //   error to warn the user because it's super unlikely they want that
                if filters.is_empty() {
                    return Err(SchemaError::EmptyFilter);
                };
                let x: Result<Vec<_>, _> = filters
                    .iter()
                    .map(|filter| filter.validate(schema))
                    .collect();
                // Now put the valid filters into the Filter
                x.map(FilterComp::Or)
            }
            FilterComp::And(filters) => {
                // * If all filters are okay, return Ok(Filter::Or())
                // * Any filter is invalid, return the error.
                // * An empty "and" is a valid filter in mathematical terms, but we throw an
                //   error to warn the user because it's super unlikely they want that
                if filters.is_empty() {
                    return Err(SchemaError::EmptyFilter);
                };
                let x: Result<Vec<_>, _> = filters
                    .iter()
                    .map(|filter| filter.validate(schema))
                    .collect();
                // Now put the valid filters into the Filter
                x.map(FilterComp::And)
            }
            FilterComp::Inclusion(filters) => {
                if filters.is_empty() {
                    return Err(SchemaError::EmptyFilter);
                };
                let x: Result<Vec<_>, _> = filters
                    .iter()
                    .map(|filter| filter.validate(schema))
                    .collect();
                // Now put the valid filters into the Filter
                x.map(FilterComp::Inclusion)
            }
            FilterComp::AndNot(filter) => {
                // Just validate the inner
                filter
                    .validate(schema)
                    .map(|r_filter| FilterComp::AndNot(Box::new(r_filter)))
            }
            FilterComp::SelfUuid => {
                // Pretty hard to mess this one up ;)
                Ok(FilterComp::SelfUuid)
            }
        }
    }

    fn from_ro(
        f: &ProtoFilter,
        qs: &mut QueryServerReadTransaction,
        depth: usize,
        elems: &mut usize,
    ) -> Result<Self, OperationError> {
        let ndepth = depth.checked_sub(1).ok_or(OperationError::ResourceLimit)?;
        Ok(match f {
            ProtoFilter::Eq(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(nk.as_str(), v)?;
                FilterComp::Eq(nk, v)
            }
            ProtoFilter::Cnt(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(nk.as_str(), v)?;
                FilterComp::Cnt(nk, v)
            }
            ProtoFilter::Pres(a) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                FilterComp::Pres(nk)
            }
            ProtoFilter::Or(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::Or(
                    l.iter()
                        .map(|f| Self::from_ro(f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::And(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::And(
                    l.iter()
                        .map(|f| Self::from_ro(f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::AndNot(l) => {
                *elems = (*elems)
                    .checked_sub(1)
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::AndNot(Box::new(Self::from_ro(l, qs, ndepth, elems)?))
            }
            ProtoFilter::SelfUuid => FilterComp::SelfUuid,
        })
    }

    fn from_rw(
        f: &ProtoFilter,
        qs: &mut QueryServerWriteTransaction,
        depth: usize,
        elems: &mut usize,
    ) -> Result<Self, OperationError> {
        let ndepth = depth.checked_sub(1).ok_or(OperationError::ResourceLimit)?;
        Ok(match f {
            ProtoFilter::Eq(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(nk.as_str(), v)?;
                FilterComp::Eq(nk, v)
            }
            ProtoFilter::Cnt(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(nk.as_str(), v)?;
                FilterComp::Cnt(nk, v)
            }
            ProtoFilter::Pres(a) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                FilterComp::Pres(nk)
            }
            ProtoFilter::Or(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::Or(
                    l.iter()
                        .map(|f| Self::from_rw(f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::And(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::And(
                    l.iter()
                        .map(|f| Self::from_rw(f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::AndNot(l) => {
                *elems = (*elems)
                    .checked_sub(1)
                    .ok_or(OperationError::ResourceLimit)?;

                FilterComp::AndNot(Box::new(Self::from_rw(l, qs, ndepth, elems)?))
            }
            ProtoFilter::SelfUuid => FilterComp::SelfUuid,
        })
    }

    fn from_ldap_ro(
        f: &LdapFilter,
        qs: &mut QueryServerReadTransaction,
        depth: usize,
        elems: &mut usize,
    ) -> Result<Self, OperationError> {
        let ndepth = depth.checked_sub(1).ok_or(OperationError::ResourceLimit)?;
        Ok(match f {
            LdapFilter::And(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::And(
                    l.iter()
                        .map(|f| Self::from_ldap_ro(f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            LdapFilter::Or(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;

                FilterComp::Or(
                    l.iter()
                        .map(|f| Self::from_ldap_ro(f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            LdapFilter::Not(l) => {
                *elems = (*elems)
                    .checked_sub(1)
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::AndNot(Box::new(Self::from_ldap_ro(l, qs, ndepth, elems)?))
            }
            LdapFilter::Equality(a, v) => {
                let a = ldap_attr_filter_map(a);
                let v = qs.clone_partialvalue(a.as_str(), v)?;
                FilterComp::Eq(a, v)
            }
            LdapFilter::Present(a) => FilterComp::Pres(ldap_attr_filter_map(a)),
            LdapFilter::Substring(
                a,
                LdapSubstringFilter {
                    initial,
                    any,
                    final_,
                },
            ) => {
                let a = ldap_attr_filter_map(a);

                let mut terms = Vec::with_capacity(any.len() + 2);
                if let Some(ini) = initial {
                    let v = qs.clone_partialvalue(a.as_str(), ini)?;
                    terms.push(FilterComp::Stw(a.clone(), v));
                }

                for term in any.iter() {
                    let v = qs.clone_partialvalue(a.as_str(), term)?;
                    terms.push(FilterComp::Cnt(a.clone(), v));
                }

                if let Some(fin) = final_ {
                    let v = qs.clone_partialvalue(a.as_str(), fin)?;
                    terms.push(FilterComp::Enw(a.clone(), v));
                }

                FilterComp::And(terms)
            }
            LdapFilter::GreaterOrEqual(_, _) => {
                admin_error!("Unsupported filter operation - greater or equal");
                return Err(OperationError::FilterGeneration);
            }
            LdapFilter::LessOrEqual(_, _) => {
                admin_error!("Unsupported filter operation - less or equal");
                return Err(OperationError::FilterGeneration);
            }
            LdapFilter::Approx(_, _) => {
                admin_error!("Unsupported filter operation - approximate");
                return Err(OperationError::FilterGeneration);
            }
            LdapFilter::Extensible(_) => {
                admin_error!("Unsupported filter operation - extensible");
                return Err(OperationError::FilterGeneration);
            }
        })
    }
}

/* We only configure partial eq if cfg test on the invalid/valid types */
/*
impl PartialEq for Filter<FilterInvalid> {
    fn eq(&self, rhs: &Filter<FilterInvalid>) -> bool {
        self.state.inner == rhs.state.inner
    }
}

impl PartialEq for Filter<FilterValid> {
    fn eq(&self, rhs: &Filter<FilterValid>) -> bool {
        self.state.inner == rhs.state.inner
    }
}

impl PartialEq for Filter<FilterValidResolved> {
    fn eq(&self, rhs: &Filter<FilterValidResolved>) -> bool {
        self.state.inner == rhs.state.inner
    }
}
*/

/*
 * Only needed in tests, in run time order only matters on the inner for
 * optimisation.
 */
#[cfg(test)]
impl PartialOrd for Filter<FilterValidResolved> {
    fn partial_cmp(&self, rhs: &Filter<FilterValidResolved>) -> Option<Ordering> {
        self.state.inner.partial_cmp(&rhs.state.inner)
    }
}

impl PartialEq for FilterResolved {
    fn eq(&self, rhs: &FilterResolved) -> bool {
        match (self, rhs) {
            (FilterResolved::Eq(a1, v1, _), FilterResolved::Eq(a2, v2, _)) => a1 == a2 && v1 == v2,
            (FilterResolved::Cnt(a1, v1, _), FilterResolved::Cnt(a2, v2, _)) => {
                a1 == a2 && v1 == v2
            }
            (FilterResolved::Pres(a1, _), FilterResolved::Pres(a2, _)) => a1 == a2,
            (FilterResolved::LessThan(a1, v1, _), FilterResolved::LessThan(a2, v2, _)) => {
                a1 == a2 && v1 == v2
            }
            (FilterResolved::And(vs1, _), FilterResolved::And(vs2, _)) => vs1 == vs2,
            (FilterResolved::Or(vs1, _), FilterResolved::Or(vs2, _)) => vs1 == vs2,
            (FilterResolved::Inclusion(vs1, _), FilterResolved::Inclusion(vs2, _)) => vs1 == vs2,
            (FilterResolved::AndNot(f1, _), FilterResolved::AndNot(f2, _)) => f1 == f2,
            (_, _) => false,
        }
    }
}

impl PartialOrd for FilterResolved {
    fn partial_cmp(&self, rhs: &FilterResolved) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Ord for FilterResolved {
    /// Ordering of filters for optimisation and subsequent dead term elimination.
    fn cmp(&self, rhs: &FilterResolved) -> Ordering {
        let left_slopey = self.get_slopeyness_factor();
        let right_slopey = rhs.get_slopeyness_factor();

        let r = match (left_slopey, right_slopey) {
            (Some(sfl), Some(sfr)) => sfl.cmp(&sfr),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };

        // If they are equal, compare other elements for determining the order. This is what
        // allows dead term elimination to occur.
        //
        // In almost all cases, we'll miss this step though as slopes will vary distinctly.
        //
        // We do NOT need to check for indexed vs unindexed here, we already did it in the slope check!
        if r == Ordering::Equal {
            match (self, rhs) {
                (FilterResolved::Eq(a1, v1, _), FilterResolved::Eq(a2, v2, _))
                | (FilterResolved::Cnt(a1, v1, _), FilterResolved::Cnt(a2, v2, _))
                | (FilterResolved::LessThan(a1, v1, _), FilterResolved::LessThan(a2, v2, _)) => {
                    match a1.cmp(a2) {
                        Ordering::Equal => v1.cmp(v2),
                        o => o,
                    }
                }
                (FilterResolved::Pres(a1, _), FilterResolved::Pres(a2, _)) => a1.cmp(a2),
                // Now sort these into the generally "best" order.
                (FilterResolved::Eq(_, _, _), _) => Ordering::Less,
                (_, FilterResolved::Eq(_, _, _)) => Ordering::Greater,
                (FilterResolved::Pres(_, _), _) => Ordering::Less,
                (_, FilterResolved::Pres(_, _)) => Ordering::Greater,
                (FilterResolved::LessThan(_, _, _), _) => Ordering::Less,
                (_, FilterResolved::LessThan(_, _, _)) => Ordering::Greater,
                (FilterResolved::Cnt(_, _, _), _) => Ordering::Less,
                (_, FilterResolved::Cnt(_, _, _)) => Ordering::Greater,
                // They can't be re-arranged, they don't move!
                (_, _) => Ordering::Equal,
            }
        } else {
            r
        }
    }
}

impl FilterResolved {
    /// ⚠️  - Process a filter without verifying with schema.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    fn from_invalid(fc: FilterComp, idxmeta: &HashSet<(&AttrString, &IndexType)>) -> Self {
        match fc {
            FilterComp::Eq(a, v) => {
                let idx = idxmeta.contains(&(&a, &IndexType::Equality));
                let idx = NonZeroU8::new(idx as u8);
                FilterResolved::Eq(a, v, idx)
            }
            FilterComp::SelfUuid => panic!("Not possible to resolve SelfUuid in from_invalid!"),
            FilterComp::Cnt(a, v) => {
                // TODO: For now, don't emit substring indexes.
                // let idx = idxmeta.contains(&(&a, &IndexType::SubString));
                // let idx = NonZeroU8::new(idx as u8);
                FilterResolved::Cnt(a, v, None)
            }
            FilterComp::Stw(a, v) => FilterResolved::Stw(a, v, None),
            FilterComp::Enw(a, v) => FilterResolved::Enw(a, v, None),
            FilterComp::Pres(a) => {
                let idx = idxmeta.contains(&(&a, &IndexType::Presence));
                FilterResolved::Pres(a, NonZeroU8::new(idx as u8))
            }
            FilterComp::LessThan(a, v) => {
                // let idx = idxmeta.contains(&(&a, &IndexType::ORDERING));
                // TODO: For now, don't emit ordering indexes.
                FilterResolved::LessThan(a, v, None)
            }
            FilterComp::Or(vs) => FilterResolved::Or(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v, idxmeta))
                    .collect(),
                None,
            ),
            FilterComp::And(vs) => FilterResolved::And(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v, idxmeta))
                    .collect(),
                None,
            ),
            FilterComp::Inclusion(vs) => FilterResolved::Inclusion(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v, idxmeta))
                    .collect(),
                None,
            ),
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::AndNot(
                    Box::new(FilterResolved::from_invalid((*f).clone(), idxmeta)),
                    None,
                )
            }
        }
    }

    fn resolve_idx(
        fc: FilterComp,
        ev: &Identity,
        idxmeta: &HashMap<IdxKey, IdxSlope>,
    ) -> Option<Self> {
        match fc {
            FilterComp::Eq(a, v) => {
                let idxkref = IdxKeyRef::new(&a, &IndexType::Equality);
                let idx = idxmeta
                    .get(&idxkref as &dyn IdxKeyToRef)
                    .copied()
                    .and_then(NonZeroU8::new);
                Some(FilterResolved::Eq(a, v, idx))
            }
            FilterComp::SelfUuid => ev.get_uuid().map(|uuid| {
                let idxkref = IdxKeyRef::new(Attribute::Uuid.as_ref(), &IndexType::Equality);
                let idx = idxmeta
                    .get(&idxkref as &dyn IdxKeyToRef)
                    .copied()
                    .and_then(NonZeroU8::new);
                FilterResolved::Eq(Attribute::Uuid.into(), PartialValue::Uuid(uuid), idx)
            }),
            FilterComp::Cnt(a, v) => {
                let idxkref = IdxKeyRef::new(&a, &IndexType::SubString);
                let idx = idxmeta
                    .get(&idxkref as &dyn IdxKeyToRef)
                    .copied()
                    .and_then(NonZeroU8::new);
                Some(FilterResolved::Cnt(a, v, idx))
            }
            FilterComp::Stw(a, v) => {
                /*
                let idxkref = IdxKeyRef::new(&a, &IndexType::SubString);
                let idx = idxmeta
                    .get(&idxkref as &dyn IdxKeyToRef)
                    .copied()
                    .and_then(NonZeroU8::new);
                Some(FilterResolved::Stw(a, v, idx))
                */
                Some(FilterResolved::Stw(a, v, None))
            }
            FilterComp::Enw(a, v) => {
                /*
                let idxkref = IdxKeyRef::new(&a, &IndexType::SubString);
                let idx = idxmeta
                    .get(&idxkref as &dyn IdxKeyToRef)
                    .copied()
                    .and_then(NonZeroU8::new);
                Some(FilterResolved::Enw(a, v, idx))
                */
                Some(FilterResolved::Enw(a, v, None))
            }
            FilterComp::Pres(a) => {
                let idxkref = IdxKeyRef::new(&a, &IndexType::Presence);
                let idx = idxmeta
                    .get(&idxkref as &dyn IdxKeyToRef)
                    .copied()
                    .and_then(NonZeroU8::new);
                Some(FilterResolved::Pres(a, idx))
            }
            FilterComp::LessThan(a, v) => {
                // let idx = idxmeta.contains(&(&a, &IndexType::SubString));
                Some(FilterResolved::LessThan(a, v, None))
            }
            // We set the compound filters slope factor to "None" here, because when we do
            // optimise we'll actually fill in the correct slope factors after we sort those
            // inner terms in a more optimal way.
            FilterComp::Or(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_idx(f, ev, idxmeta))
                    .collect();
                fi.map(|fi| FilterResolved::Or(fi, None))
            }
            FilterComp::And(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_idx(f, ev, idxmeta))
                    .collect();
                fi.map(|fi| FilterResolved::And(fi, None))
            }
            FilterComp::Inclusion(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_idx(f, ev, idxmeta))
                    .collect();
                fi.map(|fi| FilterResolved::Inclusion(fi, None))
            }
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::resolve_idx((*f).clone(), ev, idxmeta)
                    .map(|fi| FilterResolved::AndNot(Box::new(fi), None))
            }
        }
    }

    fn resolve_no_idx(fc: FilterComp, ev: &Identity) -> Option<Self> {
        // ⚠️  ⚠️  ⚠️  ⚠️
        // Remember, this function means we have NO INDEX METADATA so we can only
        // assign slopes to values we can GUARANTEE will EXIST.
        match fc {
            FilterComp::Eq(a, v) => {
                // Since we have no index data, we manually configure a reasonable
                // slope and indicate the presence of some expected basic
                // indexes.
                let idx = matches!(a.as_str(), ATTR_NAME | ATTR_UUID);
                let idx = NonZeroU8::new(idx as u8);
                Some(FilterResolved::Eq(a, v, idx))
            }
            FilterComp::SelfUuid => ev.get_uuid().map(|uuid| {
                FilterResolved::Eq(
                    Attribute::Uuid.into(),
                    PartialValue::Uuid(uuid),
                    NonZeroU8::new(true as u8),
                )
            }),
            FilterComp::Cnt(a, v) => Some(FilterResolved::Cnt(a, v, None)),
            FilterComp::Stw(a, v) => Some(FilterResolved::Stw(a, v, None)),
            FilterComp::Enw(a, v) => Some(FilterResolved::Enw(a, v, None)),
            FilterComp::Pres(a) => Some(FilterResolved::Pres(a, None)),
            FilterComp::LessThan(a, v) => Some(FilterResolved::LessThan(a, v, None)),
            FilterComp::Or(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_no_idx(f, ev))
                    .collect();
                fi.map(|fi| FilterResolved::Or(fi, None))
            }
            FilterComp::And(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_no_idx(f, ev))
                    .collect();
                fi.map(|fi| FilterResolved::And(fi, None))
            }
            FilterComp::Inclusion(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_no_idx(f, ev))
                    .collect();
                fi.map(|fi| FilterResolved::Inclusion(fi, None))
            }
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::resolve_no_idx((*f).clone(), ev)
                    .map(|fi| FilterResolved::AndNot(Box::new(fi), None))
            }
        }
    }

    // This is an optimise that only attempts to optimise the outer terms.
    fn fast_optimise(self) -> Self {
        match self {
            FilterResolved::Inclusion(mut f_list, _) => {
                f_list.sort_unstable();
                f_list.dedup();
                let sf = f_list.last().and_then(|f| f.get_slopeyness_factor());
                FilterResolved::Inclusion(f_list, sf)
            }
            FilterResolved::And(mut f_list, _) => {
                f_list.sort_unstable();
                f_list.dedup();
                let sf = f_list.first().and_then(|f| f.get_slopeyness_factor());
                FilterResolved::And(f_list, sf)
            }
            v => v,
        }
    }

    fn optimise(&self) -> Self {
        // Most optimisations only matter around or/and terms.
        match self {
            FilterResolved::Inclusion(f_list, _) => {
                // first, optimise all our inner elements
                let (f_list_inc, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    .map(|f_ref| f_ref.optimise())
                    .partition(|f| matches!(f, FilterResolved::Inclusion(_, _)));

                f_list_inc.into_iter().for_each(|fc| {
                    if let FilterResolved::Inclusion(mut l, _) = fc {
                        f_list_new.append(&mut l)
                    }
                });
                // finally, optimise this list by sorting.
                f_list_new.sort_unstable();
                f_list_new.dedup();
                // Inclusions are similar to or, so what's our worst case?
                let sf = f_list_new.last().and_then(|f| f.get_slopeyness_factor());
                FilterResolved::Inclusion(f_list_new, sf)
            }
            FilterResolved::And(f_list, _) => {
                // first, optimise all our inner elements
                let (f_list_and, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    .map(|f_ref| f_ref.optimise())
                    .partition(|f| matches!(f, FilterResolved::And(_, _)));

                // now, iterate over this list - for each "and" term, fold
                // it's elements to this level.
                // This is one of the most important improvements because it means
                // that we can compare terms such that:
                //
                // (&(class=*)(&(uid=foo)))
                // if we did not and fold, this would remain as is. However, by and
                // folding, we can optimise to:
                // (&(uid=foo)(class=*))
                // Which will be faster when indexed as the uid=foo will trigger
                // shortcutting

                f_list_and.into_iter().for_each(|fc| {
                    if let FilterResolved::And(mut l, _) = fc {
                        f_list_new.append(&mut l)
                    }
                });

                // If the f_list_and only has one element, pop it and return.
                if f_list_new.len() == 1 {
                    f_list_new.remove(0)
                } else {
                    // finally, optimise this list by sorting.
                    f_list_new.sort_unstable();
                    f_list_new.dedup();
                    // Which ever element as the head is first must be the min SF
                    // so we use this in our And to represent the "best possible" value
                    // of how indexes will perform.
                    let sf = f_list_new.first().and_then(|f| f.get_slopeyness_factor());
                    //
                    // return!
                    FilterResolved::And(f_list_new, sf)
                }
            }
            FilterResolved::Or(f_list, _) => {
                let (f_list_or, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    // Optimise all inner items.
                    .map(|f_ref| f_ref.optimise())
                    // Split out inner-or terms to fold into this term.
                    .partition(|f| matches!(f, FilterResolved::Or(_, _)));

                // Append the inner terms.
                f_list_or.into_iter().for_each(|fc| {
                    if let FilterResolved::Or(mut l, _) = fc {
                        f_list_new.append(&mut l)
                    }
                });

                // If the f_list_or only has one element, pop it and return.
                if f_list_new.len() == 1 {
                    f_list_new.remove(0)
                } else {
                    // sort, but reverse so that sub-optimal elements are earlier
                    // to promote fast-failure.
                    // We have to allow this on clippy, which attempts to suggest:
                    //   f_list_new.sort_unstable_by_key(|&b| Reverse(b))
                    // However, because these are references, it causes a lifetime
                    // issue, and fails to compile.
                    #[allow(clippy::unnecessary_sort_by)]
                    f_list_new.sort_unstable_by(|a, b| b.cmp(a));
                    f_list_new.dedup();
                    // The *last* element is the most here, and our worst case factor.
                    let sf = f_list_new.last().and_then(|f| f.get_slopeyness_factor());
                    FilterResolved::Or(f_list_new, sf)
                }
            }
            f => f.clone(),
        }
    }

    pub fn is_andnot(&self) -> bool {
        matches!(self, FilterResolved::AndNot(_, _))
    }

    #[inline(always)]
    fn get_slopeyness_factor(&self) -> Option<NonZeroU8> {
        match self {
            FilterResolved::Eq(_, _, sf)
            | FilterResolved::Cnt(_, _, sf)
            | FilterResolved::Stw(_, _, sf)
            | FilterResolved::Enw(_, _, sf)
            | FilterResolved::Pres(_, sf)
            | FilterResolved::LessThan(_, _, sf)
            | FilterResolved::Or(_, sf)
            | FilterResolved::And(_, sf)
            | FilterResolved::Inclusion(_, sf)
            | FilterResolved::AndNot(_, sf) => *sf,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::{Ordering, PartialOrd};
    use std::collections::BTreeSet;
    use std::time::Duration;

    use kanidm_proto::v1::Filter as ProtoFilter;
    use ldap3_proto::simple::LdapFilter;

    use crate::event::{CreateEvent, DeleteEvent};
    use crate::filter::{Filter, FilterInvalid, FILTER_DEPTH_MAX};
    use crate::prelude::*;

    #[test]
    fn test_filter_simple() {
        // Test construction.
        let _filt: Filter<FilterInvalid> = filter!(f_eq(Attribute::Class, EntryClass::User.into()));

        // AFTER
        let _complex_filt: Filter<FilterInvalid> = filter!(f_and!([
            f_or!([
                f_eq(Attribute::UserId, PartialValue::new_iutf8("test_a")),
                f_eq(Attribute::UserId, PartialValue::new_iutf8("test_b")),
            ]),
            f_sub(Attribute::Class, EntryClass::User.into()),
        ]));
    }

    macro_rules! filter_optimise_assert {
        (
            $init:expr,
            $expect:expr
        ) => {{
            #[allow(unused_imports)]
            use crate::filter::{f_and, f_andnot, f_eq, f_or, f_pres, f_sub};
            use crate::filter::{Filter, FilterInvalid};
            let f_init: Filter<FilterInvalid> = Filter::new($init);
            let f_expect: Filter<FilterInvalid> = Filter::new($expect);
            // Create a resolved filter, via the most unsafe means possible!
            let f_init_r = f_init.into_valid_resolved();
            let f_init_o = f_init_r.optimise();
            let f_init_e = f_expect.into_valid_resolved();
            debug!("--");
            debug!("init   --> {:?}", f_init_r);
            debug!("opt    --> {:?}", f_init_o);
            debug!("expect --> {:?}", f_init_e);
            assert!(f_init_o == f_init_e);
        }};
    }

    #[test]
    fn test_filter_optimise() {
        sketching::test_init();
        // Given sets of "optimisable" filters, optimise them.
        filter_optimise_assert!(
            f_and(vec![f_and(vec![f_eq(
                Attribute::Class,
                EntryClass::TestClass.into()
            )])]),
            f_eq(Attribute::Class, EntryClass::TestClass.into())
        );

        filter_optimise_assert!(
            f_or(vec![f_or(vec![f_eq(
                Attribute::Class,
                EntryClass::TestClass.into()
            )])]),
            f_eq(Attribute::Class, EntryClass::TestClass.into())
        );

        filter_optimise_assert!(
            f_and(vec![f_or(vec![f_and(vec![f_eq(
                Attribute::Class,
                EntryClass::TestClass.to_partialvalue()
            )])])]),
            f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue())
        );

        // Later this can test duplicate filter detection.
        filter_optimise_assert!(
            f_and(vec![
                f_and(vec![f_eq(
                    Attribute::Class,
                    EntryClass::TestClass.to_partialvalue()
                )]),
                f_sub(Attribute::Class, PartialValue::new_class("te")),
                f_pres(Attribute::Class),
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue())
            ]),
            f_and(vec![
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                f_pres(Attribute::Class),
                f_sub(Attribute::Class, PartialValue::new_class("te")),
            ])
        );

        // Test dedup removes only the correct element despite padding.
        filter_optimise_assert!(
            f_and(vec![
                f_and(vec![
                    f_eq(Attribute::Class, PartialValue::new_class("foo")),
                    f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                    f_eq(Attribute::Uid, PartialValue::new_class("bar")),
                ]),
                f_sub(Attribute::Class, PartialValue::new_class("te")),
                f_pres(Attribute::Class),
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue())
            ]),
            f_and(vec![
                f_eq(Attribute::Class, PartialValue::new_class("foo")),
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                f_pres(Attribute::Class),
                f_eq(Attribute::Uid, PartialValue::new_class("bar")),
                f_sub(Attribute::Class, PartialValue::new_class("te")),
            ])
        );

        filter_optimise_assert!(
            f_or(vec![
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                f_pres(Attribute::Class),
                f_sub(Attribute::Class, PartialValue::new_class("te")),
                f_or(vec![f_eq(
                    Attribute::Class,
                    EntryClass::TestClass.to_partialvalue()
                )]),
            ]),
            f_or(vec![
                f_sub(Attribute::Class, PartialValue::new_class("te")),
                f_pres(Attribute::Class),
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue())
            ])
        );

        // Test dedup doesn't affect nested items incorrectly.
        filter_optimise_assert!(
            f_or(vec![
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                f_and(vec![
                    f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                    f_eq(Attribute::Term, EntryClass::TestClass.to_partialvalue()),
                    f_or(vec![f_eq(
                        Attribute::Class,
                        EntryClass::TestClass.to_partialvalue()
                    )])
                ]),
            ]),
            f_or(vec![
                f_and(vec![
                    f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
                    f_eq(Attribute::Term, EntryClass::TestClass.to_partialvalue())
                ]),
                f_eq(Attribute::Class, EntryClass::TestClass.to_partialvalue()),
            ])
        );
    }

    #[test]
    fn test_filter_eq() {
        let f_t1a = filter!(f_pres(Attribute::UserId));
        let f_t1b = filter!(f_pres(Attribute::UserId));
        let f_t1c = filter!(f_pres(Attribute::NonExist));

        assert!(f_t1a == f_t1b);
        assert!(f_t1a != f_t1c);
        assert!(f_t1b != f_t1c);

        let f_t2a = filter!(f_and!([f_pres(Attribute::UserId)]));
        let f_t2b = filter!(f_and!([f_pres(Attribute::UserId)]));
        let f_t2c = filter!(f_and!([f_pres(Attribute::NonExist)]));
        assert!(f_t2a == f_t2b);
        assert!(f_t2a != f_t2c);
        assert!(f_t2b != f_t2c);

        assert!(f_t2c != f_t1a);
        assert!(f_t2c != f_t1c);
    }

    #[test]
    fn test_filter_ord() {
        // Test that we uphold the rules of partialOrd
        // Basic equality
        // Test the two major paths here (str vs list)
        let f_t1a = filter_resolved!(f_pres(Attribute::UserId));
        let f_t1b = filter_resolved!(f_pres(Attribute::UserId));

        assert_eq!(f_t1a.partial_cmp(&f_t1b), Some(Ordering::Equal));
        assert_eq!(f_t1b.partial_cmp(&f_t1a), Some(Ordering::Equal));

        let f_t2a = filter_resolved!(f_and!([]));
        let f_t2b = filter_resolved!(f_and!([]));
        assert_eq!(f_t2a.partial_cmp(&f_t2b), Some(Ordering::Equal));
        assert_eq!(f_t2b.partial_cmp(&f_t2a), Some(Ordering::Equal));

        // antisymmetry: if a < b then !(a > b), as well as a > b implying !(a < b); and
        // These are unindexed so we have to check them this way.
        let f_t3b = filter_resolved!(f_eq(Attribute::UserId, PartialValue::new_iutf8("")));
        assert_eq!(f_t1a.partial_cmp(&f_t3b), Some(Ordering::Greater));
        assert_eq!(f_t3b.partial_cmp(&f_t1a), Some(Ordering::Less));

        // transitivity: a < b and b < c implies a < c. The same must hold for both == and >.
        let f_t4b = filter_resolved!(f_sub(Attribute::UserId, PartialValue::new_iutf8("")));
        assert_eq!(f_t1a.partial_cmp(&f_t4b), Some(Ordering::Less));
        assert_eq!(f_t3b.partial_cmp(&f_t4b), Some(Ordering::Less));

        assert_eq!(f_t4b.partial_cmp(&f_t1a), Some(Ordering::Greater));
        assert_eq!(f_t4b.partial_cmp(&f_t3b), Some(Ordering::Greater));
    }

    #[test]
    fn test_filter_clone() {
        // Test that cloning filters yields the same result regardless of
        // complexity.
        let f_t1a = filter_resolved!(f_pres(Attribute::UserId));
        let f_t1b = f_t1a.clone();
        let f_t1c = filter_resolved!(f_pres(Attribute::NonExist));

        assert!(f_t1a == f_t1b);
        assert!(f_t1a != f_t1c);

        let f_t2a = filter_resolved!(f_and!([f_pres(Attribute::UserId)]));
        let f_t2b = f_t2a.clone();
        let f_t2c = filter_resolved!(f_and!([f_pres(Attribute::NonExist)]));

        assert!(f_t2a == f_t2b);
        assert!(f_t2a != f_t2c);
    }

    #[test]
    fn test_lessthan_entry_filter() {
        let e = entry_init!(
            (Attribute::UserId, Value::new_iutf8("william")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::GidNumber, Value::Uint32(1000))
        )
        .into_sealed_new();

        let f_t1a = filter_resolved!(f_lt(Attribute::GidNumber, PartialValue::new_uint32(500)));
        assert!(!e.entry_match_no_index(&f_t1a));

        let f_t1b = filter_resolved!(f_lt(Attribute::GidNumber, PartialValue::new_uint32(1000)));
        assert!(!e.entry_match_no_index(&f_t1b));

        let f_t1c = filter_resolved!(f_lt(Attribute::GidNumber, PartialValue::new_uint32(1001)));
        assert!(e.entry_match_no_index(&f_t1c));
    }

    #[test]
    fn test_or_entry_filter() {
        let e = entry_init!(
            (Attribute::UserId, Value::new_iutf8("william")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::GidNumber, Value::Uint32(1000))
        )
        .into_sealed_new();

        let f_t1a = filter_resolved!(f_or!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("william")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1000)),
        ]));
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = filter_resolved!(f_or!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("william")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1000)),
        ]));
        assert!(e.entry_match_no_index(&f_t2a));

        let f_t3a = filter_resolved!(f_or!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("alice")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1000)),
        ]));
        assert!(e.entry_match_no_index(&f_t3a));

        let f_t4a = filter_resolved!(f_or!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("alice")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1001)),
        ]));
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_and_entry_filter() {
        let e = entry_init!(
            (Attribute::UserId, Value::new_iutf8("william")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::GidNumber, Value::Uint32(1000))
        )
        .into_sealed_new();

        let f_t1a = filter_resolved!(f_and!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("william")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1000)),
        ]));
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = filter_resolved!(f_and!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("william")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1001)),
        ]));
        assert!(!e.entry_match_no_index(&f_t2a));

        let f_t3a = filter_resolved!(f_and!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("alice")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1000)),
        ]));
        assert!(!e.entry_match_no_index(&f_t3a));

        let f_t4a = filter_resolved!(f_and!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("alice")),
            f_eq(Attribute::GidNumber, PartialValue::Uint32(1001)),
        ]));
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_not_entry_filter() {
        let e1 = entry_init!(
            (Attribute::UserId, Value::new_iutf8("william")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::GidNumber, Value::Uint32(1000))
        )
        .into_sealed_new();

        let f_t1a = filter_resolved!(f_andnot(f_eq(
            Attribute::UserId,
            PartialValue::new_iutf8("alice")
        )));
        assert!(e1.entry_match_no_index(&f_t1a));

        let f_t2a = filter_resolved!(f_andnot(f_eq(
            Attribute::UserId,
            PartialValue::new_iutf8("william")
        )));
        assert!(!e1.entry_match_no_index(&f_t2a));
    }

    #[test]
    fn test_nested_entry_filter() {
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value().clone()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::GidNumber, Value::Uint32(1000))
        )
        .into_sealed_new();

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value().clone()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("4b6228ab-1dbe-42a4-a9f5-f6368222438e"))
            ),
            (Attribute::GidNumber, Value::Uint32(1001))
        )
        .into_sealed_new();

        let e3 = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("7b23c99d-c06b-4a9a-a958-3afa56383e1d"))
            ),
            (Attribute::GidNumber, Value::Uint32(1002))
        )
        .into_sealed_new();

        let e4 = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("21d816b5-1f6a-4696-b7c1-6ed06d22ed81"))
            ),
            (Attribute::GidNumber, Value::Uint32(1000))
        )
        .into_sealed_new();

        let f_t1a = filter_resolved!(f_and!([
            f_eq(Attribute::Class, EntryClass::Person.into()),
            f_or!([
                f_eq(Attribute::GidNumber, PartialValue::Uint32(1001)),
                f_eq(Attribute::GidNumber, PartialValue::Uint32(1000))
            ])
        ]));

        assert!(e1.entry_match_no_index(&f_t1a));
        assert!(e2.entry_match_no_index(&f_t1a));
        assert!(!e3.entry_match_no_index(&f_t1a));
        assert!(!e4.entry_match_no_index(&f_t1a));
    }

    #[test]
    fn test_attr_set_filter() {
        let mut f_expect = BTreeSet::new();
        f_expect.insert("userid");
        f_expect.insert(Attribute::Class.as_ref());
        // Given filters, get their expected attribute sets - this is used by access control profiles
        // to determine what attrs we are requesting regardless of the partialvalue.
        let f_t1a = filter_valid!(f_and!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("alice")),
            f_eq(Attribute::Class, PartialValue::new_iutf8("1001")),
        ]));

        assert!(f_t1a.get_attr_set() == f_expect);

        let f_t2a = filter_valid!(f_and!([
            f_eq(Attribute::UserId, PartialValue::new_iutf8("alice")),
            f_eq(Attribute::Class, PartialValue::new_iutf8("1001")),
            f_eq(Attribute::UserId, PartialValue::new_iutf8("claire")),
        ]));

        assert!(f_t2a.get_attr_set() == f_expect);
    }

    #[qs_test]
    async fn test_filter_resolve_value(server: &QueryServer) {
        let time_p1 = duration_from_epoch_now();
        let time_p2 = time_p1 + Duration::from_secs(CHANGELOG_MAX_AGE * 2);
        let time_p3 = time_p2 + Duration::from_secs(CHANGELOG_MAX_AGE * 2);

        let mut server_txn = server.write(time_p1).await;

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value().clone()),
            (Attribute::Name, Value::new_iname("testperson2")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("a67c0c71-0b35-4218-a6b0-22d23d131d27"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson2")),
            (Attribute::DisplayName, Value::new_utf8s("testperson2"))
        );

        // We need to add these and then push through the state machine.
        let e_ts = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value().clone()),
            (Attribute::Name, Value::new_iname("testperson3")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("9557f49c-97a5-4277-a9a5-097d17eb8317"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson3")),
            (Attribute::DisplayName, Value::new_utf8s("testperson3"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2, e_ts]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        let de_sin = DeleteEvent::new_internal_invalid(filter!(f_or!([f_eq(
            Attribute::Name,
            PartialValue::new_iname("testperson3")
        )])));
        assert!(server_txn.delete(&de_sin).is_ok());

        // Commit
        assert!(server_txn.commit().is_ok());

        // Now, establish enough time for the recycled items to be purged.
        let mut server_txn = server.write(time_p2).await;
        assert!(server_txn.purge_recycled().is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(time_p3).await;
        assert!(server_txn.purge_tombstones().is_ok());

        // ===== ✅ now ready to test!

        // Resolving most times should yield expected results
        let t1 = vs_utf8!["teststring".to_string()] as _;
        let r1 = server_txn.resolve_valueset(&t1);
        assert!(r1 == Ok(vec!["teststring".to_string()]));

        // Resolve UUID with matching spn
        let t_uuid = vs_refer![uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930")] as _;
        let r_uuid = server_txn.resolve_valueset(&t_uuid);
        debug!("{:?}", r_uuid);
        assert!(r_uuid == Ok(vec!["testperson1@example.com".to_string()]));

        // Resolve UUID with matching name
        let t_uuid = vs_refer![uuid!("a67c0c71-0b35-4218-a6b0-22d23d131d27")] as _;
        let r_uuid = server_txn.resolve_valueset(&t_uuid);
        debug!("{:?}", r_uuid);
        assert!(r_uuid == Ok(vec!["testperson2".to_string()]));

        // Resolve UUID non-exist
        let t_uuid_non = vs_refer![uuid!("b83e98f0-3d2e-41d2-9796-d8d993289c86")] as _;
        let r_uuid_non = server_txn.resolve_valueset(&t_uuid_non);
        debug!("{:?}", r_uuid_non);
        assert!(r_uuid_non == Ok(vec!["b83e98f0-3d2e-41d2-9796-d8d993289c86".to_string()]));

        // Resolve UUID to tombstone/recycled (same an non-exst)
        let t_uuid_ts = vs_refer![uuid!("9557f49c-97a5-4277-a9a5-097d17eb8317")] as _;
        let r_uuid_ts = server_txn.resolve_valueset(&t_uuid_ts);
        debug!("{:?}", r_uuid_ts);
        assert!(r_uuid_ts == Ok(vec!["9557f49c-97a5-4277-a9a5-097d17eb8317".to_string()]));
    }

    #[qs_test]
    async fn test_filter_depth_limits(server: &QueryServer) {
        let mut r_txn = server.read().await;

        let mut inv_proto = ProtoFilter::Pres(Attribute::Class.to_string());
        for _i in 0..(FILTER_DEPTH_MAX + 1) {
            inv_proto = ProtoFilter::And(vec![inv_proto]);
        }

        let mut inv_ldap = LdapFilter::Present(Attribute::Class.to_string());
        for _i in 0..(FILTER_DEPTH_MAX + 1) {
            inv_ldap = LdapFilter::And(vec![inv_ldap]);
        }

        let ev = Identity::from_internal();

        // Test proto + read
        let res = Filter::from_ro(&ev, &inv_proto, &mut r_txn);
        assert!(res == Err(OperationError::ResourceLimit));

        // ldap
        let res = Filter::from_ldap_ro(&ev, &inv_ldap, &mut r_txn);
        assert!(res == Err(OperationError::ResourceLimit));

        // Can only have one db conn at a time.
        std::mem::drop(r_txn);

        // proto + write
        let mut wr_txn = server.write(duration_from_epoch_now()).await;
        let res = Filter::from_rw(&ev, &inv_proto, &mut wr_txn);
        assert!(res == Err(OperationError::ResourceLimit));
    }

    #[qs_test]
    async fn test_filter_max_element_limits(server: &QueryServer) {
        const LIMIT: usize = 4;
        let mut r_txn = server.read().await;

        let inv_proto = ProtoFilter::And(
            (0..(LIMIT * 2))
                .map(|_| ProtoFilter::Pres(Attribute::Class.to_string()))
                .collect(),
        );

        let inv_ldap = LdapFilter::And(
            (0..(LIMIT * 2))
                .map(|_| LdapFilter::Present(Attribute::Class.to_string()))
                .collect(),
        );

        let mut ev = Identity::from_internal();
        ev.limits.filter_max_elements = LIMIT;

        // Test proto + read
        let res = Filter::from_ro(&ev, &inv_proto, &mut r_txn);
        assert!(res == Err(OperationError::ResourceLimit));

        // ldap
        let res = Filter::from_ldap_ro(&ev, &inv_ldap, &mut r_txn);
        assert!(res == Err(OperationError::ResourceLimit));

        // Can only have one db conn at a time.
        std::mem::drop(r_txn);

        // proto + write
        let mut wr_txn = server.write(duration_from_epoch_now()).await;
        let res = Filter::from_rw(&ev, &inv_proto, &mut wr_txn);
        assert!(res == Err(OperationError::ResourceLimit));
    }
}

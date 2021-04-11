//! [`Filter`]s are one of the three foundational concepts of the design in kanidm.
//! They are used in nearly every aspect ofthe server to provide searching of
//! datasets, and assertion of entry properties.
//!
//! A filter is a logical statement of properties that an [`Entry`] and it's
//! avas must uphold to be considered true.
//!
//! [`Filter`]: struct.Filter.html
//! [`Entry`]: ../entry/struct.Entry.html

use crate::audit::AuditScope;
use crate::be::{IdxKey, IdxKeyRef, IdxKeyToRef};
use crate::event::{Event, EventOrigin};
use crate::ldap::ldap_attr_filter_map;
use crate::schema::SchemaTransaction;
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use crate::value::{IndexType, PartialValue};
use hashbrown::HashSet;
use kanidm_proto::v1::Filter as ProtoFilter;
use kanidm_proto::v1::{OperationError, SchemaError};
use ldap3_server::proto::{LdapFilter, LdapSubstringFilter};
// use smartstring::alias::String;
use smartstring::alias::String as AttrString;
use std::cmp::{Ordering, PartialOrd};
use std::collections::BTreeSet;
use std::iter;
use uuid::Uuid;

const FILTER_DEPTH_MAX: usize = 16;

// Default filter is safe, ignores all hidden types!

// This is &Value so we can lazy const then clone, but perhaps we can reconsider
// later if this should just take Value.
#[allow(dead_code)]
pub fn f_eq(a: &str, v: PartialValue) -> FC {
    FC::Eq(a, v)
}

#[allow(dead_code)]
pub fn f_sub(a: &str, v: PartialValue) -> FC {
    FC::Sub(a, v)
}

#[allow(dead_code)]
pub fn f_pres(a: &str) -> FC {
    FC::Pres(a)
}

#[allow(dead_code)]
pub fn f_lt(a: &str, v: PartialValue) -> FC {
    FC::LessThan(a, v)
}

#[allow(dead_code)]
pub fn f_or(vs: Vec<FC>) -> FC {
    FC::Or(vs)
}

#[allow(dead_code)]
pub fn f_and(vs: Vec<FC>) -> FC {
    FC::And(vs)
}

#[allow(dead_code)]
pub fn f_inc(vs: Vec<FC>) -> FC {
    FC::Inclusion(vs)
}

#[allow(dead_code)]
pub fn f_andnot(fc: FC) -> FC {
    FC::AndNot(Box::new(fc))
}

#[allow(dead_code)]
pub fn f_self<'a>() -> FC<'a> {
    FC::SelfUUID
}

#[allow(dead_code)]
pub fn f_id(id: &str) -> FC<'static> {
    let uf = Uuid::parse_str(id)
        .ok()
        .map(|u| FC::Eq("uuid", PartialValue::new_uuid(u)));
    let spnf = PartialValue::new_spn_s(id).map(|spn| FC::Eq("spn", spn));
    let nf = FC::Eq("name", PartialValue::new_iname(id));
    let f: Vec<_> = iter::once(uf)
        .chain(iter::once(spnf))
        .filter_map(|v| v)
        .chain(iter::once(nf))
        .collect();
    FC::Or(f)
}

#[allow(dead_code)]
pub fn f_spn_name(id: &str) -> FC<'static> {
    let spnf = PartialValue::new_spn_s(id).map(|spn| FC::Eq("spn", spn));
    let nf = FC::Eq("name", PartialValue::new_iname(id));
    let f: Vec<_> = iter::once(spnf)
        .filter_map(|v| v)
        .chain(iter::once(nf))
        .collect();
    FC::Or(f)
}

// This is the short-form for tests and internal filters that can then
// be transformed into a filter for the server to use.
#[derive(Debug, Deserialize)]
pub enum FC<'a> {
    Eq(&'a str, PartialValue),
    Sub(&'a str, PartialValue),
    Pres(&'a str),
    LessThan(&'a str, PartialValue),
    Or(Vec<FC<'a>>),
    And(Vec<FC<'a>>),
    Inclusion(Vec<FC<'a>>),
    AndNot(Box<FC<'a>>),
    SelfUUID,
    // Not(Box<FC>),
}

// This is the filters internal representation.
#[derive(Debug, Clone, PartialEq)]
enum FilterComp {
    // This is attr - value
    Eq(AttrString, PartialValue),
    Sub(AttrString, PartialValue),
    Pres(AttrString),
    LessThan(AttrString, PartialValue),
    Or(Vec<FilterComp>),
    And(Vec<FilterComp>),
    Inclusion(Vec<FilterComp>),
    AndNot(Box<FilterComp>),
    SelfUUID,
    // Does this mean we can add a true not to the type now?
    // Not(Box<FilterComp>),
}

// This is the fully resolved internal representation. Note the lack of Not and selfUUID
// because these are resolved into And(Pres(class), AndNot(term)) and Eq(uuid, ...).
// Importantly, we make this accessible to Entry so that it can then match on filters
// properly.
#[derive(Debug, Clone)]
pub enum FilterResolved {
    // This is attr - value - indexed
    Eq(AttrString, PartialValue, bool),
    Sub(AttrString, PartialValue, bool),
    Pres(AttrString, bool),
    LessThan(AttrString, PartialValue, bool),
    Or(Vec<FilterResolved>),
    And(Vec<FilterResolved>),
    // All terms must have 1 or more items, or the inclusion is false!
    Inclusion(Vec<FilterResolved>),
    AndNot(Box<FilterResolved>),
}

#[derive(Debug, Clone)]
pub struct FilterInvalid {
    inner: FilterComp,
}

#[derive(Debug, Clone)]
pub struct FilterValid {
    inner: FilterComp,
}

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct Filter<STATE> {
    state: STATE,
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
        ev: &Event,
        idxmeta: Option<&HashSet<IdxKey>>,
        // rsv_cache: (),
    ) -> Result<Filter<FilterValidResolved>, OperationError> {
        // Given a filter, resolve Not and SelfUUID to real terms.
        //
        // The benefit of moving optimisation to this step is from various inputs, we can
        // get to a resolved + optimised filter, and then we can cache those outputs in many
        // cases!
        Ok(Filter {
            state: FilterValidResolved {
                inner: match idxmeta {
                    Some(idx) => FilterResolved::resolve_idx(self.state.inner.clone(), ev, idx),
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
                .ok_or(OperationError::FilterUUIDResolution)?,
            },
        })
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

    #[cfg(test)]
    pub unsafe fn into_valid_resolved(self) -> Filter<FilterValidResolved> {
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
            (AttrString::from("uuid"), IndexType::EQUALITY),
            (AttrString::from("uuid"), IndexType::PRESENCE),
            (AttrString::from("name"), IndexType::EQUALITY),
            (AttrString::from("name"), IndexType::SUBSTRING),
            (AttrString::from("name"), IndexType::PRESENCE),
            (AttrString::from("class"), IndexType::EQUALITY),
            (AttrString::from("class"), IndexType::PRESENCE),
            (AttrString::from("member"), IndexType::EQUALITY),
            (AttrString::from("member"), IndexType::PRESENCE),
            (AttrString::from("memberof"), IndexType::EQUALITY),
            (AttrString::from("memberof"), IndexType::PRESENCE),
            (AttrString::from("directmemberof"), IndexType::EQUALITY),
            (AttrString::from("directmemberof"), IndexType::PRESENCE),
        ];

        let idxmeta_ref = idxmeta.iter().map(|(attr, itype)| (attr, itype)).collect();

        Filter {
            state: FilterValidResolved {
                inner: FilterResolved::from_invalid(self.state.inner, &idxmeta_ref),
            },
        }
    }

    #[cfg(test)]
    pub unsafe fn into_valid(self) -> Filter<FilterValid> {
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

    #[cfg(test)]
    pub unsafe fn from_str(fc: &str) -> Self {
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
    pub fn from_ro(
        audit: &mut AuditScope,
        ev: &Event,
        f: &ProtoFilter,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        lperf_trace_segment!(audit, "filter::from_ro", || {
            let depth = FILTER_DEPTH_MAX;
            let mut elems = ev.limits.filter_max_elements;
            Ok(Filter {
                state: FilterInvalid {
                    inner: FilterComp::from_ro(audit, f, qs, depth, &mut elems)?,
                },
            })
        })
    }

    pub fn from_rw(
        audit: &mut AuditScope,
        ev: &Event,
        f: &ProtoFilter,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        lperf_trace_segment!(audit, "filter::from_rw", || {
            let depth = FILTER_DEPTH_MAX;
            let mut elems = ev.limits.filter_max_elements;
            Ok(Filter {
                state: FilterInvalid {
                    inner: FilterComp::from_rw(audit, f, qs, depth, &mut elems)?,
                },
            })
        })
    }

    pub fn from_ldap_ro(
        audit: &mut AuditScope,
        ev: &Event,
        f: &LdapFilter,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        lperf_trace_segment!(audit, "filter::from_ldap_ro", || {
            let depth = FILTER_DEPTH_MAX;
            let mut elems = ev.limits.filter_max_elements;
            Ok(Filter {
                state: FilterInvalid {
                    inner: FilterComp::from_ldap_ro(audit, f, qs, depth, &mut elems)?,
                },
            })
        })
    }
}

impl FilterComp {
    fn new(fc: FC) -> Self {
        match fc {
            FC::Eq(a, v) => FilterComp::Eq(AttrString::from(a), v),
            FC::Sub(a, v) => FilterComp::Sub(AttrString::from(a), v),
            FC::Pres(a) => FilterComp::Pres(AttrString::from(a)),
            FC::LessThan(a, v) => FilterComp::LessThan(AttrString::from(a), v),
            FC::Or(v) => FilterComp::Or(v.into_iter().map(FilterComp::new).collect()),
            FC::And(v) => FilterComp::And(v.into_iter().map(FilterComp::new).collect()),
            FC::Inclusion(v) => FilterComp::Inclusion(v.into_iter().map(FilterComp::new).collect()),
            FC::AndNot(b) => FilterComp::AndNot(Box::new(FilterComp::new(*b))),
            FC::SelfUUID => FilterComp::SelfUUID,
        }
    }

    fn new_ignore_hidden(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::AndNot(Box::new(FilterComp::Or(vec![
                FilterComp::Eq(
                    AttrString::from("class"),
                    PartialValue::new_iutf8("tombstone"),
                ),
                FilterComp::Eq(
                    AttrString::from("class"),
                    PartialValue::new_iutf8("recycled"),
                ),
            ]))),
            fc,
        ])
    }

    fn new_recycled(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::Eq(
                AttrString::from("class"),
                PartialValue::new_iutf8("recycled"),
            ),
            fc,
        ])
    }

    fn get_attr_set<'a>(&'a self, r_set: &mut BTreeSet<&'a str>) {
        match self {
            FilterComp::Eq(attr, _) => {
                r_set.insert(attr.as_str());
            }
            FilterComp::Sub(attr, _) => {
                r_set.insert(attr.as_str());
            }
            FilterComp::Pres(attr) => {
                r_set.insert(attr.as_str());
            }
            FilterComp::LessThan(attr, _) => {
                r_set.insert(attr.as_str());
            }
            FilterComp::Or(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::And(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::Inclusion(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::AndNot(f) => f.get_attr_set(r_set),
            FilterComp::SelfUUID => {
                r_set.insert("uuid");
            }
        }
    }

    fn validate(&self, schema: &dyn SchemaTransaction) -> Result<FilterComp, SchemaError> {
        // Optimisation is done at another stage.

        // This probably needs some rework

        // Getting this each recursion could be slow. Maybe
        // we need an inner functon that passes the reference?
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
                            .validate_partialvalue(attr_norm.as_str(), &value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Eq(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Sub(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(attr_norm.as_str(), &value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Sub(attr_norm, value.clone()))
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
                            .validate_partialvalue(attr_norm.as_str(), &value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::LessThan(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute(attr_norm.to_string())),
                }
            }
            FilterComp::Or(filters) => {
                // If all filters are okay, return Ok(Filter::Or())
                // If any is invalid, return the error.
                // TODO: ftweedal says an empty or is a valid filter
                // in mathematical terms.
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
                // TODO: ftweedal says an empty or is a valid filter
                // in mathematical terms.
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
            FilterComp::SelfUUID => {
                // Pretty hard to mess this one up ;)
                Ok(FilterComp::SelfUUID)
            }
        }
    }

    fn from_ro(
        audit: &mut AuditScope,
        f: &ProtoFilter,
        qs: &QueryServerReadTransaction,
        depth: usize,
        elems: &mut usize,
    ) -> Result<Self, OperationError> {
        let ndepth = depth.checked_sub(1).ok_or(OperationError::ResourceLimit)?;
        Ok(match f {
            ProtoFilter::Eq(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(audit, nk.as_str(), v)?;
                FilterComp::Eq(nk, v)
            }
            ProtoFilter::Sub(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(audit, nk.as_str(), v)?;
                FilterComp::Sub(nk, v)
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
                        .map(|f| Self::from_ro(audit, f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::And(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::And(
                    l.iter()
                        .map(|f| Self::from_ro(audit, f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::AndNot(l) => {
                *elems = (*elems)
                    .checked_sub(1)
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::AndNot(Box::new(Self::from_ro(audit, l, qs, ndepth, elems)?))
            }
            ProtoFilter::SelfUUID => FilterComp::SelfUUID,
        })
    }

    fn from_rw(
        audit: &mut AuditScope,
        f: &ProtoFilter,
        qs: &QueryServerWriteTransaction,
        depth: usize,
        elems: &mut usize,
    ) -> Result<Self, OperationError> {
        let ndepth = depth.checked_sub(1).ok_or(OperationError::ResourceLimit)?;
        Ok(match f {
            ProtoFilter::Eq(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(audit, nk.as_str(), v)?;
                FilterComp::Eq(nk, v)
            }
            ProtoFilter::Sub(a, v) => {
                let nk = qs.get_schema().normalise_attr_name(a);
                let v = qs.clone_partialvalue(audit, nk.as_str(), v)?;
                FilterComp::Sub(nk, v)
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
                        .map(|f| Self::from_rw(audit, f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::And(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::And(
                    l.iter()
                        .map(|f| Self::from_rw(audit, f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            ProtoFilter::AndNot(l) => {
                *elems = (*elems)
                    .checked_sub(1)
                    .ok_or(OperationError::ResourceLimit)?;

                FilterComp::AndNot(Box::new(Self::from_rw(audit, l, qs, ndepth, elems)?))
            }
            ProtoFilter::SelfUUID => FilterComp::SelfUUID,
        })
    }

    fn from_ldap_ro(
        audit: &mut AuditScope,
        f: &LdapFilter,
        qs: &QueryServerReadTransaction,
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
                        .map(|f| Self::from_ldap_ro(audit, f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            LdapFilter::Or(l) => {
                *elems = (*elems)
                    .checked_sub(l.len())
                    .ok_or(OperationError::ResourceLimit)?;

                FilterComp::Or(
                    l.iter()
                        .map(|f| Self::from_ldap_ro(audit, f, qs, ndepth, elems))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            LdapFilter::Not(l) => {
                *elems = (*elems)
                    .checked_sub(1)
                    .ok_or(OperationError::ResourceLimit)?;
                FilterComp::AndNot(Box::new(Self::from_ldap_ro(audit, l, qs, ndepth, elems)?))
            }
            LdapFilter::Equality(a, v) => {
                let a = ldap_attr_filter_map(a);
                let v = qs.clone_partialvalue(audit, a.as_str(), v)?;
                FilterComp::Eq(a, v)
            }
            LdapFilter::Present(a) => FilterComp::Pres(ldap_attr_filter_map(a)),
            LdapFilter::Substring(
                _a,
                LdapSubstringFilter {
                    initial: _,
                    any: _,
                    final_: _,
                },
            ) => {
                // let a = ldap_attr_filter_map(a);
                ladmin_error!(audit, "Unable to convert ldapsubstringfilter to sub filter");
                return Err(OperationError::FilterGeneration);
            }
        })
    }
}

/* We only configure partial eq if cfg test on the invalid/valid types */
#[cfg(test)]
impl PartialEq for Filter<FilterInvalid> {
    fn eq(&self, rhs: &Filter<FilterInvalid>) -> bool {
        self.state.inner == rhs.state.inner
    }
}

#[cfg(test)]
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

impl PartialEq for FilterResolved {
    fn eq(&self, rhs: &FilterResolved) -> bool {
        match (self, rhs) {
            (FilterResolved::Eq(a1, v1, i1), FilterResolved::Eq(a2, v2, i2)) => {
                a1 == a2 && v1 == v2 && i1 == i2
            }
            (FilterResolved::Sub(a1, v1, i1), FilterResolved::Sub(a2, v2, i2)) => {
                a1 == a2 && v1 == v2 && i1 == i2
            }
            (FilterResolved::Pres(a1, i1), FilterResolved::Pres(a2, i2)) => a1 == a2 && i1 == i2,
            (FilterResolved::And(vs1), FilterResolved::And(vs2)) => vs1 == vs2,
            (FilterResolved::Or(vs1), FilterResolved::Or(vs2)) => vs1 == vs2,
            (FilterResolved::AndNot(f1), FilterResolved::AndNot(f2)) => f1 == f2,
            (_, _) => false,
        }
    }
}

impl Eq for FilterResolved {}

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

// remember, this isn't ordering by alphanumeric, this is ordering of
// optimisation preference!
impl PartialOrd for FilterResolved {
    fn partial_cmp(&self, rhs: &FilterResolved) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Ord for FilterResolved {
    fn cmp(&self, rhs: &FilterResolved) -> Ordering {
        match (self, rhs) {
            (FilterResolved::Eq(a1, v1, true), FilterResolved::Eq(a2, v2, true)) => {
                match a1.cmp(a2) {
                    Ordering::Equal => v1.cmp(v2),
                    o => o,
                }
            }
            (FilterResolved::Sub(a1, v1, true), FilterResolved::Sub(a2, v2, true)) => {
                match a1.cmp(a2) {
                    Ordering::Equal => v1.cmp(v2),
                    o => o,
                }
            }
            (FilterResolved::Pres(a1, true), FilterResolved::Pres(a2, true)) => a1.cmp(a2),
            // Always higher prefer indexed Eq over all else, as these will have
            // the best indexes and return smallest candidates.
            (FilterResolved::Eq(_, _, true), _) => Ordering::Less,
            (_, FilterResolved::Eq(_, _, true)) => Ordering::Greater,
            (FilterResolved::Pres(_, true), _) => Ordering::Less,
            (_, FilterResolved::Pres(_, true)) => Ordering::Greater,
            (FilterResolved::Sub(_, _, true), _) => Ordering::Greater,
            (_, FilterResolved::Sub(_, _, true)) => Ordering::Less,
            // Now prefer the unindexed types by performance order.
            (FilterResolved::Pres(_, false), FilterResolved::Pres(_, false)) => Ordering::Equal,
            (FilterResolved::Pres(_, false), _) => Ordering::Less,
            (_, FilterResolved::Pres(_, false)) => Ordering::Greater,
            (FilterResolved::Eq(_, _, false), FilterResolved::Eq(_, _, false)) => Ordering::Equal,
            (FilterResolved::Eq(_, _, false), _) => Ordering::Less,
            (_, FilterResolved::Eq(_, _, false)) => Ordering::Greater,
            (FilterResolved::Sub(_, _, false), FilterResolved::Sub(_, _, false)) => Ordering::Equal,
            (FilterResolved::Sub(_, _, false), _) => Ordering::Greater,
            (_, FilterResolved::Sub(_, _, false)) => Ordering::Less,
            // They can't be compared, they don't move!
            (_, _) => Ordering::Equal,
        }
    }
}

impl FilterResolved {
    #[cfg(test)]
    unsafe fn from_invalid(fc: FilterComp, idxmeta: &HashSet<(&AttrString, &IndexType)>) -> Self {
        match fc {
            FilterComp::Eq(a, v) => {
                let idx = idxmeta.contains(&(&a, &IndexType::EQUALITY));
                FilterResolved::Eq(a, v, idx)
            }
            FilterComp::Sub(a, v) => {
                // let idx = idxmeta.contains(&(&a, &IndexType::SUBSTRING));
                // TODO: For now, don't emit substring indexes.
                let idx = false;
                FilterResolved::Sub(a, v, idx)
            }
            FilterComp::Pres(a) => {
                let idx = idxmeta.contains(&(&a, &IndexType::PRESENCE));
                FilterResolved::Pres(a, idx)
            }
            FilterComp::LessThan(a, v) => {
                // let idx = idxmeta.contains(&(&a, &IndexType::ORDERING));
                // TODO: For now, don't emit ordering indexes.
                let idx = false;
                FilterResolved::LessThan(a, v, idx)
            }
            FilterComp::Or(vs) => FilterResolved::Or(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v, idxmeta))
                    .collect(),
            ),
            FilterComp::And(vs) => FilterResolved::And(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v, idxmeta))
                    .collect(),
            ),
            FilterComp::Inclusion(vs) => FilterResolved::Inclusion(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v, idxmeta))
                    .collect(),
            ),
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::AndNot(Box::new(FilterResolved::from_invalid(
                    (*f).clone(),
                    idxmeta,
                )))
            }
            FilterComp::SelfUUID => panic!("Not possible to resolve SelfUUID in from_invalid!"),
        }
    }

    fn resolve_idx(fc: FilterComp, ev: &Event, idxmeta: &HashSet<IdxKey>) -> Option<Self> {
        match fc {
            FilterComp::Eq(a, v) => {
                let idxkref = IdxKeyRef::new(&a, &IndexType::EQUALITY);
                let idx = idxmeta.contains(&idxkref as &dyn IdxKeyToRef);
                Some(FilterResolved::Eq(a, v, idx))
            }
            FilterComp::Sub(a, v) => {
                let idxkref = IdxKeyRef::new(&a, &IndexType::SUBSTRING);
                let idx = idxmeta.contains(&idxkref as &dyn IdxKeyToRef);
                Some(FilterResolved::Sub(a, v, idx))
            }
            FilterComp::Pres(a) => {
                let idxkref = IdxKeyRef::new(&a, &IndexType::PRESENCE);
                let idx = idxmeta.contains(&idxkref as &dyn IdxKeyToRef);
                Some(FilterResolved::Pres(a, idx))
            }
            FilterComp::LessThan(a, v) => {
                // let idx = idxmeta.contains(&(&a, &IndexType::SUBSTRING));
                let idx = false;
                Some(FilterResolved::LessThan(a, v, idx))
            }
            FilterComp::Or(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_idx(f, ev, idxmeta))
                    .collect();
                fi.map(FilterResolved::Or)
            }
            FilterComp::And(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_idx(f, ev, idxmeta))
                    .collect();
                fi.map(FilterResolved::And)
            }
            FilterComp::Inclusion(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_idx(f, ev, idxmeta))
                    .collect();
                fi.map(FilterResolved::Inclusion)
            }
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::resolve_idx((*f).clone(), ev, idxmeta)
                    .map(|fi| FilterResolved::AndNot(Box::new(fi)))
            }
            FilterComp::SelfUUID => match &ev.origin {
                EventOrigin::User(e) => {
                    let uuid_s = AttrString::from("uuid");
                    let idxkref = IdxKeyRef::new(&uuid_s, &IndexType::EQUALITY);
                    let idx = idxmeta.contains(&idxkref as &dyn IdxKeyToRef);
                    Some(FilterResolved::Eq(
                        uuid_s,
                        PartialValue::new_uuid(*e.get_uuid()),
                        idx,
                    ))
                }
                _ => None,
            },
        }
    }

    fn resolve_no_idx(fc: FilterComp, ev: &Event) -> Option<Self> {
        match fc {
            FilterComp::Eq(a, v) => Some(FilterResolved::Eq(a, v, false)),
            FilterComp::Sub(a, v) => Some(FilterResolved::Sub(a, v, false)),
            FilterComp::Pres(a) => Some(FilterResolved::Pres(a, false)),
            FilterComp::LessThan(a, v) => Some(FilterResolved::LessThan(a, v, false)),
            FilterComp::Or(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_no_idx(f, ev))
                    .collect();
                fi.map(FilterResolved::Or)
            }
            FilterComp::And(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_no_idx(f, ev))
                    .collect();
                fi.map(FilterResolved::And)
            }
            FilterComp::Inclusion(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve_no_idx(f, ev))
                    .collect();
                fi.map(FilterResolved::Inclusion)
            }
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::resolve_no_idx((*f).clone(), ev)
                    .map(|fi| FilterResolved::AndNot(Box::new(fi)))
            }
            FilterComp::SelfUUID => match &ev.origin {
                EventOrigin::User(e) => Some(FilterResolved::Eq(
                    AttrString::from("uuid"),
                    PartialValue::new_uuid(*e.get_uuid()),
                    false,
                )),
                _ => None,
            },
        }
    }

    // This is an optimise that only attempts to optimise the outer terms.
    fn fast_optimise(self) -> Self {
        match self {
            FilterResolved::Inclusion(mut f_list) => {
                f_list.sort_unstable();
                f_list.dedup();
                FilterResolved::Inclusion(f_list)
            }
            FilterResolved::And(mut f_list) => {
                f_list.sort_unstable();
                f_list.dedup();
                FilterResolved::And(f_list)
            }
            v => v,
        }
    }

    fn optimise(&self) -> Self {
        // Most optimisations only matter around or/and terms.
        match self {
            FilterResolved::Inclusion(f_list) => {
                // first, optimise all our inner elements
                let (f_list_inc, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    .map(|f_ref| f_ref.optimise())
                    .partition(|f| match f {
                        FilterResolved::Inclusion(_) => true,
                        _ => false,
                    });

                f_list_inc.into_iter().for_each(|fc| {
                    if let FilterResolved::Inclusion(mut l) = fc {
                        f_list_new.append(&mut l)
                    }
                });
                // finally, optimise this list by sorting.
                f_list_new.sort_unstable();
                f_list_new.dedup();
                FilterResolved::Inclusion(f_list_new)
            }
            FilterResolved::And(f_list) => {
                // first, optimise all our inner elements
                let (f_list_and, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    .map(|f_ref| f_ref.optimise())
                    .partition(|f| match f {
                        FilterResolved::And(_) => true,
                        _ => false,
                    });

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
                    if let FilterResolved::And(mut l) = fc {
                        f_list_new.append(&mut l)
                    }
                });

                // If the f_list_or only has one element, pop it and return.
                if f_list_new.len() == 1 {
                    #[allow(clippy::expect_used)]
                    f_list_new.pop().expect("corrupt?")
                } else {
                    // finally, optimise this list by sorting.
                    f_list_new.sort_unstable();
                    f_list_new.dedup();
                    // return!
                    FilterResolved::And(f_list_new)
                }
            }
            FilterResolved::Or(f_list) => {
                let (f_list_or, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    // Optimise all inner items.
                    .map(|f_ref| f_ref.optimise())
                    // Split out inner-or terms to fold into this term.
                    .partition(|f| match f {
                        FilterResolved::Or(_) => true,
                        _ => false,
                    });

                // Append the inner terms.
                f_list_or.into_iter().for_each(|fc| {
                    if let FilterResolved::Or(mut l) = fc {
                        f_list_new.append(&mut l)
                    }
                });

                // If the f_list_or only has one element, pop it and return.
                if f_list_new.len() == 1 {
                    #[allow(clippy::expect_used)]
                    f_list_new.pop().expect("corrupt?")
                } else {
                    // sort, but reverse so that sub-optimal elements are earlier
                    // to promote fast-failure.
                    f_list_new.sort_unstable_by(|a, b| b.cmp(a));
                    f_list_new.dedup();

                    FilterResolved::Or(f_list_new)
                }
            }
            f => f.clone(),
        }
    }

    pub fn is_andnot(&self) -> bool {
        match self {
            FilterResolved::AndNot(_) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryInit, EntryNew, EntrySealed};
    use crate::event::{CreateEvent, Event};
    use crate::filter::{Filter, FilterInvalid, FILTER_DEPTH_MAX};
    use crate::server::QueryServerTransaction;
    use crate::value::{PartialValue, Value};
    use std::cmp::{Ordering, PartialOrd};
    use std::collections::BTreeSet;

    use kanidm_proto::v1::Filter as ProtoFilter;
    use kanidm_proto::v1::OperationError;
    use ldap3_server::simple::LdapFilter;

    #[test]
    fn test_filter_simple() {
        // Test construction.
        let _filt: Filter<FilterInvalid> = filter!(f_eq("class", PartialValue::new_class("user")));

        // AFTER
        let _complex_filt: Filter<FilterInvalid> = filter!(f_and!([
            f_or!([
                f_eq("userid", PartialValue::new_iutf8("test_a")),
                f_eq("userid", PartialValue::new_iutf8("test_b")),
            ]),
            f_sub("class", PartialValue::new_class("user")),
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
            let f_init_r = unsafe { f_init.into_valid_resolved() };
            let f_init_o = f_init_r.optimise();
            let f_init_e = unsafe { f_expect.into_valid_resolved() };
            debug!("--");
            debug!("init   --> {:?}", f_init_r);
            debug!("opt    --> {:?}", f_init_o);
            debug!("expect --> {:?}", f_init_e);
            assert!(f_init_o == f_init_e);
        }};
    }

    #[test]
    fn test_filter_optimise() {
        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();
        // Given sets of "optimisable" filters, optimise them.
        filter_optimise_assert!(
            f_and(vec![f_and(vec![f_eq(
                "class",
                PartialValue::new_class("test")
            )])]),
            f_eq("class", PartialValue::new_class("test"))
        );

        filter_optimise_assert!(
            f_or(vec![f_or(vec![f_eq(
                "class",
                PartialValue::new_class("test")
            )])]),
            f_eq("class", PartialValue::new_class("test"))
        );

        filter_optimise_assert!(
            f_and(vec![f_or(vec![f_and(vec![f_eq(
                "class",
                PartialValue::new_class("test")
            )])])]),
            f_eq("class", PartialValue::new_class("test"))
        );

        // Later this can test duplicate filter detection.
        filter_optimise_assert!(
            f_and(vec![
                f_and(vec![f_eq("class", PartialValue::new_class("test"))]),
                f_sub("class", PartialValue::new_class("te")),
                f_pres("class"),
                f_eq("class", PartialValue::new_class("test"))
            ]),
            f_and(vec![
                f_eq("class", PartialValue::new_class("test")),
                f_pres("class"),
                f_sub("class", PartialValue::new_class("te")),
            ])
        );

        // Test dedup removes only the correct element despite padding.
        filter_optimise_assert!(
            f_and(vec![
                f_and(vec![
                    f_eq("class", PartialValue::new_class("foo")),
                    f_eq("class", PartialValue::new_class("test")),
                    f_eq("uid", PartialValue::new_class("bar")),
                ]),
                f_sub("class", PartialValue::new_class("te")),
                f_pres("class"),
                f_eq("class", PartialValue::new_class("test"))
            ]),
            f_and(vec![
                f_eq("class", PartialValue::new_class("foo")),
                f_eq("class", PartialValue::new_class("test")),
                f_pres("class"),
                f_eq("uid", PartialValue::new_class("bar")),
                f_sub("class", PartialValue::new_class("te")),
            ])
        );

        filter_optimise_assert!(
            f_or(vec![
                f_eq("class", PartialValue::new_class("test")),
                f_pres("class"),
                f_sub("class", PartialValue::new_class("te")),
                f_or(vec![f_eq("class", PartialValue::new_class("test"))]),
            ]),
            f_or(vec![
                f_sub("class", PartialValue::new_class("te")),
                f_pres("class"),
                f_eq("class", PartialValue::new_class("test"))
            ])
        );

        // Test dedup doesn't affect nested items incorrectly.
        filter_optimise_assert!(
            f_or(vec![
                f_eq("class", PartialValue::new_class("test")),
                f_and(vec![
                    f_eq("class", PartialValue::new_class("test")),
                    f_eq("term", PartialValue::new_class("test")),
                    f_or(vec![f_eq("class", PartialValue::new_class("test"))])
                ]),
            ]),
            f_or(vec![
                f_and(vec![
                    f_eq("class", PartialValue::new_class("test")),
                    f_eq("term", PartialValue::new_class("test"))
                ]),
                f_eq("class", PartialValue::new_class("test")),
            ])
        );
    }

    #[test]
    fn test_filter_eq() {
        let f_t1a = filter!(f_pres("userid"));
        let f_t1b = filter!(f_pres("userid"));
        let f_t1c = filter!(f_pres("zzzz"));

        assert_eq!(f_t1a == f_t1b, true);
        assert_eq!(f_t1a == f_t1c, false);
        assert_eq!(f_t1b == f_t1c, false);

        let f_t2a = filter!(f_and!([f_pres("userid")]));
        let f_t2b = filter!(f_and!([f_pres("userid")]));
        let f_t2c = filter!(f_and!([f_pres("zzzz")]));
        assert_eq!(f_t2a == f_t2b, true);
        assert_eq!(f_t2a == f_t2c, false);
        assert_eq!(f_t2b == f_t2c, false);

        assert_eq!(f_t2c == f_t1a, false);
        assert_eq!(f_t2c == f_t1c, false);
    }

    #[test]
    fn test_filter_ord() {
        // Test that we uphold the rules of partialOrd
        // Basic equality
        // Test the two major paths here (str vs list)
        let f_t1a = unsafe { filter_resolved!(f_pres("userid")) };
        let f_t1b = unsafe { filter_resolved!(f_pres("userid")) };

        assert_eq!(f_t1a.partial_cmp(&f_t1b), Some(Ordering::Equal));
        assert_eq!(f_t1b.partial_cmp(&f_t1a), Some(Ordering::Equal));

        let f_t2a = unsafe { filter_resolved!(f_and!([])) };
        let f_t2b = unsafe { filter_resolved!(f_and!([])) };
        assert_eq!(f_t2a.partial_cmp(&f_t2b), Some(Ordering::Equal));
        assert_eq!(f_t2b.partial_cmp(&f_t2a), Some(Ordering::Equal));

        // antisymmetry: if a < b then !(a > b), as well as a > b implying !(a < b); and
        // These are unindexed so we have to check them this way.
        let f_t3b = unsafe { filter_resolved!(f_eq("userid", PartialValue::new_iutf8(""))) };
        assert_eq!(f_t1a.partial_cmp(&f_t3b), Some(Ordering::Less));
        assert_eq!(f_t3b.partial_cmp(&f_t1a), Some(Ordering::Greater));

        // transitivity: a < b and b < c implies a < c. The same must hold for both == and >.
        let f_t4b = unsafe { filter_resolved!(f_sub("userid", PartialValue::new_iutf8(""))) };
        assert_eq!(f_t1a.partial_cmp(&f_t4b), Some(Ordering::Less));
        assert_eq!(f_t3b.partial_cmp(&f_t4b), Some(Ordering::Less));

        assert_eq!(f_t4b.partial_cmp(&f_t1a), Some(Ordering::Greater));
        assert_eq!(f_t4b.partial_cmp(&f_t3b), Some(Ordering::Greater));
    }

    #[test]
    fn test_filter_clone() {
        // Test that cloning filters yields the same result regardless of
        // complexity.
        let f_t1a = unsafe { filter_resolved!(f_pres("userid")) };
        let f_t1b = f_t1a.clone();
        let f_t1c = unsafe { filter_resolved!(f_pres("zzzz")) };

        assert_eq!(f_t1a == f_t1b, true);
        assert_eq!(f_t1a == f_t1c, false);

        let f_t2a = unsafe { filter_resolved!(f_and!([f_pres("userid")])) };
        let f_t2b = f_t2a.clone();
        let f_t2c = unsafe { filter_resolved!(f_and!([f_pres("zzzz")])) };

        assert_eq!(f_t2a == f_t2b, true);
        assert_eq!(f_t2a == f_t2c, false);
    }

    #[test]
    fn test_lessthan_entry_filter() {
        let e: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "gidnumber": ["1000"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let f_t1a = unsafe { filter_resolved!(f_lt("gidnumber", PartialValue::new_uint32(500))) };
        assert!(e.entry_match_no_index(&f_t1a) == false);

        let f_t1b = unsafe { filter_resolved!(f_lt("gidnumber", PartialValue::new_uint32(1000))) };
        assert!(e.entry_match_no_index(&f_t1b) == false);

        let f_t1c = unsafe { filter_resolved!(f_lt("gidnumber", PartialValue::new_uint32(1001))) };
        assert!(e.entry_match_no_index(&f_t1c) == true);
    }

    #[test]
    fn test_or_entry_filter() {
        let e: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let f_t1a = unsafe {
            filter_resolved!(f_or!([
                f_eq("userid", PartialValue::new_iutf8("william")),
                f_eq("uidnumber", PartialValue::new_iutf8("1000")),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = unsafe {
            filter_resolved!(f_or!([
                f_eq("userid", PartialValue::new_iutf8("william")),
                f_eq("uidnumber", PartialValue::new_iutf8("1001")),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t2a));

        let f_t3a = unsafe {
            filter_resolved!(f_or!([
                f_eq("userid", PartialValue::new_iutf8("alice")),
                f_eq("uidnumber", PartialValue::new_iutf8("1000")),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t3a));

        let f_t4a = unsafe {
            filter_resolved!(f_or!([
                f_eq("userid", PartialValue::new_iutf8("alice")),
                f_eq("uidnumber", PartialValue::new_iutf8("1001")),
            ]))
        };
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_and_entry_filter() {
        let e: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let f_t1a = unsafe {
            filter_resolved!(f_and!([
                f_eq("userid", PartialValue::new_iutf8("william")),
                f_eq("uidnumber", PartialValue::new_iutf8("1000")),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = unsafe {
            filter_resolved!(f_and!([
                f_eq("userid", PartialValue::new_iutf8("william")),
                f_eq("uidnumber", PartialValue::new_iutf8("1001")),
            ]))
        };
        assert!(!e.entry_match_no_index(&f_t2a));

        let f_t3a = unsafe {
            filter_resolved!(f_and!([
                f_eq("userid", PartialValue::new_iutf8("alice")),
                f_eq("uidnumber", PartialValue::new_iutf8("1000")),
            ]))
        };
        assert!(!e.entry_match_no_index(&f_t3a));

        let f_t4a = unsafe {
            filter_resolved!(f_and!([
                f_eq("userid", PartialValue::new_iutf8("alice")),
                f_eq("uidnumber", PartialValue::new_iutf8("1001")),
            ]))
        };
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_not_entry_filter() {
        let e1: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let f_t1a =
            unsafe { filter_resolved!(f_andnot(f_eq("userid", PartialValue::new_iutf8("alice")))) };
        assert!(e1.entry_match_no_index(&f_t1a));

        let f_t2a = unsafe {
            filter_resolved!(f_andnot(f_eq("userid", PartialValue::new_iutf8("william"))))
        };
        assert!(!e1.entry_match_no_index(&f_t2a));
    }

    #[test]
    fn test_nested_entry_filter() {
        let e1: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["person"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let e2: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["person"],
                "uuid": ["4b6228ab-1dbe-42a4-a9f5-f6368222438e"],
                "uidnumber": ["1001"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let e3: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["person"],
                "uuid": ["7b23c99d-c06b-4a9a-a958-3afa56383e1d"],
                "uidnumber": ["1002"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let e4: Entry<EntrySealed, EntryNew> = unsafe {
            Entry::unsafe_from_entry_str(
                r#"{
            "attrs": {
                "class": ["group"],
                "uuid": ["21d816b5-1f6a-4696-b7c1-6ed06d22ed81"],
                "uidnumber": ["1000"]
            }
        }"#,
            )
            .into_sealed_new()
        };

        let f_t1a = unsafe {
            filter_resolved!(f_and!([
                f_eq("class", PartialValue::new_class("person")),
                f_or!([
                    f_eq("uidnumber", PartialValue::new_iutf8("1001")),
                    f_eq("uidnumber", PartialValue::new_iutf8("1000"))
                ])
            ]))
        };

        assert!(e1.entry_match_no_index(&f_t1a));
        assert!(e2.entry_match_no_index(&f_t1a));
        assert!(!e3.entry_match_no_index(&f_t1a));
        assert!(!e4.entry_match_no_index(&f_t1a));
    }

    #[test]
    fn test_attr_set_filter() {
        let mut f_expect = BTreeSet::new();
        f_expect.insert("userid");
        f_expect.insert("class");
        // Given filters, get their expected attribute sets - this is used by access control profiles
        // to determine what attrs we are requesting regardless of the partialvalue.
        let f_t1a = unsafe {
            filter_valid!(f_and!([
                f_eq("userid", PartialValue::new_iutf8("alice")),
                f_eq("class", PartialValue::new_iutf8("1001")),
            ]))
        };

        assert!(f_t1a.get_attr_set() == f_expect);

        let f_t2a = unsafe {
            filter_valid!(f_and!([
                f_eq("userid", PartialValue::new_iutf8("alice")),
                f_eq("class", PartialValue::new_iutf8("1001")),
                f_eq("userid", PartialValue::new_iutf8("claire")),
            ]))
        };

        assert!(f_t2a.get_attr_set() == f_expect);
    }

    #[test]
    fn test_filter_resolve_value() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());
            let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
                r#"{
                "attrs": {
                    "class": ["object", "person", "account"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
            }"#,
            );
            let e2: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
                r#"{
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson2"],
                    "uuid": ["a67c0c71-0b35-4218-a6b0-22d23d131d27"],
                    "description": ["testperson"],
                    "displayname": ["testperson2"]
                }
            }"#,
            );
            let e_ts: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
                r#"{
                "attrs": {
                    "class": ["tombstone", "object"],
                    "uuid": ["9557f49c-97a5-4277-a9a5-097d17eb8317"]
                }
            }"#,
            );
            let ce = CreateEvent::new_internal(vec![e1, e2, e_ts]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Resolving most times should yield expected results
            let t1 = Value::new_utf8s("teststring");
            let r1 = server_txn.resolve_value(audit, &t1);
            assert!(r1 == Ok("teststring".to_string()));

            // Resolve UUID with matching spn
            let t_uuid = Value::new_refer_s("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap();
            let r_uuid = server_txn.resolve_value(audit, &t_uuid);
            debug!("{:?}", r_uuid);
            assert!(r_uuid == Ok("testperson1@example.com".to_string()));

            // Resolve UUID with matching name
            let t_uuid = Value::new_refer_s("a67c0c71-0b35-4218-a6b0-22d23d131d27").unwrap();
            let r_uuid = server_txn.resolve_value(audit, &t_uuid);
            debug!("{:?}", r_uuid);
            assert!(r_uuid == Ok("testperson2".to_string()));

            // Resolve UUID non-exist
            let t_uuid_non = Value::new_refer_s("b83e98f0-3d2e-41d2-9796-d8d993289c86").unwrap();
            let r_uuid_non = server_txn.resolve_value(audit, &t_uuid_non);
            debug!("{:?}", r_uuid_non);
            assert!(r_uuid_non == Ok("b83e98f0-3d2e-41d2-9796-d8d993289c86".to_string()));

            // Resolve UUID to tombstone/recycled (same an non-exst)
            let t_uuid_ts = Value::new_refer_s("9557f49c-97a5-4277-a9a5-097d17eb8317").unwrap();
            let r_uuid_ts = server_txn.resolve_value(audit, &t_uuid_ts);
            debug!("{:?}", r_uuid_ts);
            assert!(r_uuid_ts == Ok("9557f49c-97a5-4277-a9a5-097d17eb8317".to_string()));
        })
    }

    #[test]
    fn test_filter_depth_limits() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let r_txn = server.read();

            let mut inv_proto = ProtoFilter::Pres("class".to_string());
            for _i in 0..(FILTER_DEPTH_MAX + 1) {
                inv_proto = ProtoFilter::And(vec![inv_proto]);
            }

            let mut inv_ldap = LdapFilter::Present("class".to_string());
            for _i in 0..(FILTER_DEPTH_MAX + 1) {
                inv_ldap = LdapFilter::And(vec![inv_ldap]);
            }

            let ev = Event::from_internal();

            // Test proto + read
            let res = Filter::from_ro(audit, &ev, &inv_proto, &r_txn);
            assert!(res == Err(OperationError::ResourceLimit));

            // ldap
            let res = Filter::from_ldap_ro(audit, &ev, &inv_ldap, &r_txn);
            assert!(res == Err(OperationError::ResourceLimit));

            // Can only have one db conn at a time.
            std::mem::drop(r_txn);

            // proto + write
            let wr_txn = server.write(duration_from_epoch_now());
            let res = Filter::from_rw(audit, &ev, &inv_proto, &wr_txn);
            assert!(res == Err(OperationError::ResourceLimit));
        })
    }

    #[test]
    fn test_filter_max_element_limits() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            const LIMIT: usize = 4;
            let r_txn = server.read();

            let inv_proto = ProtoFilter::And(
                (0..(LIMIT * 2))
                    .map(|_| ProtoFilter::Pres("class".to_string()))
                    .collect(),
            );

            let inv_ldap = LdapFilter::And(
                (0..(LIMIT * 2))
                    .map(|_| LdapFilter::Present("class".to_string()))
                    .collect(),
            );

            let mut ev = Event::from_internal();
            ev.limits.filter_max_elements = LIMIT;

            // Test proto + read
            let res = Filter::from_ro(audit, &ev, &inv_proto, &r_txn);
            assert!(res == Err(OperationError::ResourceLimit));

            // ldap
            let res = Filter::from_ldap_ro(audit, &ev, &inv_ldap, &r_txn);
            assert!(res == Err(OperationError::ResourceLimit));

            // Can only have one db conn at a time.
            std::mem::drop(r_txn);

            // proto + write
            let wr_txn = server.write(duration_from_epoch_now());
            let res = Filter::from_rw(audit, &ev, &inv_proto, &wr_txn);
            assert!(res == Err(OperationError::ResourceLimit));
        })
    }
}

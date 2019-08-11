// This represents a filtering query. This can be done
// in parallel map/reduce style, or directly on a single
// entry to assert it matches.

use crate::audit::AuditScope;
use crate::error::{OperationError, SchemaError};
use crate::event::{Event, EventOrigin};
use crate::proto::v1::Filter as ProtoFilter;
use crate::schema::SchemaTransaction;
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use crate::value::PartialValue;
use std::cmp::{Ordering, PartialOrd};
use std::collections::BTreeSet;

// Default filter is safe, ignores all hidden types!

// This is &Value so we can lazy static then clone, but perhaps we can reconsider
// later if this should just take Value.
#[allow(dead_code)]
pub fn f_eq<'a>(a: &'a str, v: PartialValue) -> FC<'a> {
    FC::Eq(a, v)
}

#[allow(dead_code)]
pub fn f_sub<'a>(a: &'a str, v: PartialValue) -> FC<'a> {
    FC::Sub(a, v)
}

#[allow(dead_code)]
pub fn f_pres<'a>(a: &'a str) -> FC<'a> {
    FC::Pres(a)
}

#[allow(dead_code)]
pub fn f_or<'a>(vs: Vec<FC<'a>>) -> FC<'a> {
    FC::Or(vs)
}

#[allow(dead_code)]
pub fn f_and<'a>(vs: Vec<FC<'a>>) -> FC<'a> {
    FC::And(vs)
}

#[allow(dead_code)]
pub fn f_andnot<'a>(fc: FC<'a>) -> FC<'a> {
    FC::AndNot(Box::new(fc))
}

#[allow(dead_code)]
pub fn f_self<'a>() -> FC<'a> {
    FC::SelfUUID
}

// This is the short-form for tests and internal filters that can then
// be transformed into a filter for the server to use.
#[derive(Debug, Deserialize)]
pub enum FC<'a> {
    Eq(&'a str, PartialValue),
    Sub(&'a str, PartialValue),
    Pres(&'a str),
    Or(Vec<FC<'a>>),
    And(Vec<FC<'a>>),
    AndNot(Box<FC<'a>>),
    SelfUUID,
    // Not(Box<FC>),
}

// This is the filters internal representation.
#[derive(Debug, Clone, PartialEq)]
enum FilterComp {
    // This is attr - value
    Eq(String, PartialValue),
    Sub(String, PartialValue),
    Pres(String),
    Or(Vec<FilterComp>),
    And(Vec<FilterComp>),
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
    // This is attr - value
    Eq(String, PartialValue),
    Sub(String, PartialValue),
    Pres(String),
    Or(Vec<FilterResolved>),
    And(Vec<FilterResolved>),
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

#[derive(Debug, Clone)]
pub struct Filter<STATE> {
    state: STATE,
}

impl Filter<FilterValidResolved> {
    // Does this need mut self? Aren't we returning
    // a new copied filter?
    pub fn optimise(&self) -> Self {
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

    pub fn resolve(&self, ev: &Event) -> Result<Filter<FilterValidResolved>, OperationError> {
        // Given a filter, resolve Not and SelfUUID to real terms.
        Ok(Filter {
            state: FilterValidResolved {
                inner: FilterResolved::resolve(self.state.inner.clone(), ev)
                    .ok_or(OperationError::FilterUUIDResolution)?,
            },
        })
    }

    pub fn get_attr_set(&self) -> BTreeSet<&str> {
        // Recurse through the filter getting an attribute set.
        let mut r_set: BTreeSet<&str> = BTreeSet::new();
        self.state.inner.get_attr_set(&mut r_set);
        r_set
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

    pub fn to_ignore_hidden(self) -> Self {
        // Destructure the former filter, and surround it with an ignore_hidden.
        Filter {
            state: FilterInvalid {
                inner: FilterComp::new_ignore_hidden(self.state.inner),
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

    pub fn to_recycled(self) -> Self {
        // Destructure the former filter and surround it with a recycled only query
        Filter {
            state: FilterInvalid {
                inner: FilterComp::new_recycled(self.state.inner),
            },
        }
    }

    #[cfg(test)]
    pub unsafe fn to_valid_resolved(self) -> Filter<FilterValidResolved> {
        // There is a good reason this function only exists in tests ...
        //
        // YOLO.
        // tl;dr - panic if there is a Self term because we don't have the QS
        // to resolve the uuid. Perhaps in the future we can provide a uuid
        // to this for the resolving to make it safer and test case usable.
        Filter {
            state: FilterValidResolved {
                inner: FilterResolved::from_invalid(self.state.inner),
            },
        }
    }

    #[cfg(test)]
    pub unsafe fn to_valid(self) -> Filter<FilterValid> {
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

    pub fn validate(&self, schema: &SchemaTransaction) -> Result<Filter<FilterValid>, SchemaError> {
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
        f: &ProtoFilter,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        Ok(Filter {
            state: FilterInvalid {
                inner: FilterComp::from_ro(audit, f, qs)?,
            },
        })
    }

    pub fn from_rw(
        audit: &mut AuditScope,
        f: &ProtoFilter,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(Filter {
            state: FilterInvalid {
                inner: FilterComp::from_rw(audit, f, qs)?,
            },
        })
    }
}

impl FilterComp {
    fn new(fc: FC) -> Self {
        match fc {
            FC::Eq(a, v) => FilterComp::Eq(a.to_string(), v),
            FC::Sub(a, v) => FilterComp::Sub(a.to_string(), v),
            FC::Pres(a) => FilterComp::Pres(a.to_string()),
            FC::Or(v) => FilterComp::Or(v.into_iter().map(|c| FilterComp::new(c)).collect()),
            FC::And(v) => FilterComp::And(v.into_iter().map(|c| FilterComp::new(c)).collect()),
            FC::AndNot(b) => FilterComp::AndNot(Box::new(FilterComp::new(*b))),
            FC::SelfUUID => FilterComp::SelfUUID,
        }
    }

    fn new_ignore_hidden(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::AndNot(Box::new(FilterComp::Or(vec![
                FilterComp::Eq("class".to_string(), PartialValue::new_iutf8("tombstone")),
                FilterComp::Eq("class".to_string(), PartialValue::new_iutf8("recycled")),
            ]))),
            fc,
        ])
    }

    fn new_recycled(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::Eq("class".to_string(), PartialValue::new_iutf8("recycled")),
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
            FilterComp::Or(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::And(vs) => vs.iter().for_each(|f| f.get_attr_set(r_set)),
            FilterComp::AndNot(f) => f.get_attr_set(r_set),
            FilterComp::SelfUUID => {
                r_set.insert("uuid");
            }
        }
    }

    pub fn validate(&self, schema: &SchemaTransaction) -> Result<FilterComp, SchemaError> {
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
                            .validate_partialvalue(&value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Eq(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            FilterComp::Sub(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema.normalise_attr_name(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        schema_a
                            .validate_partialvalue(&value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Sub(attr_norm, value.clone()))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
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
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            FilterComp::Or(filters) => {
                // If all filters are okay, return Ok(Filter::Or())
                // If any is invalid, return the error.
                // TODO: ftweedal says an empty or is a valid filter
                // in mathematical terms.
                if filters.len() == 0 {
                    return Err(SchemaError::EmptyFilter);
                };
                let x: Result<Vec<_>, _> = filters
                    .iter()
                    .map(|filter| filter.validate(schema))
                    .collect();
                // Now put the valid filters into the Filter
                x.map(|valid_filters| FilterComp::Or(valid_filters))
            }
            FilterComp::And(filters) => {
                // TODO: ftweedal says an empty or is a valid filter
                // in mathematical terms.
                if filters.len() == 0 {
                    return Err(SchemaError::EmptyFilter);
                };
                let x: Result<Vec<_>, _> = filters
                    .iter()
                    .map(|filter| filter.validate(schema))
                    .collect();
                // Now put the valid filters into the Filter
                x.map(|valid_filters| FilterComp::And(valid_filters))
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
    ) -> Result<Self, OperationError> {
        Ok(match f {
            ProtoFilter::Eq(a, v) => FilterComp::Eq(a.clone(), qs.clone_partialvalue(audit, a, v)?),
            ProtoFilter::Sub(a, v) => FilterComp::Sub(a.clone(), qs.clone_partialvalue(audit, a, v)?),
            ProtoFilter::Pres(a) => FilterComp::Pres(a.clone()),
            ProtoFilter::Or(l) => FilterComp::Or(
                l.iter()
                    .map(|f| Self::from_ro(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::And(l) => FilterComp::And(
                l.iter()
                    .map(|f| Self::from_ro(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::AndNot(l) => FilterComp::AndNot(Box::new(Self::from_ro(audit, l, qs)?)),
            ProtoFilter::SelfUUID => FilterComp::SelfUUID,
        })
    }

    fn from_rw(
        audit: &mut AuditScope,
        f: &ProtoFilter,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(match f {
            ProtoFilter::Eq(a, v) => FilterComp::Eq(a.clone(), qs.clone_partialvalue(audit, a, v)?),
            ProtoFilter::Sub(a, v) => FilterComp::Sub(a.clone(), qs.clone_partialvalue(audit, a, v)?),
            ProtoFilter::Pres(a) => FilterComp::Pres(a.clone()),
            ProtoFilter::Or(l) => FilterComp::Or(
                l.iter()
                    .map(|f| Self::from_rw(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::And(l) => FilterComp::And(
                l.iter()
                    .map(|f| Self::from_rw(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::AndNot(l) => FilterComp::AndNot(Box::new(Self::from_rw(audit, l, qs)?)),
            ProtoFilter::SelfUUID => FilterComp::SelfUUID,
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
            (FilterResolved::Eq(a1, v1), FilterResolved::Eq(a2, v2)) => a1 == a2 && v1 == v2,
            (FilterResolved::Sub(a1, v1), FilterResolved::Sub(a2, v2)) => a1 == a2 && v1 == v2,
            (FilterResolved::Pres(a1), FilterResolved::Pres(a2)) => a1 == a2,
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
            (FilterResolved::Eq(a1, v1), FilterResolved::Eq(a2, v2)) => {
                // Later this is how we will promote or demote values. We may
                // need to make this schema aware ...
                match a1.cmp(a2) {
                    Ordering::Equal => v1.cmp(v2),
                    o => o,
                }
            }
            (FilterResolved::Sub(a1, v1), FilterResolved::Sub(a2, v2)) => match a1.cmp(a2) {
                Ordering::Equal => v1.cmp(v2),
                o => o,
            },
            (FilterResolved::Pres(a1), FilterResolved::Pres(a2)) => a1.cmp(a2),
            (FilterResolved::Eq(_, _), _) => {
                // Always higher prefer Eq over all else, as these will have
                // the best indexes and return smallest candidates.
                Ordering::Less
            }
            (_, FilterResolved::Eq(_, _)) => Ordering::Greater,
            (FilterResolved::Pres(_), _) => Ordering::Less,
            (_, FilterResolved::Pres(_)) => Ordering::Greater,
            (FilterResolved::Sub(_, _), _) => Ordering::Greater,
            (_, FilterResolved::Sub(_, _)) => Ordering::Less,
            (_, _) => Ordering::Equal,
        }
    }
}

impl FilterResolved {
    #[cfg(test)]
    unsafe fn from_invalid(fc: FilterComp) -> Self {
        match fc {
            FilterComp::Eq(a, v) => FilterResolved::Eq(a, v),
            FilterComp::Sub(a, v) => FilterResolved::Sub(a, v),
            FilterComp::Pres(a) => FilterResolved::Pres(a),
            FilterComp::Or(vs) => FilterResolved::Or(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v))
                    .collect(),
            ),
            FilterComp::And(vs) => FilterResolved::And(
                vs.into_iter()
                    .map(|v| FilterResolved::from_invalid(v))
                    .collect(),
            ),
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::AndNot(Box::new(FilterResolved::from_invalid((*f).clone())))
            }
            FilterComp::SelfUUID => panic!("Not possible to resolve SelfUUID in from_invalid!"),
        }
    }

    fn resolve(fc: FilterComp, ev: &Event) -> Option<Self> {
        match fc {
            FilterComp::Eq(a, v) => Some(FilterResolved::Eq(a, v)),
            FilterComp::Sub(a, v) => Some(FilterResolved::Sub(a, v)),
            FilterComp::Pres(a) => Some(FilterResolved::Pres(a)),
            FilterComp::Or(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve(f, ev))
                    .collect();
                fi.map(|fv| FilterResolved::Or(fv))
            }
            FilterComp::And(vs) => {
                let fi: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|f| FilterResolved::resolve(f, ev))
                    .collect();
                fi.map(|fv| FilterResolved::And(fv))
            }
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::resolve((*f).clone(), ev)
                    .map(|fi| FilterResolved::AndNot(Box::new(fi)))
            }
            FilterComp::SelfUUID => match &ev.origin {
                EventOrigin::User(e) => Some(FilterResolved::Eq(
                    "uuid".to_string(),
                    PartialValue::new_uuid(e.get_uuid().clone()),
                )),
                _ => None,
            },
        }
    }

    fn optimise(&self) -> Self {
        // Most optimisations only matter around or/and terms.
        match self {
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
                f_list_and.into_iter().for_each(|fc| match fc {
                    FilterResolved::And(mut l) => f_list_new.append(&mut l),
                    _ => {}
                });

                // finally, optimise this list by sorting.
                f_list_new.sort_unstable();
                f_list_new.dedup();

                // return!
                FilterResolved::And(f_list_new)
            }
            FilterResolved::Or(f_list) => {
                let (f_list_or, mut f_list_new): (Vec<_>, Vec<_>) = f_list
                    .iter()
                    .map(|f_ref| f_ref.optimise())
                    .partition(|f| match f {
                        FilterResolved::Or(_) => true,
                        _ => false,
                    });

                f_list_or.into_iter().for_each(|fc| match fc {
                    FilterResolved::Or(mut l) => f_list_new.append(&mut l),
                    _ => {}
                });

                // sort, but reverse so that sub-optimal elements are later!
                f_list_new.sort_unstable_by(|a, b| b.cmp(a));
                f_list_new.dedup();

                FilterResolved::Or(f_list_new)
            }
            f => f.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryNew, EntryValid};
    use crate::filter::{Filter, FilterInvalid};
    use serde_json;
    use std::cmp::{Ordering, PartialOrd};
    use std::collections::BTreeSet;

    #[test]
    fn test_filter_simple() {
        // Test construction.
        let _filt: Filter<FilterInvalid> = filter!(f_eq("class", "user"));

        // AFTER
        let _complex_filt: Filter<FilterInvalid> = filter!(f_and!([
            f_or!([f_eq("userid", "test_a"), f_eq("userid", "test_b"),]),
            f_sub("class", "user"),
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
            let f_init_r = unsafe { f_init.to_valid_resolved() };
            let f_init_o = f_init_r.optimise();
            let f_init_e = unsafe { f_expect.to_valid_resolved() };
            println!("--");
            println!("init   --> {:?}", f_init_r);
            println!("opt    --> {:?}", f_init_o);
            println!("expect --> {:?}", f_init_e);
            assert!(f_init_o == f_init_e);
        }};
    }

    #[test]
    fn test_filter_optimise() {
        // Given sets of "optimisable" filters, optimise them.
        filter_optimise_assert!(
            f_and(vec![f_and(vec![f_eq("class", "test")])]),
            f_and(vec![f_eq("class", "test")])
        );

        filter_optimise_assert!(
            f_or(vec![f_or(vec![f_eq("class", "test")])]),
            f_or(vec![f_eq("class", "test")])
        );

        filter_optimise_assert!(
            f_and(vec![f_or(vec![f_and(vec![f_eq("class", "test")])])]),
            f_and(vec![f_or(vec![f_and(vec![f_eq("class", "test")])])])
        );

        // Later this can test duplicate filter detection.
        filter_optimise_assert!(
            f_and(vec![
                f_and(vec![f_eq("class", "test")]),
                f_sub("class", "te"),
                f_pres("class"),
                f_eq("class", "test")
            ]),
            f_and(vec![
                f_eq("class", "test"),
                f_pres("class"),
                f_sub("class", "te"),
            ])
        );

        // Test dedup removes only the correct element despite padding.
        filter_optimise_assert!(
            f_and(vec![
                f_and(vec![
                    f_eq("class", "foo"),
                    f_eq("class", "test"),
                    f_eq("uid", "bar"),
                ]),
                f_sub("class", "te"),
                f_pres("class"),
                f_eq("class", "test")
            ]),
            f_and(vec![
                f_eq("class", "foo"),
                f_eq("class", "test"),
                f_eq("uid", "bar"),
                f_pres("class"),
                f_sub("class", "te"),
            ])
        );

        filter_optimise_assert!(
            f_or(vec![
                f_eq("class", "test"),
                f_pres("class"),
                f_sub("class", "te"),
                f_or(vec![f_eq("class", "test")]),
            ]),
            f_or(vec![
                f_sub("class", "te"),
                f_pres("class"),
                f_eq("class", "test")
            ])
        );

        // Test dedup doesn't affect nested items incorrectly.
        filter_optimise_assert!(
            f_or(vec![
                f_eq("class", "test"),
                f_and(vec![
                    f_eq("class", "test"),
                    f_eq("term", "test"),
                    f_or(vec![f_eq("class", "test")])
                ]),
            ]),
            f_or(vec![
                f_and(vec![
                    f_eq("class", "test"),
                    f_eq("term", "test"),
                    f_or(vec![f_eq("class", "test")])
                ]),
                f_eq("class", "test"),
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
        let f_t3b = unsafe { filter_resolved!(f_eq("userid", "")) };
        assert_eq!(f_t1a.partial_cmp(&f_t3b), Some(Ordering::Greater));
        assert_eq!(f_t3b.partial_cmp(&f_t1a), Some(Ordering::Less));

        // transitivity: a < b and b < c implies a < c. The same must hold for both == and >.
        let f_t4b = unsafe { filter_resolved!(f_sub("userid", "")) };
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
    fn test_or_entry_filter() {
        let e: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "db237e8a-0079-4b8c-8a56-593b22aa44d1"
            },
            "state": null,
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = unsafe {
            filter_resolved!(f_or!([
                f_eq("userid", "william"),
                f_eq("uidnumber", "1000"),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = unsafe {
            filter_resolved!(f_or!([
                f_eq("userid", "william"),
                f_eq("uidnumber", "1001"),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t2a));

        let f_t3a = unsafe {
            filter_resolved!(f_or!([f_eq("userid", "alice"), f_eq("uidnumber", "1000"),]))
        };
        assert!(e.entry_match_no_index(&f_t3a));

        let f_t4a = unsafe {
            filter_resolved!(f_or!([f_eq("userid", "alice"), f_eq("uidnumber", "1001"),]))
        };
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_and_entry_filter() {
        let e: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "db237e8a-0079-4b8c-8a56-593b22aa44d1"
            },
            "state": null,
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = unsafe {
            filter_resolved!(f_and!([
                f_eq("userid", "william"),
                f_eq("uidnumber", "1000"),
            ]))
        };
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = unsafe {
            filter_resolved!(f_and!([
                f_eq("userid", "william"),
                f_eq("uidnumber", "1001"),
            ]))
        };
        assert!(!e.entry_match_no_index(&f_t2a));

        let f_t3a = unsafe {
            filter_resolved!(f_and!(
                [f_eq("userid", "alice"), f_eq("uidnumber", "1000"),]
            ))
        };
        assert!(!e.entry_match_no_index(&f_t3a));

        let f_t4a = unsafe {
            filter_resolved!(f_and!(
                [f_eq("userid", "alice"), f_eq("uidnumber", "1001"),]
            ))
        };
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_not_entry_filter() {
        let e1: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "db237e8a-0079-4b8c-8a56-593b22aa44d1"
            },
            "state": null,
            "attrs": {
                "userid": ["william"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = unsafe { filter_resolved!(f_andnot(f_eq("userid", "alice"))) };
        assert!(e1.entry_match_no_index(&f_t1a));

        let f_t2a = unsafe { filter_resolved!(f_andnot(f_eq("userid", "william"))) };
        assert!(!e1.entry_match_no_index(&f_t2a));
    }

    #[test]
    fn test_nested_entry_filter() {
        let e1: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "db237e8a-0079-4b8c-8a56-593b22aa44d1"
            },
            "state": null,
            "attrs": {
                "class": ["person"],
                "uuid": ["db237e8a-0079-4b8c-8a56-593b22aa44d1"],
                "uidnumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let e2: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "4b6228ab-1dbe-42a4-a9f5-f6368222438e"
            },
            "state": null,
            "attrs": {
                "class": ["person"],
                "uuid": ["4b6228ab-1dbe-42a4-a9f5-f6368222438e"],
                "uidnumber": ["1001"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let e3: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "7b23c99d-c06b-4a9a-a958-3afa56383e1d"
            },
            "state": null,
            "attrs": {
                "class": ["person"],
                "uuid": ["7b23c99d-c06b-4a9a-a958-3afa56383e1d"],
                "uidnumber": ["1002"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let e4: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": {
                "uuid": "21d816b5-1f6a-4696-b7c1-6ed06d22ed81"
            },
            "state": null,
            "attrs": {
                "class": ["group"],
                "uuid": ["21d816b5-1f6a-4696-b7c1-6ed06d22ed81"],
                "uidnumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = unsafe {
            filter_resolved!(f_and!([
                f_eq("class", "person"),
                f_or!([f_eq("uidnumber", "1001"), f_eq("uidnumber", "1000")])
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
        // Given filters, get their expected attribute sets.
        let f_t1a =
            unsafe { filter_valid!(f_and!([f_eq("userid", "alice"), f_eq("class", "1001"),])) };

        assert!(f_t1a.get_attr_set() == f_expect);

        let f_t2a = unsafe {
            filter_valid!(f_and!([
                f_eq("userid", "alice"),
                f_eq("class", "1001"),
                f_eq("userid", "claire"),
            ]))
        };

        assert!(f_t2a.get_attr_set() == f_expect);
    }
}

// This represents a filtering query. This can be done
// in parallel map/reduce style, or directly on a single
// entry to assert it matches.

use crate::audit::AuditScope;
use crate::error::{OperationError, SchemaError};
use crate::proto_v1::Filter as ProtoFilter;
use crate::schema::SchemaTransaction;
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use std::cmp::{Ordering, PartialOrd};

// Default filter is safe, ignores all hidden types!

pub fn f_eq<'a>(a: &'a str, v: &'a str) -> FC<'a> {
    FC::Eq(a, v)
}

pub fn f_sub<'a>(a: &'a str, v: &'a str) -> FC<'a> {
    FC::Sub(a, v)
}

pub fn f_pres<'a>(a: &'a str) -> FC<'a> {
    FC::Pres(a)
}

pub fn f_or<'a>(vs: Vec<FC<'a>>) -> FC<'a> {
    FC::Or(vs)
}

pub fn f_and<'a>(vs: Vec<FC<'a>>) -> FC<'a> {
    FC::And(vs)
}

pub fn f_andnot<'a>(fc: FC<'a>) -> FC<'a> {
    FC::AndNot(Box::new(fc))
}

pub fn f_self<'a>() -> FC<'a> {
    FC::SelfUUID
}

// This is the short-form for tests and internal filters that can then
// be transformed into a filter for the server to use.
#[derive(Debug, Deserialize)]
pub enum FC<'a> {
    Eq(&'a str, &'a str),
    Sub(&'a str, &'a str),
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
    Eq(String, String),
    Sub(String, String),
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
    Eq(String, String),
    Sub(String, String),
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
        self.clone()
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

    pub fn resolve(self) -> Result<Filter<FilterValidResolved>, OperationError> {
        unimplemented!();
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
        // YOLO.
        // tl;dr - panic if there is a Self term because we don't have the QS
        // to resolve the uuid. Perhaps in the future we can provide a uuid
        // to this for the resolving to make it safer ...
        //
        // Saying this, we COULD also use this chance to resolve name->uuid
        // instead of in the proto translation layer ...
        Filter {
            state: FilterValidResolved {
                inner: FilterResolved::from_invalid(self.state.inner),
            },
        }
    }

    #[cfg(test)]
    pub unsafe fn to_valid(self) -> Filter<FilterValid> {
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

    // TODO: This has to have two versions to account for ro/rw traits, because RS can't
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
            FC::Eq(a, v) => FilterComp::Eq(a.to_string(), v.to_string()),
            FC::Sub(a, v) => FilterComp::Sub(a.to_string(), v.to_string()),
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
                FilterComp::Eq("class".to_string(), "tombstone".to_string()),
                FilterComp::Eq("class".to_string(), "recycled".to_string()),
            ]))),
            fc,
        ])
    }

    fn new_recycled(fc: FilterComp) -> Self {
        FilterComp::And(vec![
            FilterComp::Eq("class".to_string(), "recycled".to_string()),
            fc,
        ])
    }

    pub fn validate(&self, schema: &SchemaTransaction) -> Result<FilterComp, SchemaError> {
        // TODO:
        // First, normalise (if possible)
        // Then, validate

        // Optimisation is done at another stage.

        // This probably needs some rework

        // TODO: Getting this each recursion could be slow. Maybe
        // we need an inner functon that passes the reference?
        let schema_attributes = schema.get_attributes();
        let schema_name = schema_attributes
            .get("name")
            .expect("Critical: Core schema corrupt or missing.");

        match self {
            FilterComp::Eq(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema_name.normalise_value(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        let value_norm = schema_a.normalise_value(value);
                        schema_a
                            .validate_value(&value_norm)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Eq(attr_norm, value_norm))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            FilterComp::Sub(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema_name.normalise_value(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        let value_norm = schema_a.normalise_value(value);
                        schema_a
                            .validate_value(&value_norm)
                            // Okay, it worked, transform to a filter component
                            .map(|_| FilterComp::Sub(attr_norm, value_norm))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            FilterComp::Pres(attr) => {
                let attr_norm = schema_name.normalise_value(attr);
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
            ProtoFilter::Eq(a, v) => FilterComp::Eq(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoFilter::Sub(a, v) => FilterComp::Sub(a.clone(), qs.clone_value(audit, a, v)?),
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
            ProtoFilter::Eq(a, v) => FilterComp::Eq(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoFilter::Sub(a, v) => FilterComp::Sub(a.clone(), qs.clone_value(audit, a, v)?),
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
            (FilterResolved::Or(l1), FilterResolved::Or(l2)) => l1 == l2,
            (FilterResolved::And(l1), FilterResolved::And(l2)) => l1 == l2,
            (FilterResolved::AndNot(l1), FilterResolved::AndNot(l2)) => l1 == l2,
            // Eq and Pres can attempt to match, but we don't want that ...
            (_, _) => false,
        }
    }
}

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
        match (self, rhs) {
            (FilterResolved::Eq(a1, _), FilterResolved::Eq(a2, _)) => {
                // Order attr name, then value
                // Later we may add rules to put certain attrs ahead due
                // to optimisation rules
                a1.partial_cmp(a2)
            }
            (FilterResolved::Sub(a1, _), FilterResolved::Sub(a2, _)) => a1.partial_cmp(a2),
            (FilterResolved::Pres(a1), FilterResolved::Pres(a2)) => a1.partial_cmp(a2),
            (FilterResolved::Eq(_, _), _) => {
                // Always higher prefer Eq over all else, as these will have
                // the best indexes and return smallest candidates.
                Some(Ordering::Less)
            }
            (_, FilterResolved::Eq(_, _)) => Some(Ordering::Greater),
            (FilterResolved::Pres(_), _) => Some(Ordering::Less),
            (_, FilterResolved::Pres(_)) => Some(Ordering::Greater),
            (FilterResolved::Sub(_, _), _) => Some(Ordering::Greater),
            (_, FilterResolved::Sub(_, _)) => Some(Ordering::Less),
            (_, _) => Some(Ordering::Equal),
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
                    .map(|v| unsafe { FilterResolved::from_invalid(v) })
                    .collect(),
            ),
            FilterComp::And(vs) => FilterResolved::And(
                vs.into_iter()
                    .map(|v| unsafe { FilterResolved::from_invalid(v) })
                    .collect(),
            ),
            FilterComp::AndNot(f) => {
                // TODO: pattern match box here. (AndNot(box f)).
                // We have to clone f into our space here because pattern matching can
                // not today remove the box, and we need f in our ownership. Since
                // AndNot currently is a rare request, cloning is not the worst thing
                // here ...
                FilterResolved::AndNot(Box::new(unsafe {
                    FilterResolved::from_invalid((*f).clone())
                }))
            }
            FilterComp::SelfUUID => panic!("Not possible to resolve SelfUUID in from_invalid!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryNew, EntryValid};
    use crate::filter::{Filter, FilterInvalid};
    use serde_json;
    use std::cmp::{Ordering, PartialOrd};

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

    #[test]
    fn test_filter_optimise() {
        // Given sets of "optimisable" filters, optimise them.
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
        let f_t2b = f_t1a.clone();
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
}

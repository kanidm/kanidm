// This represents a filtering query. This can be done
// in parallel map/reduce style, or directly on a single
// entry to assert it matches.

use crate::audit::AuditScope;
use crate::error::{OperationError, SchemaError};
use crate::proto_v1::Filter as ProtoFilter;
use crate::schema::SchemaReadTransaction;
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use std::cmp::{Ordering, PartialOrd};
use std::marker::PhantomData;

// Perhaps make these json serialisable. Certainly would make parsing
// simpler ...

#[derive(Debug)]
pub struct FilterValid;
#[derive(Debug)]
pub struct FilterInvalid;

#[derive(Debug)]
pub enum Filter<VALID> {
    // This is attr - value
    Eq(String, String),
    Sub(String, String),
    Pres(String),
    Or(Vec<Filter<VALID>>),
    And(Vec<Filter<VALID>>),
    AndNot(Box<Filter<VALID>>),
    Invalid(PhantomData<VALID>),
}

// Change this so you have RawFilter and Filter. RawFilter is the "builder", and then
// given a "schema" you can emit a Filter. For us internally, we can create Filter
// directly still ...

impl Filter<FilterValid> {
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

    pub fn invalidate(&self) -> Filter<FilterInvalid> {
        match self {
            Filter::Eq(a, v) => Filter::Eq(a.clone(), v.clone()),
            Filter::Sub(a, v) => Filter::Sub(a.clone(), v.clone()),
            Filter::Pres(a) => Filter::Pres(a.clone()),
            Filter::Or(l) => Filter::Or(l.iter().map(|f| f.invalidate()).collect()),
            Filter::And(l) => Filter::And(l.iter().map(|f| f.invalidate()).collect()),
            Filter::AndNot(l) => Filter::AndNot(Box::new(l.invalidate())),
            Filter::Invalid(_) => {
                // TODO: Is there a better way to not need to match the phantom?
                unimplemented!()
            }
        }
    }
}

impl Filter<FilterInvalid> {
    pub fn new_ignore_hidden(inner: Filter<FilterInvalid>) -> Self {
        // Create a new filter, that ignores hidden entries.
        Filter::And(vec![
            Filter::AndNot(Box::new(Filter::Or(vec![
                Filter::Eq("class".to_string(), "tombstone".to_string()),
                Filter::Eq("class".to_string(), "recycled".to_string()),
            ]))),
            inner,
        ])
    }

    pub fn new_recycled(inner: Filter<FilterInvalid>) -> Self {
        // Create a filter that searches recycled items only.
        Filter::And(vec![
            Filter::Eq("class".to_string(), "recycled".to_string()),
            inner,
        ])
    }

    pub fn validate(
        &self,
        schema: &SchemaReadTransaction,
    ) -> Result<Filter<FilterValid>, SchemaError> {
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
            Filter::Eq(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema_name.normalise_value(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        let value_norm = schema_a.normalise_value(value);
                        schema_a
                            .validate_value(&value_norm)
                            // Okay, it worked, transform to a filter component
                            .map(|_| Filter::Eq(attr_norm, value_norm))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            Filter::Sub(attr, value) => {
                // Validate/normalise the attr name.
                let attr_norm = schema_name.normalise_value(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(schema_a) => {
                        let value_norm = schema_a.normalise_value(value);
                        schema_a
                            .validate_value(&value_norm)
                            // Okay, it worked, transform to a filter component
                            .map(|_| Filter::Sub(attr_norm, value_norm))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            Filter::Pres(attr) => {
                let attr_norm = schema_name.normalise_value(attr);
                // Now check it exists
                match schema_attributes.get(&attr_norm) {
                    Some(_attr_name) => {
                        // Return our valid data
                        Ok(Filter::Pres(attr_norm))
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            Filter::Or(filters) => {
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
                x.map(|valid_filters| Filter::Or(valid_filters))
            }
            Filter::And(filters) => {
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
                x.map(|valid_filters| Filter::And(valid_filters))
            }
            Filter::AndNot(filter) => {
                // Just validate the inner
                filter
                    .validate(schema)
                    .map(|r_filter| Filter::AndNot(Box::new(r_filter)))
            }
            _ => panic!(),
        }
    }

    // TODO: This has to have two versions to account for ro/rw traits, because RS can't
    // monomorphise on the trait to call clone_value. An option is to make a fn that
    // takes "clone_value(t, a, v) instead, but that may have a similar issue.
    pub fn from_ro(
        audit: &mut AuditScope,
        f: &ProtoFilter,
        qs: &QueryServerTransaction,
    ) -> Result<Self, OperationError> {
        Ok(match f {
            ProtoFilter::Eq(a, v) => Filter::Eq(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoFilter::Sub(a, v) => Filter::Sub(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoFilter::Pres(a) => Filter::Pres(a.clone()),
            ProtoFilter::Or(l) => Filter::Or(
                l.iter()
                    .map(|f| Self::from_ro(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::And(l) => Filter::And(
                l.iter()
                    .map(|f| Self::from_ro(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::AndNot(l) => Filter::AndNot(Box::new(Self::from_ro(audit, l, qs)?)),
        })
    }

    pub fn from_rw(
        audit: &mut AuditScope,
        f: &ProtoFilter,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(match f {
            ProtoFilter::Eq(a, v) => Filter::Eq(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoFilter::Sub(a, v) => Filter::Sub(a.clone(), qs.clone_value(audit, a, v)?),
            ProtoFilter::Pres(a) => Filter::Pres(a.clone()),
            ProtoFilter::Or(l) => Filter::Or(
                l.iter()
                    .map(|f| Self::from_rw(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::And(l) => Filter::And(
                l.iter()
                    .map(|f| Self::from_rw(audit, f, qs))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ProtoFilter::AndNot(l) => Filter::AndNot(Box::new(Self::from_rw(audit, l, qs)?)),
        })
    }
}

impl Clone for Filter<FilterValid> {
    fn clone(&self) -> Self {
        // I think we only need to match self then new + clone?
        match self {
            Filter::Eq(a, v) => Filter::Eq(a.clone(), v.clone()),
            Filter::Sub(a, v) => Filter::Sub(a.clone(), v.clone()),
            Filter::Pres(a) => Filter::Pres(a.clone()),
            Filter::Or(l) => Filter::Or(l.clone()),
            Filter::And(l) => Filter::And(l.clone()),
            Filter::AndNot(l) => Filter::AndNot(l.clone()),
            Filter::Invalid(_) => {
                // TODO: Is there a better way to not need to match the phantom?
                unimplemented!()
            }
        }
    }
}

impl Clone for Filter<FilterInvalid> {
    fn clone(&self) -> Self {
        // I think we only need to match self then new + clone?
        match self {
            Filter::Eq(a, v) => Filter::Eq(a.clone(), v.clone()),
            Filter::Sub(a, v) => Filter::Sub(a.clone(), v.clone()),
            Filter::Pres(a) => Filter::Pres(a.clone()),
            Filter::Or(l) => Filter::Or(l.clone()),
            Filter::And(l) => Filter::And(l.clone()),
            Filter::AndNot(l) => Filter::AndNot(l.clone()),
            Filter::Invalid(_) => {
                // TODO: Is there a better way to not need to match the phantom?
                unimplemented!()
            }
        }
    }
}

impl PartialEq for Filter<FilterValid> {
    fn eq(&self, rhs: &Filter<FilterValid>) -> bool {
        match (self, rhs) {
            (Filter::Eq(a1, v1), Filter::Eq(a2, v2)) => a1 == a2 && v1 == v2,
            (Filter::Sub(a1, v1), Filter::Sub(a2, v2)) => a1 == a2 && v1 == v2,
            (Filter::Pres(a1), Filter::Pres(a2)) => a1 == a2,
            (Filter::Or(l1), Filter::Or(l2)) => l1 == l2,
            (Filter::And(l1), Filter::And(l2)) => l1 == l2,
            (Filter::AndNot(l1), Filter::AndNot(l2)) => l1 == l2,
            (_, _) => false,
        }
    }
}

// remember, this isn't ordering by alphanumeric, this is ordering of
// optimisation preference!
impl PartialOrd for Filter<FilterValid> {
    fn partial_cmp(&self, rhs: &Filter<FilterValid>) -> Option<Ordering> {
        match (self, rhs) {
            (Filter::Eq(a1, _), Filter::Eq(a2, _)) => {
                // Order attr name, then value
                // Later we may add rules to put certain attrs ahead due
                // to optimisation rules
                a1.partial_cmp(a2)
            }
            (Filter::Sub(a1, _), Filter::Sub(a2, _)) => a1.partial_cmp(a2),
            (Filter::Pres(a1), Filter::Pres(a2)) => a1.partial_cmp(a2),
            (Filter::Eq(_, _), _) => {
                // Always higher prefer Eq over all else, as these will have
                // the best indexes and return smallest candidates.
                Some(Ordering::Less)
            }
            (_, Filter::Eq(_, _)) => Some(Ordering::Greater),
            (Filter::Pres(_), _) => Some(Ordering::Less),
            (_, Filter::Pres(_)) => Some(Ordering::Greater),
            (Filter::Sub(_, _), _) => Some(Ordering::Greater),
            (_, Filter::Sub(_, _)) => Some(Ordering::Less),
            (_, _) => Some(Ordering::Equal),
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
        let _filt: Filter<FilterInvalid> = Filter::Eq(String::from("class"), String::from("user"));

        let _complex_filt: Filter<FilterInvalid> = Filter::And(vec![
            Filter::Or(vec![
                Filter::Eq(String::from("userid"), String::from("test_a")),
                Filter::Eq(String::from("userid"), String::from("test_b")),
            ]),
            Filter::Eq(String::from("class"), String::from("user")),
        ]);
    }

    #[test]
    fn test_filter_optimise() {
        // Given sets of "optimisable" filters, optimise them.
    }

    #[test]
    fn test_filter_eq() {
        let f_t1a = Filter::Pres(String::from("userid"));
        let f_t1b = Filter::Pres(String::from("userid"));
        let f_t1c = Filter::Pres(String::from("zzzz"));

        assert_eq!(f_t1a == f_t1b, true);
        assert_eq!(f_t1a == f_t1c, false);
        assert_eq!(f_t1b == f_t1c, false);

        let f_t2a = Filter::And(vec![f_t1a]);
        let f_t2b = Filter::And(vec![f_t1b]);
        let f_t2c = Filter::And(vec![f_t1c]);
        assert_eq!(f_t2a == f_t2b, true);
        assert_eq!(f_t2a == f_t2c, false);
        assert_eq!(f_t2b == f_t2c, false);

        assert_eq!(f_t2c == Filter::Pres(String::from("test")), false);
    }

    #[test]
    fn test_filter_ord() {
        // Test that we uphold the rules of partialOrd
        // Basic equality
        // Test the two major paths here (str vs list)
        let f_t1a = Filter::Pres(String::from("userid"));
        let f_t1b = Filter::Pres(String::from("userid"));

        assert_eq!(f_t1a.partial_cmp(&f_t1b), Some(Ordering::Equal));
        assert_eq!(f_t1b.partial_cmp(&f_t1a), Some(Ordering::Equal));

        let f_t2a = Filter::And(vec![]);
        let f_t2b = Filter::And(vec![]);
        assert_eq!(f_t2a.partial_cmp(&f_t2b), Some(Ordering::Equal));
        assert_eq!(f_t2b.partial_cmp(&f_t2a), Some(Ordering::Equal));

        // antisymmetry: if a < b then !(a > b), as well as a > b implying !(a < b); and
        let f_t3b = Filter::Eq(String::from("userid"), String::from(""));
        assert_eq!(f_t1a.partial_cmp(&f_t3b), Some(Ordering::Greater));
        assert_eq!(f_t3b.partial_cmp(&f_t1a), Some(Ordering::Less));

        // transitivity: a < b and b < c implies a < c. The same must hold for both == and >.
        let f_t4b = Filter::Sub(String::from("userid"), String::from(""));
        assert_eq!(f_t1a.partial_cmp(&f_t4b), Some(Ordering::Less));
        assert_eq!(f_t3b.partial_cmp(&f_t4b), Some(Ordering::Less));

        assert_eq!(f_t4b.partial_cmp(&f_t1a), Some(Ordering::Greater));
        assert_eq!(f_t4b.partial_cmp(&f_t3b), Some(Ordering::Greater));
    }

    #[test]
    fn test_filter_clone() {
        // Test that cloning filters yields the same result regardless of
        // complexity.
        let f_t1a = Filter::Pres(String::from("userid"));
        let f_t1b = f_t1a.clone();
        let f_t1c = Filter::Pres(String::from("zzzz"));

        assert_eq!(f_t1a == f_t1b, true);
        assert_eq!(f_t1a == f_t1c, false);

        let f_t2a = Filter::And(vec![f_t1a]);
        let f_t2b = f_t2a.clone();
        let f_t2c = Filter::And(vec![f_t1c]);

        assert_eq!(f_t2a == f_t2b, true);
        assert_eq!(f_t2a == f_t2c, false);
    }

    #[test]
    fn test_or_entry_filter() {
        let e: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "userid": ["william"],
                "uidNumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = Filter::Or(vec![
            Filter::Eq(String::from("userid"), String::from("william")),
            Filter::Eq(String::from("uidNumber"), String::from("1000")),
        ]);
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = Filter::Or(vec![
            Filter::Eq(String::from("userid"), String::from("william")),
            Filter::Eq(String::from("uidNumber"), String::from("1001")),
        ]);
        assert!(e.entry_match_no_index(&f_t2a));

        let f_t3a = Filter::Or(vec![
            Filter::Eq(String::from("userid"), String::from("alice")),
            Filter::Eq(String::from("uidNumber"), String::from("1000")),
        ]);
        assert!(e.entry_match_no_index(&f_t3a));

        let f_t4a = Filter::Or(vec![
            Filter::Eq(String::from("userid"), String::from("alice")),
            Filter::Eq(String::from("uidNumber"), String::from("1001")),
        ]);
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_and_entry_filter() {
        let e: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "userid": ["william"],
                "uidNumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = Filter::And(vec![
            Filter::Eq(String::from("userid"), String::from("william")),
            Filter::Eq(String::from("uidNumber"), String::from("1000")),
        ]);
        assert!(e.entry_match_no_index(&f_t1a));

        let f_t2a = Filter::And(vec![
            Filter::Eq(String::from("userid"), String::from("william")),
            Filter::Eq(String::from("uidNumber"), String::from("1001")),
        ]);
        assert!(!e.entry_match_no_index(&f_t2a));

        let f_t3a = Filter::And(vec![
            Filter::Eq(String::from("userid"), String::from("alice")),
            Filter::Eq(String::from("uidNumber"), String::from("1000")),
        ]);
        assert!(!e.entry_match_no_index(&f_t3a));

        let f_t4a = Filter::And(vec![
            Filter::Eq(String::from("userid"), String::from("alice")),
            Filter::Eq(String::from("uidNumber"), String::from("1001")),
        ]);
        assert!(!e.entry_match_no_index(&f_t4a));
    }

    #[test]
    fn test_not_entry_filter() {
        let e1: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "userid": ["william"],
                "uidNumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = Filter::AndNot(Box::new(Filter::Eq(
            String::from("userid"),
            String::from("alice"),
        )));
        assert!(e1.entry_match_no_index(&f_t1a));

        let f_t2a = Filter::AndNot(Box::new(Filter::Eq(
            String::from("userid"),
            String::from("william"),
        )));
        assert!(!e1.entry_match_no_index(&f_t2a));
    }

    #[test]
    fn test_nested_entry_filter() {
        let e1: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "uidNumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let e2: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "uidNumber": ["1001"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let e3: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "uidNumber": ["1002"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let e4: Entry<EntryValid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "uidNumber": ["1000"]
            }
        }"#,
        )
        .expect("Json parse failure");

        let f_t1a = Filter::And(vec![
            Filter::Eq(String::from("class"), String::from("person")),
            Filter::Or(vec![
                Filter::Eq(String::from("uidNumber"), String::from("1001")),
                Filter::Eq(String::from("uidNumber"), String::from("1000")),
            ]),
        ]);

        assert!(e1.entry_match_no_index(&f_t1a));
        assert!(e2.entry_match_no_index(&f_t1a));
        assert!(!e3.entry_match_no_index(&f_t1a));
        assert!(!e4.entry_match_no_index(&f_t1a));
    }
}

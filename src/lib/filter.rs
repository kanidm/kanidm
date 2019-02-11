// This represents a filtering query. This can be done
// in parallel map/reduce style, or directly on a single
// entry to assert it matches.

use error::SchemaError;
use proto_v1::Filter as ProtoFilter;
use regex::Regex;
use schema::{SchemaAttribute, SchemaClass, SchemaReadTransaction};
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
    Not(Box<Filter<VALID>>),
    invalid(PhantomData<VALID>),
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

    pub fn invalidate(self) -> Filter<FilterInvalid> {
        // Not used a lot, but probably a chance for improvement?
        unimplemented!()
    }
}

impl Filter<FilterInvalid> {
    pub fn validate(
        &self,
        schema: &SchemaReadTransaction,
    ) -> Result<Filter<FilterValid>, SchemaError> {
        // TODO:
        // First, normalise (if possible)
        // Then, validate

        // Optimisation is done at another stage.

        // This probably needs some rework

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
                            .validate_value(value)
                            // Okay, it worked, transform to a filter component
                            .map(|_| Filter::Eq(attr_norm, value_norm))
                        // On error, pass the error back out.
                    }
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            _ => unimplemented!(),
        }

        /*
        match self {
            Filter::Eq(attr, value) => match schema_attributes.get(attr) {
                Some(schema_a) => schema_a.validate_value(value),
                None => Err(SchemaError::InvalidAttribute),
            },
            Filter::Sub(attr, value) => match schema_attributes.get(attr) {
                Some(schema_a) => schema_a.validate_value(value),
                None => Err(SchemaError::InvalidAttribute),
            },
            Filter::Pres(attr) => {
                // This could be better as a contains_key
                // because we never use the value
                match schema_attributes.get(attr) {
                    Some(_) => Ok(()),
                    None => Err(SchemaError::InvalidAttribute),
                }
            }
            Filter::Or(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EmptyFilter);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate(filt)
                    } else {
                        acc
                    }
                })
            }
            Filter::And(filters) => {
                // This should never happen because
                // optimising should remove them as invalid parts?
                if filters.len() == 0 {
                    return Err(SchemaError::EmptyFilter);
                };
                filters.iter().fold(Ok(()), |acc, filt| {
                    if acc.is_ok() {
                        self.validate(filt)
                    } else {
                        acc
                    }
                })
            }
            Filter::Not(filter) => self.validate(filter),
        }
        */
    }

    pub fn from(f: &ProtoFilter) -> Self {
        unimplemented!()
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
            Filter::Not(l) => Filter::Not(l.clone()),
            Filter::invalid(_) => {
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
            Filter::Not(l) => Filter::Not(l.clone()),
            Filter::invalid(_) => {
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
            (Filter::Not(l1), Filter::Not(l2)) => l1 == l2,
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
    use super::{Filter, FilterValid, FilterInvalid};
    use entry::{Entry, EntryNew, EntryValid};
    use serde_json;
    use std::cmp::{Ordering, PartialOrd};

    #[test]
    fn test_filter_simple() {
        let filt: Filter<FilterInvalid> = Filter::Eq(String::from("class"), String::from("user"));

        let complex_filt: Filter<FilterInvalid> = Filter::And(vec![
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
        .unwrap();

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

        let f_t3a: Filter<FilterInvalid> = Filter::Or(vec![
            Filter::Eq(String::from("userid"), String::from("alice")),
            Filter::Eq(String::from("uidNumber"), String::from("1000")),
        ]);
        assert!(e.entry_match_no_index(&f_t2a));

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
        .unwrap();

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
        .unwrap();

        let f_t1a = Filter::Not(Box::new(Filter::Eq(
            String::from("userid"),
            String::from("alice"),
        )));
        assert!(e1.entry_match_no_index(&f_t1a));

        let f_t2a = Filter::Not(Box::new(Filter::Eq(
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
        .unwrap();

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
        .unwrap();

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
        .unwrap();

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
        .unwrap();

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

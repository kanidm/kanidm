// This represents a filtering query. This can be done
// in parallel map/reduce style, or directly on a single
// entry to assert it matches.

use super::entry::Entry;

// Perhaps make these json serialisable. Certainly would make parsing
// simpler ...

#[derive(Serialize, Deserialize, Debug)]
pub enum Filter {
    // This is attr - value
    Eq(String, String),
    Sub(String, String),
    Pres(String, String),
    Or(Vec<Filter>),
    And(Vec<Filter>),
    Not(Vec<Filter>),
}

impl Filter {
    fn optimise(mut self) -> Self {
        // Apply optimisations to the filter
        self
    }

    // In the future this will probably be used with schema ...
    fn validate(mut self) -> Result<(), ()> {
        Ok(())
    }

    // This is probably not safe, so it's for internal test cases
    // only because I'm familiar with the syntax ... you have been warned.
    fn from_ldap_string(ldap_string: String) -> Result<Self, ()> {
        // For now return an empty filters
        Ok(Filter::And(Vec::new()))
    }

    // What other parse types do we need?

    // Assert if this filter matches the entry (no index)
    pub fn entry_match_no_index(e: Entry) -> bool {
        // Go through the filter components and check them in the entry.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Filter;
    use serde_json;

    #[test]
    fn test_filter_simple() {
        let filt = Filter::Eq(String::from("class"), String::from("user"));
        let j = serde_json::to_string_pretty(&filt);
        println!("{}", j.unwrap());

        let complex_filt = Filter::And(vec![
            Filter::Or(vec![
                Filter::Eq(String::from("userid"), String::from("test_a")),
                Filter::Eq(String::from("userid"), String::from("test_b")),
            ]),
            Filter::Eq(String::from("class"), String::from("user")),
        ]);
        let y = serde_json::to_string_pretty(&complex_filt);
        println!("{}", y.unwrap());
    }

    #[test]
    fn test_filter_optimise() {
        // Given sets of "optimisable" filters, optimise them.
    }
}

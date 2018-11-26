use super::entry::Entry;
use super::filter::Filter;

// These proto implementations are here because they have public definitions

// FIXME: We probably need a proto entry to transform our
// server core entry into.

// FIXME: Proto Response as well here

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    pub filter: Filter,
}

impl SearchRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRequest { filter: filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    pub entries: Vec<Entry>,
}

impl CreateRequest {
    pub fn new(entries: Vec<Entry>) -> Self {
        CreateRequest { entries: entries }
    }
}

// use super::entry::Entry;
use super::filter::Filter;
use std::collections::BTreeMap;

// These proto implementations are here because they have public definitions

// FIXME: We probably need a proto entry to transform our
// server core entry into. We also need to get from proto
// entry to our actual entry.
//
// There is agood future reason for this seperation. It allows changing
// the in memory server core entry type, without affecting the proto

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub attrs: BTreeMap<String, Vec<String>>,
}

// FIXME: Do I need proto filter?
// Probably yes, don't be shit william.

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    // ?
}

impl Response {
    pub fn new(_: ()) -> Self {
        Response {}
    }
}

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
pub struct SearchResponse {
    pub entries: Vec<Entry>,
}

impl SearchResponse {
    pub fn new(entries: Vec<Entry>) -> Self {
        SearchResponse { entries: entries }
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

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

// Login is a multi-step process potentially. First the client says who they
// want to request
//
// we respond with a set of possible authentications that can proceed, and perhaps
// we indicate which options must/may?
//
// The client can then step and negotiate each.
//
// This continues until a LoginSuccess, or LoginFailure is returned.
//
// On loginSuccess, we send a cookie, and that allows the token to be
// generated. The cookie can be shared between servers.

// Request auth for identity X
pub struct AuthRequest {}

// Respond with the list of auth types and nonce, etc.
pub struct AuthResponse {}

// Provide responses
pub struct AuthProvide {}

// After authprovide, we can move to AuthResponse (for more)
// or below ...

// Go away.
// Provide reason?
pub struct AuthDenied {}

// Welcome friend.
// On success provide entry "self", for group assertions?
pub struct AuthSuccess {}

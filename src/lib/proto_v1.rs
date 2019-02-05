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

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub filter: Filter,
}

impl DeleteRequest {
    pub fn new(filter: Filter) -> Self {
        DeleteRequest { filter: filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifyRequest {
    // Probably needs a modlist?
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



#[derive(Debug, Serialize, Deserialize)]
pub enum AuthState {
    Init(String, Vec<String>),
    /*
    Step(
        Type(params ....)
    ),
    */
}

// Request auth for identity X with roles Y?
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub state: AuthState
}

// Respond with the list of auth types and nonce, etc.
// It can also contain a denied, or success.
#[derive(Debug, Serialize, Deserialize)]
pub enum AuthStatus {
    Begin(String), // uuid of this session.
    // Continue, // Keep going, here are the things you could still provide ...
    // Go away, you made a mistake somewhere.
    // Provide reason?
    // Denied(String),
    // Welcome friend.
    // On success provide entry "self", for group assertions?
    // We also provide the "cookie"/token?
    // Success(String, Entry),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub status: AuthStatus,
}


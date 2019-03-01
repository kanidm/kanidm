// use super::entry::Entry;
// use super::filter::Filter;
use actix::prelude::*;
use error::OperationError;
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Filter {
    // This is attr - value
    Eq(String, String),
    Sub(String, String),
    Pres(String),
    Or(Vec<Filter>),
    And(Vec<Filter>),
    AndNot(Box<Filter>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Modify {
    Present(String, String),
    Removed(String, String),
    Purged(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModifyList {
    pub mods: Vec<Modify>,
}

impl ModifyList {
    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList { mods: mods }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationResponse {}

impl OperationResponse {
    pub fn new(_: ()) -> Self {
        OperationResponse {}
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

impl Message for SearchRequest {
    type Result = Result<SearchResponse, OperationError>;
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

impl Message for CreateRequest {
    type Result = Result<OperationResponse, OperationError>;
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

impl Message for DeleteRequest {
    type Result = Result<OperationResponse, OperationError>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifyRequest {
    // Probably needs a modlist?
    pub filter: Filter,
    pub modlist: ModifyList,
}

impl ModifyRequest {
    pub fn new(filter: Filter, modlist: ModifyList) -> Self {
        ModifyRequest {
            filter: filter,
            modlist: modlist,
        }
    }
}

impl Message for ModifyRequest {
    type Result = Result<OperationResponse, OperationError>;
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
    pub state: AuthState,
}

impl Message for AuthRequest {
    type Result = Result<OperationResponse, OperationError>;
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

/* Recycle Requests area */

// Only two actions on recycled is possible. Search and Revive.

pub struct SearchRecycledRequest {
    pub filter: Filter,
}

impl SearchRecycledRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRecycledRequest { filter: filter }
    }
}

// Need a search response here later.

pub struct ReviveRecycledRequest {
    pub filter: Filter,
}

impl ReviveRecycledRequest {
    pub fn new(filter: Filter) -> Self {
        ReviveRecycledRequest { filter: filter }
    }
}

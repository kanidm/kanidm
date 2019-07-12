// use super::entry::Entry;
// use super::filter::Filter;
use crate::error::OperationError;
use actix::prelude::*;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) mod actors;
pub mod client;
pub(crate) mod messages;

// These proto implementations are here because they have public definitions

/* ===== higher level types ===== */
// These are all types that are conceptually layers ontop of entry and
// friends. They allow us to process more complex requests and provide
// domain specific fields for the purposes of IDM, over the normal
// entry/ava/filter types. These related deeply to schema.

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub name: String,
    pub uuid: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claim {
    pub name: String,
    pub uuid: String,
    // These can be ephemeral, or shortlived in a session.
    // some may even need requesting.
    // pub expiry: DateTime
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Application {
    pub name: String,
    pub uuid: String,
}

// The currently authenticated user, and any required metadata for them
// to properly authorise them. This is similar in nature to oauth and the krb
// PAC/PAD structures. Currently we only use this internally, but we should
// consider making it "parseable" by the client so they can have per-session
// group/authorisation data.
//
// This structure and how it works will *very much* change over time from this
// point onward!
//
// It's likely that this must have a relationship to the server's user structure
// and to the Entry so that filters or access controls can be applied.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserAuthToken {
    // When this data should be considered invalid. Interpretation
    // may depend on the client application.
    // pub expiry: DateTime,
    pub name: String,
    pub displayname: String,
    pub uuid: String,
    pub application: Option<Application>,
    pub groups: Vec<Group>,
    pub claims: Vec<Claim>,
    // Should we allow supplemental ava's to be added on request?
}

// UAT will need a downcast to Entry, which adds in the claims to the entry
// for the purpose of filtering.

/* ===== low level proto types ===== */

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
    #[serde(rename = "Self")]
    SelfUUID,
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
    pub user_uuid: String,
}

impl SearchRequest {
    pub fn new(filter: Filter, user_uuid: &str) -> Self {
        SearchRequest {
            filter: filter,
            user_uuid: user_uuid.to_string(),
        }
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
    pub user_uuid: String,
}

impl CreateRequest {
    pub fn new(entries: Vec<Entry>, user_uuid: &str) -> Self {
        CreateRequest {
            entries: entries,
            user_uuid: user_uuid.to_string(),
        }
    }
}

impl Message for CreateRequest {
    type Result = Result<OperationResponse, OperationError>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub filter: Filter,
    pub user_uuid: String,
}

impl DeleteRequest {
    pub fn new(filter: Filter, user_uuid: &str) -> Self {
        DeleteRequest {
            filter: filter,
            user_uuid: user_uuid.to_string(),
        }
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
    pub user_uuid: String,
}

impl ModifyRequest {
    pub fn new(filter: Filter, modlist: ModifyList, user_uuid: &str) -> Self {
        ModifyRequest {
            filter: filter,
            modlist: modlist,
            user_uuid: user_uuid.to_string(),
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
pub enum AuthCredential {
    Anonymous,
    Password(String),
    // TOTP(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthStep {
    // name, application id?
    Init(String, Option<String>),
    /*
    Step(
        Type(params ....)
    ),
    */
    Creds(Vec<AuthCredential>),
    // Should we have a "finalise" type to attempt to finish based on
    // what we have given?
}

// Request auth for identity X with roles Y?
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub step: AuthStep,
}

// Respond with the list of auth types and nonce, etc.
// It can also contain a denied, or success.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum AuthAllowed {
    Anonymous,
    Password,
    // TOTP,
    // Webauthn(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthState {
    // Everything is good, your cookie has been issued, and a token is set here
    // for the client to view.
    Success(UserAuthToken),
    // Something was bad, your session is terminated and no cookie.
    Denied,
    // Continue to auth, allowed mechanisms listed.
    Continue(Vec<AuthAllowed>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    // TODO: Consider moving to an AuthMessageResponse type, and leave the proto
    // without the session id because it's not necesary to know.
    pub sessionid: Uuid,
    pub state: AuthState,
}

/* Recycle Requests area */

// Only two actions on recycled is possible. Search and Revive.

pub struct SearchRecycledRequest {
    pub filter: Filter,
    pub user_uuid: String,
}

impl SearchRecycledRequest {
    pub fn new(filter: Filter, user_uuid: &str) -> Self {
        SearchRecycledRequest {
            filter: filter,
            user_uuid: user_uuid.to_string(),
        }
    }
}

// Need a search response here later.

pub struct ReviveRecycledRequest {
    pub filter: Filter,
    pub user_uuid: String,
}

impl ReviveRecycledRequest {
    pub fn new(filter: Filter, user_uuid: &str) -> Self {
        ReviveRecycledRequest {
            filter: filter,
            user_uuid: user_uuid.to_string(),
        }
    }
}

// This doesn't need seralise because it's only accessed via a "get".
#[derive(Debug)]
pub struct WhoamiRequest {}

impl WhoamiRequest {
    pub fn new() -> Self {
        WhoamiRequest {}
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoamiResponse {
    // Should we just embed the entry? Or destructure it?
    pub youare: Entry,
}

impl WhoamiResponse {
    pub fn new(e: Entry) -> Self {
        WhoamiResponse { youare: e }
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::v1::Filter as ProtoFilter;
    #[test]
    fn test_protofilter_simple() {
        let pf: ProtoFilter = ProtoFilter::Pres("class".to_string());

        println!("{:?}", serde_json::to_string(&pf).expect("JSON failure"));
    }
}

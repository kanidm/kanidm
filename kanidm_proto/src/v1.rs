use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;
// use zxcvbn::feedback;

// These proto implementations are here because they have public definitions

/* ===== errors ===== */

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum SchemaError {
    NotImplemented,
    InvalidClass,
    MissingMustAttribute(String),
    InvalidAttribute,
    InvalidAttributeSyntax,
    EmptyFilter,
    Corrupted,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum PluginError {
    AttrUnique(String),
    Base(String),
    ReferentialIntegrity(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ConsistencyError {
    Unknown,
    // Class, Attribute
    SchemaClassMissingAttribute(String, String),
    QueryServerSearchFailure,
    EntryUuidCorrupt(u64),
    UuidIndexCorrupt(String),
    UuidNotUnique(String),
    RefintNotUpheld(u64),
    MemberOfInvalid(u64),
    InvalidAttributeType(String),
    DuplicateUniqueAttribute(String),
    InvalidSPN(u64),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum OperationError {
    EmptyRequest,
    Backend,
    NoMatchingEntries,
    CorruptedEntry(u64),
    ConsistencyError(Vec<Result<(), ConsistencyError>>),
    SchemaViolation(SchemaError),
    Plugin(PluginError),
    FilterGeneration,
    FilterUUIDResolution,
    InvalidAttributeName(String),
    InvalidAttribute(String),
    InvalidDBState,
    InvalidEntryID,
    InvalidRequestState,
    InvalidState,
    InvalidEntryState,
    InvalidUuid,
    InvalidACPState(String),
    InvalidSchemaState(String),
    InvalidAccountState(String),
    BackendEngine,
    SQLiteError, //(RusqliteError)
    FsError,
    SerdeJsonError,
    SerdeCborError,
    AccessDenied,
    NotAuthenticated,
    InvalidAuthState(String),
    InvalidSessionState,
    SystemProtectedObject,
    SystemProtectedAttribute,
    PasswordTooWeak,
    PasswordTooShort(usize),
    PasswordEmpty,
    PasswordBadListed,
}

impl PartialEq for OperationError {
    fn eq(&self, other: &Self) -> bool {
        // We do this to avoid InvalidPassword being checked as it's not
        // derive PartialEq. Generally we only use the PartialEq for TESTING
        // anyway.
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

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

impl fmt::Display for UserAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "display: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "groups: {:?}", self.groups)?;
        writeln!(f, "claims: {:?}", self.claims)
    }
}

// UAT will need a downcast to Entry, which adds in the claims to the entry
// for the purpose of filtering.

// This is similar to uat, but omits claims (they have no role in radius), and adds
// the radius secret field.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RadiusAuthToken {
    pub name: String,
    pub displayname: String,
    pub uuid: String,
    pub secret: String,
    pub groups: Vec<Group>,
}

impl fmt::Display for RadiusAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "display: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "secret: {}", self.secret)?;
        writeln!(f, "groups: {:?}", self.groups)
    }
}

/* ===== low level proto types ===== */

// ProtoEntry vs Entry
// There is a good future reason for this seperation. It allows changing
// the in memory server core entry type, without affecting the protoEntry type
//

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub attrs: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
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
        ModifyList { mods }
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
        SearchRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
}

impl SearchResponse {
    pub fn new(entries: Vec<Entry>) -> Self {
        SearchResponse { entries }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    pub entries: Vec<Entry>,
}

impl CreateRequest {
    pub fn new(entries: Vec<Entry>) -> Self {
        CreateRequest { entries }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub filter: Filter,
}

impl DeleteRequest {
    pub fn new(filter: Filter) -> Self {
        DeleteRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifyRequest {
    // Probably needs a modlist?
    pub filter: Filter,
    pub modlist: ModifyList,
}

impl ModifyRequest {
    pub fn new(filter: Filter, modlist: ModifyList) -> Self {
        ModifyRequest { filter, modlist }
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
    // Webauthn(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthState {
    // Everything is good, your cookie has been issued, and a token is set here
    // for the client to view.
    Success(UserAuthToken),
    // Something was bad, your session is terminated and no cookie.
    Denied(String),
    // Continue to auth, allowed mechanisms listed.
    Continue(Vec<AuthAllowed>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub sessionid: Uuid,
    pub state: AuthState,
}

// Types needed for setting credentials
#[derive(Debug, Serialize, Deserialize)]
pub enum SetAuthCredential {
    Password(String),
    GeneratePassword,
    // TOTP()
    // Webauthn(response)
}

/* Recycle Requests area */

// Only two actions on recycled is possible. Search and Revive.

pub struct SearchRecycledRequest {
    pub filter: Filter,
}

impl SearchRecycledRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRecycledRequest { filter }
    }
}

// Need a search response here later.

pub struct ReviveRecycledRequest {
    pub filter: Filter,
}

impl ReviveRecycledRequest {
    pub fn new(filter: Filter) -> Self {
        ReviveRecycledRequest { filter }
    }
}

// This doesn't need seralise because it's only accessed via a "get".
#[derive(Debug, Default)]
pub struct WhoamiRequest {}

impl WhoamiRequest {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoamiResponse {
    // Should we just embed the entry? Or destructure it?
    pub youare: Entry,
    pub uat: UserAuthToken,
}

impl WhoamiResponse {
    pub fn new(e: Entry, uat: UserAuthToken) -> Self {
        WhoamiResponse { youare: e, uat }
    }
}

// Simple string value provision.
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleStringRequest {
    pub value: String,
}

impl SingleStringRequest {
    pub fn new(s: String) -> Self {
        SingleStringRequest { value: s }
    }
}
// Use OperationResponse here ...

#[cfg(test)]
mod tests {
    use crate::v1::Filter as ProtoFilter;
    #[test]
    fn test_protofilter_simple() {
        let pf: ProtoFilter = ProtoFilter::Pres("class".to_string());

        println!("{:?}", serde_json::to_string(&pf).expect("JSON failure"));
    }
}

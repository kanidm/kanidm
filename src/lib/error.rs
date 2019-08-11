//use rusqlite::Error as RusqliteError;

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
pub enum OperationError {
    EmptyRequest,
    Backend,
    NoMatchingEntries,
    CorruptedEntry,
    ConsistencyError(Vec<Result<(), ConsistencyError>>),
    SchemaViolation(SchemaError),
    Plugin,
    FilterGeneration,
    FilterUUIDResolution,
    InvalidAttributeName(String),
    InvalidAttribute(&'static str),
    InvalidDBState,
    InvalidEntryID,
    InvalidRequestState,
    InvalidState,
    InvalidEntryState,
    InvalidACPState(&'static str),
    InvalidSchemaState(&'static str),
    InvalidAccountState(&'static str),
    BackendEngine,
    SQLiteError, //(RusqliteError)
    FsError,
    SerdeJsonError,
    SerdeCborError,
    AccessDenied,
    NotAuthenticated,
    InvalidAuthState(&'static str),
    InvalidSessionState,
    SystemProtectedObject,
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
}

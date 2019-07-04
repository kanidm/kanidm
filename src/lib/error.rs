//use rusqlite::Error as RusqliteError;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum SchemaError {
    NotImplemented,
    InvalidClass,
    // FIXME: Is there a way to say what we are missing on error?
    // Yes, add a string on the enum.
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
    ConsistencyError(Vec<Result<(), ConsistencyError>>),
    SchemaViolation(SchemaError),
    Plugin,
    FilterGeneration,
    FilterUUIDResolution,
    InvalidDBState,
    InvalidEntryID,
    InvalidRequestState,
    InvalidState,
    InvalidEntryState,
    InvalidACPState,
    InvalidAccountState(&'static str),
    BackendEngine,
    SQLiteError, //(RusqliteError)
    FsError,
    SerdeJsonError,
    AccessDenied,
    NotAuthenticated,
    InvalidAuthState(&'static str),
    InvalidSessionState,
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

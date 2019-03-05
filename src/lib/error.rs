// use rusqlite::Error as RusqliteError;

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
    SchemaViolation(SchemaError),
    Plugin,
    FilterGeneration,
    InvalidDBState,
    InvalidRequestState,
    InvalidState,
    InvalidEntryState,
    BackendEngine,
}

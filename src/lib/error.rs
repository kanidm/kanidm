#[derive(Debug, PartialEq)]
pub enum SchemaError {
    NotImplemented,
    InvalidClass,
    // FIXME: Is there a way to say what we are missing on error?
    // Yes, add a string on the enum.
    MissingMustAttribute,
    InvalidAttribute,
    InvalidAttributeSyntax,
    EmptyFilter,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum OperationError {
    EmptyRequest,
    Backend,
    SchemaViolation,
    Plugin,
    FilterGeneration,
}

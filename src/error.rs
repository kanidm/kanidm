#[derive(Debug, PartialEq)]
pub enum SchemaError {
    NOT_IMPLEMENTED,
    INVALID_CLASS,
    // FIXME: Is there a way to say what we are missing on error?
    MISSING_MUST_ATTRIBUTE,
    INVALID_ATTRIBUTE,
    INVALID_ATTRIBUTE_SYNTAX,
}

#[derive(Debug, PartialEq)]
pub enum SchemaError {
    NotImplemented,
    InvalidClass,
    // FIXME: Is there a way to say what we are missing on error?
    MissingMustAttribute,
    InvalidAttribute,
    InvalidAttributeSyntax,
    EmptyFilter,
}

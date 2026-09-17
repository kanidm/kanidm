#[derive(Debug)]
pub enum Error {
    Provider,
    TimeConversion,

    IdpError,

    Cryptography,
    SerdeJson,
    Parse,
    Sqlite,
    TooManyResults,
    TransactionInvalidState,
    Tpm,
}

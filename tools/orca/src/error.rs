pub enum Error {
    Io,
    SerdeToml,
    SerdeJson,
    KanidmClient,
    ProfileBuilder,
    Tokio,
    Interrupt,
    Crossbeam,
    InvalidState,
    InvalidInput(String),
}

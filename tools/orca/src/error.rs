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
    #[allow(dead_code)]
    RandomNumber(String),
}

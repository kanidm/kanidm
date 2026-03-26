#[derive(Debug)]
pub enum ModuleError {
    Io(String),
    Config(String),
    Http(String),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "IO Error: {s}"),
            Self::Config(s) => write!(f, "Config Error: {s}"),
            Self::Http(s) => write!(f, "HTTP Error: {s}"),
        }
    }
}

impl std::error::Error for ModuleError {}

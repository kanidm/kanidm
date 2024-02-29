use std::path::PathBuf;

/// Generates the integrity hash for a file based on a filename
pub fn generate_integrity_hash(filename: String) -> Result<String, String> {
    let wasm_filepath = PathBuf::from(filename);
    match wasm_filepath.exists() {
        false => Err(format!(
            "Can't find {:?} to generate file hash",
            &wasm_filepath
        )),
        true => {
            let filecontents = match std::fs::read(&wasm_filepath) {
                Ok(value) => value,
                Err(error) => {
                    return Err(format!(
                        "Failed to read {:?}, skipping: {:?}",
                        wasm_filepath, error
                    ));
                }
            };
            let shasum = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), &filecontents)
                .map_err(|_| {
                    format!(
                        "Failed to generate SHA384 hash for WASM at {:?}",
                        wasm_filepath
                    )
                })?;
            Ok(openssl::base64::encode_block(&shasum))
        }
    }
}

#[derive(Clone)]
pub struct JavaScriptFile {
    // Relative to the pkg/ dir
    pub filepath: &'static str,
    // Dynamic
    pub dynamic: bool,
    // SHA384 hash of the file
    pub hash: String,
    // if it's a module add the "type"
    pub filetype: Option<String>,
}

impl JavaScriptFile {
    /// returns a `<script>` or `<meta>` HTML tag
    pub fn as_tag(&self) -> String {
        let filetype = match &self.filetype {
            Some(val) => {
                format!(" type=\"{}\"", val.as_str())
            }
            _ => String::from(""),
        };
        if self.dynamic {
            format!(
                r#"<meta async src="/pkg/{}" integrity="sha384-{}"{} />"#,
                self.filepath, &self.hash, &filetype,
            )
        } else {
            format!(
                r#"<script async src="/pkg/{}" integrity="sha384-{}"{}></script>"#,
                self.filepath, &self.hash, &filetype,
            )
        }
    }
}

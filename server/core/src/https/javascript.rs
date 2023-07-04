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
            #[allow(clippy::expect_used)]
            let shasum = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), &filecontents)
                .expect("Failed to build hash of file");
            Ok(openssl::base64::encode_block(&shasum))
        }
    }
}

#[derive(Clone)]
pub struct JavaScriptFile {
    // Relative to the pkg/ dir
    pub filepath: &'static str,
    // SHA384 hash of the file
    pub hash: String,
    // if it's a module add the "type"
    pub filetype: Option<String>,
}

impl JavaScriptFile {
    /// return the hash for use in CSP headers
    // pub fn as_csp_hash(self) -> String {
    //     self.hash
    // }
    /// returns a `<script>` HTML tag
    pub fn as_tag(&self) -> String {
        let typeattr = match &self.filetype {
            Some(val) => {
                format!(" type=\"{}\"", val.as_str())
            }
            _ => String::from(""),
        };
        format!(
            r#"<script src="/pkg/{}" integrity="sha384-{}"{}></script>"#,
            self.filepath, &self.hash, &typeattr,
        )
    }
}

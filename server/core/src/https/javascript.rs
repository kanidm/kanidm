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
    // SHA384 hash of the file
    pub hash: String,
}

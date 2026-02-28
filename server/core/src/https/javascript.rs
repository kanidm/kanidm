use base64::{engine::general_purpose, Engine as _};
use crypto_glue::{s384::Sha384, traits::Digest};
use std::path::PathBuf;

/// Generates the integrity hash for a file based on a filename
pub fn generate_integrity_hash(filename: String) -> Result<String, String> {
    let filepath = PathBuf::from(filename);
    match filepath.exists() {
        false => Err(format!("Can't find {:?} to generate file hash", &filepath)),
        true => std::fs::read(&filepath)
            .map(|value| hash_content(&value))
            .map_err(|err| {
                error!(?err);
                format!("Failed to read {filepath:?}, skipping: {err:?}")
            }),
    }
}

fn hash_content(content: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(content);
    let shasum = hasher.finalize();

    general_purpose::STANDARD.encode(shasum)
}

#[derive(Clone)]
pub struct JavaScriptFile {
    // SHA384 hash of the file
    pub hash: String,
}

#[cfg(test)]
mod test {
    use super::hash_content;

    #[test]
    fn sha284_test() {
        let expect = "2BNhX2Y+kiI2uJZ5QmBrtxb29RjBWyKsF33hXUka61me++r03OdAYqi9eY8uaeSy";

        let content = "<script>alert(1);</script>";

        let result = hash_content(content.as_bytes());

        assert_eq!(result, expect);
    }
}

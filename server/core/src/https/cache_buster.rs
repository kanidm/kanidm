//! Used for appending cache-busting query parameters to URLs.
//!

#[allow(dead_code)] // Because it's used in templates
/// Gets the git rev from the KANIDM_PKG_COMMIT_REV variable else drops back to the version, to allow for cache-busting parameters in URLs
#[inline]
pub fn get_cache_buster_key() -> String {
    match option_env!("KANIDM_PKG_COMMIT_REV") {
        Some(rev) => rev.to_string(),
        None => env!("CARGO_PKG_VERSION").to_string(),
    }
}

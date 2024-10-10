//! Used for appending cache-busting query parameters to URLs.
//!

#[allow(dead_code)] // Because it's used in templates
/// Gets the git rev from the KANIDM_PKG_COMMIT_REV variable else drops back to the version, to allow for cache-busting parameters in URLs
#[inline]
pub fn get_cache_buster_key() -> String {
    option_env!("KANIDM_PKG_VERSION_HASH") // this comes from the profiles crate at build time
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .to_string()
}

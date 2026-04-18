use sparkle_resolver_common::SparkleFlavour;

/// The Kanidm Flavour Enhancer!!!
pub struct Msg {}

impl Default for Msg {
    fn default() -> Self {
        Msg {}
    }
}

impl SparkleFlavour for Msg {
    fn nss_module_name(&self) -> &str {
        "kanidm"
    }
}

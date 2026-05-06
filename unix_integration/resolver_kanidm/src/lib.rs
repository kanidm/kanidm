use sparkle_resolver_common::SparkleFlavour;

/// The Kanidm Flavour Enhancer!!!
#[derive(Default)]
pub struct Msg {}

impl SparkleFlavour for Msg {
    fn nss_module_name(&self) -> &str {
        "kanidm"
    }
}

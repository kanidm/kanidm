use crate::https::extractors::DomainInfoRead;
use kanidm_proto::internal::UiHint;
use std::collections::BTreeSet;

pub struct NavbarCtx {
    pub domain_info: DomainInfoRead,
    pub ui_hints: BTreeSet<UiHint>,
}

impl NavbarCtx {
    /// Clones ui_hints
    pub(crate) fn new(domain_info: DomainInfoRead, ui_hints: &BTreeSet<UiHint>) -> NavbarCtx {
        NavbarCtx {
            domain_info,
            ui_hints: ui_hints.clone(),
        }
    }
}

#![cfg(feature = "kanidm_tui")]
use crate::TuiOpt;
use kanidm_tui::KanidmTUI;
impl TuiOpt {
    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    pub fn exec(&self) {
        let kanidm_tui = KanidmTUI::default();
        kanidm_tui.exec();
    }
}

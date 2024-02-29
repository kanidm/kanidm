pub mod admin_accounts;
pub mod admin_groups;
pub mod admin_menu;
pub mod admin_oauth2;
pub mod admin_objectgraph;

mod prelude {

    pub use kanidmd_web_ui_shared::alpha_warning_banner;
    pub use kanidmd_web_ui_shared::utils::{do_alert_error, do_page_header};
    pub use kanidmd_web_ui_shared::{do_request, RequestMethod};
}

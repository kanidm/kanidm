use yew::prelude::*;
use yew::Html;

pub mod admin_accounts;
pub mod admin_groups;
pub mod admin_menu;
pub mod admin_oauth2;
pub mod change_unix_password;
pub mod create_reset_code;

/// creates the "Kanidm is alpha" banner
pub fn alpha_warning_banner() -> Html {
    html!(
        <div class="alert alert-warning" role="alert">
        {"🦀 Kanidm is still in early Alpha, this interface is a placeholder! "}
        </div>
    )
}

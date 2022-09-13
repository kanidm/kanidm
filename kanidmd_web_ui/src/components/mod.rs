use yew::Html;
use yew::prelude::*;

pub mod adminmenu;
pub mod change_unix_password;


/// creates the "Kanidm is alpha" banner
pub fn alpha_warning_banner() -> Html {
    html!(
        <div class="alert alert-warning" role="alert">
        {"🦀 Kanidm is still in early Alpha, this interface is a placeholder! "}
        </div>
    )
}

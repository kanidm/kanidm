use serde::{Deserialize, Serialize};
use yew_router::Routable;

// use crate::components;

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum LoginRoute {
    #[at("/ui/login")]
    Login,
    #[at("/ui/reauth")]
    Reauth,

    #[at("/ui/oauth2")]
    Oauth2,

    #[not_found]
    #[at("/ui/login/404")]
    NotFound,
}

// pub(crate) fn login_routes(route: LoginRoute) -> Html {
//     match route {
//         #[allow(clippy::let_unit_value)]
//         LoginRoute::Login => html! { <LoginApp workflow={ LoginWorkflow::Login } /> },
//         #[allow(clippy::let_unit_value)]
//         LoginRoute::Reauth => html! { <LoginApp workflow={ LoginWorkflow::Reauth } /> },

//         #[allow(clippy::let_unit_value)]
//         LoginRoute::Oauth2 => html! { <Oauth2App /> },

//         LoginRoute::NotFound => {
//             todo!()
//             // <Redirect<AdminRoute> to={AdminRoute::NotFound}/>
//         }
//     }
// }

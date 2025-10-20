use crate::https::views::admin::{admin_api_router, admin_router};
use crate::https::{middleware, ServerState};
use askama::Template;
use askama_web::WebTemplate;

use axum::{
    middleware::from_fn_with_state,
    response::Redirect,
    routing::{get, post},
    Router,
};
use axum_htmx::{HxEvent, HxRequestGuardLayer};
use constants::Urls;
use kanidmd_lib::{
    idm::server::DomainInfoRead,
    prelude::{OperationError, Uuid},
};

mod admin;
mod apps;
pub(crate) mod constants;
mod cookies;
mod enrol;
mod errors;
mod login;
mod navbar;
mod oauth2;
mod profile;
mod radius;
mod reset;

#[derive(Template, WebTemplate)]
#[template(path = "unrecoverable_error.html")]
struct UnrecoverableErrorView {
    err_code: OperationError,
    operation_id: Uuid,
    // This is an option because it's not always present in an "unrecoverable" situation
    domain_info: DomainInfoRead,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/error_toast.html")]
struct ErrorToastPartial {
    err_code: OperationError,
    operation_id: Uuid,
}

pub fn view_router(state: ServerState) -> Router<ServerState> {
    // These routes are special, and often need to redirect *out* of kanidm. We need to
    // allow this within CSP.
    let unguarded_csp_router = Router::new()
        .route("/oauth2/resume", get(oauth2::view_resume_get))
        .route("/oauth2/consent", post(oauth2::view_consent_post))
        // The login routes are htmx-free to make them simpler, which means
        // they need manual guarding for direct get requests which can occur
        // if a user attempts to reload the page.
        .route("/login", get(login::view_index_get))
        .route(
            "/login/passkey",
            post(login::view_login_passkey_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/seckey",
            post(login::view_login_seckey_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/begin",
            post(login::view_login_begin_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/mech_choose",
            post(login::view_login_mech_choose_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/backup_code",
            post(login::view_login_backupcode_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/totp",
            post(login::view_login_totp_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/pw",
            post(login::view_login_pw_post).get(|| async { Redirect::to("/ui") }),
        )
        .layer(from_fn_with_state(
            state,
            middleware::security_headers::csp_header_no_form_action_layer,
        ));

    // These will have the standard CSP headers applied.
    let mut unguarded_router = Router::new()
        .route(
            "/",
            get(|| async { Redirect::permanent(Urls::Login.as_ref()) }),
        )
        .route("/apps", get(apps::view_apps_get))
        .route("/enrol", get(enrol::view_enrol_get))
        .route("/reset", get(reset::view_reset_get))
        .route("/update_credentials", get(reset::view_self_reset_get))
        .route("/profile", get(profile::view_profile_get))
        .route("/profile/diff", get(profile::view_profile_get))
        .route("/radius", get(radius::view_radius_get))
        .route("/unlock", get(login::view_reauth_to_referer_get))
        .route("/logout", get(login::view_logout_get));

    // This is me being temporarily cheeky to avoid a lint while cfg(dev oauth device) is still
    // present.
    unguarded_router = unguarded_router.route("/oauth2", get(oauth2::view_index_get));

    #[cfg(feature = "dev-oauth2-device-flow")]
    {
        unguarded_router = unguarded_router.route(
            kanidmd_lib::prelude::uri::OAUTH2_DEVICE_LOGIN,
            get(oauth2::view_device_get).post(oauth2::view_device_post),
        );
    }

    // The webauthn post is unguarded because it's not a htmx event.

    // Anything that is a partial only works if triggered from htmx
    let guarded_router = Router::new()
        .route("/reset/add_totp", post(reset::view_new_totp))
        .route("/reset/add_password", post(reset::view_new_pwd))
        .route("/reset/change_password", post(reset::view_new_pwd))
        .route("/reset/add_passkey", post(reset::view_new_passkey))
        .route("/reset/set_unixcred", post(reset::view_set_unixcred))
        .route(
            "/reset/add_ssh_publickey",
            post(reset::view_add_ssh_publickey),
        )
        .route("/radius/generate", post(radius::view_radius_post))
        .route("/api/delete_alt_creds", post(reset::remove_alt_creds))
        .route("/api/delete_unixcred", post(reset::remove_unixcred))
        .route("/api/add_totp", post(reset::add_totp))
        .route("/api/remove_totp", post(reset::remove_totp))
        .route("/api/remove_passkey", post(reset::remove_passkey))
        .route("/api/finish_passkey", post(reset::finish_passkey))
        .route("/api/cancel_mfareg", post(reset::cancel_mfareg))
        .route(
            "/api/remove_ssh_publickey",
            post(reset::remove_ssh_publickey),
        )
        .route("/api/cu_cancel", post(reset::cancel_cred_update))
        .route("/api/cu_commit", post(reset::commit))
        .route(
            "/api/user_settings/add_email",
            get(profile::view_new_email_entry_partial),
        )
        .route(
            "/api/user_settings/edit_profile",
            post(profile::view_profile_diff_start_save_post),
        )
        .route(
            "/api/user_settings/confirm_profile",
            post(profile::view_profile_diff_confirm_save_post),
        )
        .layer(HxRequestGuardLayer::new("/ui"));

    let admin_router = admin_router();
    let admin_api_router = admin_api_router();
    Router::new()
        .merge(unguarded_csp_router)
        .merge(unguarded_router)
        .merge(guarded_router)
        .nest("/admin", admin_router)
        .nest("/api/admin", admin_api_router)
}

/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::Deserialize;
    use std::str::FromStr;

    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s)
            .map_err(serde::de::Error::custom)
            .map(Some),
    }
}

/// Used for creating hx events
pub(crate) enum KanidmHxEventName {
    AddEmailSwapped,
    AddTotpSwapped,
    AddPasskeySwapped,
    AddPasswordSwapped,
    PermissionDenied,
}

impl From<KanidmHxEventName> for HxEvent {
    fn from(event_name: KanidmHxEventName) -> Self {
        match event_name {
            KanidmHxEventName::AddEmailSwapped => HxEvent::new("addEmailSwapped"),
            KanidmHxEventName::AddTotpSwapped => HxEvent::new("addTotpSwapped"),
            KanidmHxEventName::AddPasskeySwapped => HxEvent::new("addPasskeySwapped"),
            KanidmHxEventName::AddPasswordSwapped => HxEvent::new("addPasswordSwapped"),
            KanidmHxEventName::PermissionDenied => HxEvent::new("permissionDenied"),
        }
    }
}

#[cfg(test)]
mod tests {

    use axum::response::IntoResponse;

    use super::*;
    #[tokio::test]
    async fn test_unrecoverableerrorview() {
        let domain_info = kanidmd_lib::server::DomainInfo::new_test();

        let view = UnrecoverableErrorView {
            err_code: OperationError::InvalidState,
            operation_id: Uuid::new_v4(),
            domain_info: domain_info.read(),
        };

        let error_html = view.render().expect("Failed to render");

        assert!(error_html.contains(domain_info.read().display_name()));

        let response = view.into_response();

        // TODO: this really should be an error code :(
        assert_eq!(response.status(), 200);
    }
}

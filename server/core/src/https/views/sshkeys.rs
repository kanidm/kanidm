use askama::Template;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension,
};
use axum_htmx::{HxPushUrl, HxRequest};
use futures::TryFutureExt;
use hyper::Uri;

use crate::https::{extractors::VerifiedClientInformation, middleware::KOpId, ServerState};

use super::{constants::ProfileMenuItems, errors::HtmxError, HtmlTemplate};

#[derive(Clone)]
pub struct PublicKey {
    kind: String,
    key: String,
    comment: Option<String>,
}

#[derive(Template, Clone)]
#[template(path = "ssh_keys.html")]
struct SshKeysPartialView {
    menu_active_item: ProfileMenuItems,
    ssh_keys: Vec<PublicKey>,
    posix_enabled: bool,
}

#[derive(Template)]
#[template(path = "user_settings.html")]
struct SshKeysView {
    profile_partial: SshKeysPartialView,
}

pub(crate) async fn view_sshkeys_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
) -> axum::response::Result<Response> {
    let uat = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let ssh_keys = state
        .qe_r_ref
        .handle_internalsshkeyread(client_auth_info, uat.uuid.to_string(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?
        .into_iter()
        .map(|s| {
            let mut tokens = s.split(' ');
            PublicKey {
                kind: tokens.next().unwrap_or("").to_string(),
                key: tokens.next().unwrap_or("").to_string(),
                comment: tokens.next().map(|s| s.to_string()),
            }
        })
        .collect();

    let sshkeys_partial_view = SshKeysPartialView {
        menu_active_item: ProfileMenuItems::SshKeys,
        ssh_keys,
        // TODO: fill in posix_enabled
        posix_enabled: false,
    };

    let sshkeys_view = SshKeysView {
        profile_partial: sshkeys_partial_view.clone(),
    };

    Ok(if hx_request {
        (
            HxPushUrl(Uri::from_static("/ui/ssh_keys")),
            HtmlTemplate(sshkeys_partial_view),
        )
            .into_response()
    } else {
        HtmlTemplate(sshkeys_view).into_response()
    })
}

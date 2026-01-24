use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::login::{LoginDisplayCtx, Reauth, ReauthPurpose};
use crate::https::views::Urls;
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use axum::response::IntoResponse;
use axum::response::Response;
use axum_extra::extract::cookie::CookieJar;
use kanidm_proto::internal::{PrivilegesActive, UserAuthToken};
use kanidmd_lib::idm::server::DomainInfoRead;
use kanidmd_lib::prelude::ClientAuthInfo;
use uuid::Uuid;

const READ_WRITE_REAUTH_WINDOW_SECONDS: i64 = 60;

#[must_use]
pub(crate) enum PrivilegeDecision {
    Proceed,
    ReauthRequired,
    ReadOnly,
}

/// Test if the current session *could* have read-write permissions granted. This indicates
/// the session is either read-write *now* or *could* become read-write after a re-authentication
/// process.
pub(crate) fn uat_privileges_possible(uat: &UserAuthToken) -> bool {
    #[allow(clippy::disallowed_methods)]
    // Allowed as this timestamp is only used for "fuzzy" checking of remaining time in the users
    // privilege state.
    let time =
        time::OffsetDateTime::now_utc() + time::Duration::seconds(READ_WRITE_REAUTH_WINDOW_SECONDS);

    match uat.purpose_privilege_state(time) {
        PrivilegesActive::True | PrivilegesActive::ReauthRequired => true,
        PrivilegesActive::False => false,
    }
}

/// Test if the current session has read-write permissions *now*. This does not inform you
/// if the session *could* become read-write.
pub(crate) fn uat_privileges_active(uat: &UserAuthToken) -> bool {
    #[allow(clippy::disallowed_methods)]
    // Allowed as this timestamp is only used for "fuzzy" checking of remaining time in the users
    // privilege state.
    let time =
        time::OffsetDateTime::now_utc() + time::Duration::seconds(READ_WRITE_REAUTH_WINDOW_SECONDS);

    match uat.purpose_privilege_state(time) {
        PrivilegesActive::True => true,
        PrivilegesActive::ReauthRequired | PrivilegesActive::False => false,
    }
}

/// Determine the current state of privileges in the session, and if re-authentication would be
/// required or not.
pub(crate) fn uat_privilege_decision(uat: &UserAuthToken) -> PrivilegeDecision {
    #[allow(clippy::disallowed_methods)]
    // Allowed as this timestamp is only used for "fuzzy" checking of remaining time in the users
    // privilege state.
    let time =
        time::OffsetDateTime::now_utc() + time::Duration::seconds(READ_WRITE_REAUTH_WINDOW_SECONDS);

    match uat.purpose_privilege_state(time) {
        PrivilegesActive::True => PrivilegeDecision::Proceed,
        PrivilegesActive::ReauthRequired => PrivilegeDecision::ReauthRequired,
        PrivilegesActive::False => PrivilegeDecision::ReadOnly,
    }
}

pub(crate) async fn render_reauth(
    state: ServerState,
    jar: CookieJar,
    domain_info: DomainInfoRead,
    client_auth_info: ClientAuthInfo,
    kopid: KOpId,
    reauth_purpose: ReauthPurpose,
    return_to: Urls,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: Some(Reauth {
            username: uat.spn.clone(),
            purpose: reauth_purpose,
        }),
        error: None,
    };

    Ok(super::login::view_reauth_get(
        state,
        client_auth_info,
        kopid,
        jar,
        return_to.as_ref(),
        display_ctx,
    )
    .await)
}

#[derive(Template, WebTemplate)]
#[template(path = "reauth_readonly.html")]
struct ReauthReadonlyView {
    domain_info: DomainInfoRead,
    spn: String,
    operation_id: Uuid,
}

pub(crate) async fn render_readonly(
    domain_info: DomainInfoRead,
    uat: &UserAuthToken,
    kopid: KOpId,
) -> axum::response::Result<Response> {
    Ok(ReauthReadonlyView {
        domain_info,
        spn: uat.spn.clone(),
        operation_id: kopid.eventid,
    }
    .into_response())
}

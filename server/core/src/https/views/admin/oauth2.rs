#![allow(clippy::result_large_err)]

use crate::https::{
    extractors::{DomainInfo, VerifiedClientInformation},
    middleware::KOpId,
    views::{errors::HtmxError, navbar::NavbarCtx, Urls},
    ServerState,
};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension,
};
use axum_htmx::{HxPushUrl, HxRequest};
use kanidm_proto::internal::UserAuthToken;
use kanidmd_lib::prelude::*;

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_oauth2_view_partial.html")]
struct OauthViewPartial {
    resources: Vec<OAuth2RS>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct OAuthView {
    navbar_ctx: NavbarCtx,
    partial: OauthViewPartial,
    title: String,
}

#[derive(Debug, Clone)]
struct OAuth2RS {
    name: String,
    display_name: String,
    uuid: String,
}

pub async fn get_oauths_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let filters = filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ));
    let search_result = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filters, None, kopid.eventid)
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?
        .iter()
        .filter_map(|entry| {
            let name = entry
                .attrs
                .get(&Attribute::Name.to_string())
                .and_then(|vec| vec.first())?
                .to_owned();

            let display_name = entry
                .attrs
                .get(&Attribute::DisplayName.to_string())
                .and_then(|vec| vec.first())?
                .to_owned();

            let uuid = entry
                .attrs
                .get(&Attribute::Uuid.to_string())
                .and_then(|vec| vec.first())?
                .to_owned();

            Some(OAuth2RS {
                name,
                display_name,
                uuid,
            })
        })
        .collect::<Vec<_>>();

    let oauth2s = OauthViewPartial {
        resources: search_result,
    };
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let push_url = HxPushUrl("/ui/admin/oauth2".to_string());
    Ok(if is_htmx {
        (push_url, oauth2s).into_response()
    } else {
        (
            push_url,
            OAuthView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial: oauth2s,
                title: "OAuth2".to_string(),
            },
        )
            .into_response()
    })
}

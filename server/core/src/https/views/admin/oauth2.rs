#![allow(clippy::result_large_err)]

use crate::https::{
    errors::WebError,
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
use kanidm_proto::{
    internal::UserAuthToken,
    scim_v1::{
        server::{ScimEffectiveAccess, ScimEntryKanidm, ScimValueKanidm},
        ScimEntryGetQuery, ScimFilter,
    },
};
use kanidmd_lib::prelude::*;

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_oauth2_view_partial.html")]
struct OauthViewPartial {
    resources: Vec<(OAuth2RS, ScimEffectiveAccess)>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct OAuthView {
    navbar_ctx: NavbarCtx,
    partial: OauthViewPartial,
    title: String,
}

pub async fn get_oauths_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let resources = get_oauth2_rs_list(state, &kopid, client_auth_info.clone()).await?;
    let oauth2s = OauthViewPartial { resources };
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

async fn get_oauth2_rs_list(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Vec<(OAuth2RS, ScimEffectiveAccess)>, WebError> {
    let group_attributes: [Attribute; _] =
        [Attribute::Uuid, Attribute::DisplayName, Attribute::Name];
    let filter = ScimFilter::Equal(
        Attribute::Class.into(),
        EntryClass::OAuth2ResourceServer.into(),
    );

    let search_result = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(group_attributes)),
                ext_access_check: true,
                sort_by: Some(Attribute::Name),
                ..Default::default()
            },
        )
        .await?;

    let resource_server: Vec<_> = search_result
        .resources
        .into_iter()
        .filter_map(|entry| {
            let effective_access = entry.ext_access_check.clone()?;
            let rs = OAuth2RS::try_from(entry).ok()?;
            Some((rs, effective_access))
        })
        .collect();
    Ok(resource_server)
}

#[derive(Debug, Clone)]
struct OAuth2RS {
    uuid: Uuid,
    name: String,
    display_name: String,
}

impl TryFrom<ScimEntryKanidm> for OAuth2RS {
    type Error = ();

    fn try_from(mut value: ScimEntryKanidm) -> Result<Self, Self::Error> {
        let uuid = value.header.id;
        let name = value
            .attrs
            .remove(&Attribute::Name)
            .and_then(|v| match v {
                ScimValueKanidm::String(value) => Some(value),
                _ => None,
            })
            .ok_or(())?;

        let display_name = value
            .attrs
            .remove(&Attribute::DisplayName)
            .and_then(|v| match v {
                ScimValueKanidm::String(value) => Some(value),
                _ => None,
            })
            .ok_or(())?;
        Ok(OAuth2RS {
            uuid,
            name,
            display_name,
        })
    }
}

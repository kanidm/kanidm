use crate::https::extractors::{AccessInfo, DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::Urls;
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::response::{ErrorResponse, IntoResponse, Response};
use axum::Extension;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::OperationError;
use kanidm_proto::scim_v1::server::{ScimEffectiveAccess, ScimEntryKanidm};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimMail};
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_and, f_eq, Filter, FC};
use kanidmd_lib::idm::server::DomainInfoRead;
use kanidmd_lib::idm::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct AccountsView {
    access_info: AccessInfo,
    navbar_ctx: NavbarCtx,
    partial: AccountsPartialView,
}

#[derive(Template)]
#[template(path = "admin/admin_accounts_partial.html")]
struct AccountsPartialView {
    accounts: Vec<AccountInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AccountInfo {
    uuid: Uuid,
    name: String,
    displayname: Option<String>,
    spn: String,
    description: Option<String>,
    mails: Vec<ScimMail>,
    scim_effective_access: ScimEffectiveAccess,
}

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct AccountView {
    access_info: AccessInfo,
    partial: AccountViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template)]
#[template(path = "admin/admin_account_view_partial.html")]
struct AccountViewPartial {
    account: AccountInfo,
}

pub(crate) async fn view_account_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let account =
        get_account_info(uuid, state, &kopid, client_auth_info, domain_info.clone()).await?;
    let accounts_partial = AccountViewPartial { account };

    let path_string = format!("/ui/admin/account/{uuid}/view");
    let uri = Uri::from_str(path_string.as_str())
        .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;
    let push_url = HxPushUrl(uri);
    Ok(if is_htmx {
        (push_url, accounts_partial).into_response()
    } else {
        (
            push_url,
            AccountView {
                access_info: AccessInfo::new(),
                partial: accounts_partial,
                navbar_ctx: NavbarCtx { domain_info },
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_accounts_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let accounts = get_accounts_info(state, &kopid, client_auth_info, domain_info.clone()).await?;
    let accounts_partial = AccountsPartialView { accounts };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/accounts"));
    Ok(if is_htmx {
        (push_url, accounts_partial).into_response()
    } else {
        (
            push_url,
            AccountsView {
                access_info: AccessInfo::new(),
                navbar_ctx: NavbarCtx { domain_info },
                partial: accounts_partial,
            },
        )
            .into_response()
    })
}

async fn get_account_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
) -> Result<AccountInfo, ErrorResponse> {
    let scim_entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            uuid.to_string(),
            EntryClass::Account,
            ScimEntryGetQuery {
                attributes: Some(vec![
                    Attribute::Uuid,
                    Attribute::Description,
                    Attribute::Name,
                    Attribute::DisplayName,
                    Attribute::Spn,
                    Attribute::Mail,
                ]),
                ext_access_check: true,
            },
        )
        .map_err(|op_err| HtmxError::new(kopid, op_err, domain_info.clone()))
        .await?;

    if let Some(account_info) = scimentry_into_accountinfo(scim_entry) {
        Ok(account_info)
    } else {
        Err(HtmxError::new(kopid, OperationError::InvalidState, domain_info.clone()).into())
    }
}

async fn get_accounts_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
) -> Result<Vec<AccountInfo>, ErrorResponse> {
    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Account.into())]));
    let attrs = Some(BTreeSet::from([
        Attribute::Uuid,
        Attribute::Description,
        Attribute::Name,
        Attribute::DisplayName,
        Attribute::Spn,
        Attribute::Mail,
    ]));
    let base: Vec<ScimEntryKanidm> = state
        .qe_r_ref
        .scim_entry_search(client_auth_info.clone(), filter, kopid.eventid, attrs, true)
        .map_err(|op_err| HtmxError::new(kopid, op_err, domain_info.clone()))
        .await?;

    // TODO: inefficient to sort here
    let mut accounts: Vec<_> = base
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_accountinfo)
        .collect();

    accounts.sort_by_key(|gi| gi.uuid);
    accounts.reverse();
    Ok(accounts)
}

fn scimentry_into_accountinfo(scim_entry: ScimEntryKanidm) -> Option<AccountInfo> {
    let uuid = scim_entry.header.id;
    let name = scim_entry.attr_str(&Attribute::Name)?.to_string();
    let displayname = scim_entry
        .attr_str(&Attribute::DisplayName)
        .map(|s| s.to_string());
    let spn = scim_entry.attr_str(&Attribute::Spn)?.to_string();
    let description = scim_entry
        .attr_str(&Attribute::Description)
        .map(|t| t.to_string());
    let mails = scim_entry.attr_mails().cloned().unwrap_or_default();

    let option = scim_entry.ext_access_check;
    let scim_effective_access = option?; // TODO: This should be an error msg.

    Some(AccountInfo {
        scim_effective_access,
        uuid,
        name,
        displayname,
        spn,
        description,
        mails,
    })
}

use crate::https::extractors::{AccessInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::HtmlTemplate;
use crate::https::ServerState;
use askama::Template;
use axum::extract::State;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_NAME, ATTR_UUID};
use kanidm_proto::v1::Entry;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_eq, f_and, FC, Filter};
use serde::{Deserialize, Serialize};

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct AccountsView {
    access_info: AccessInfo,
    partial: AccountsPartialView,
}

#[derive(Template)]
#[template(path = "admin/admin_accounts_partial.html")]
struct AccountsPartialView {
    accounts: Vec<AccountInfo>
}

#[derive(Serialize, Deserialize, Debug)]
struct AccountInfo {
    uuid: String,
    name: String,
    displayname: String,
}

pub(crate) async fn view_accounts_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_and!([f_eq(
        Attribute::Class,
        EntryClass::Account.into()
    )]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filter, None, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let accounts = base.into_iter().map(|entry: Entry| {
        let uuid = entry.attrs.get(ATTR_UUID).unwrap_or(&vec![]).first().unwrap_or(&"".to_string()).clone();
        let name = entry.attrs.get(ATTR_NAME).unwrap_or(&vec![]).first().unwrap_or(&"".to_string()).clone();
        let displayname = entry.attrs.get(ATTR_DISPLAYNAME).unwrap_or(&vec![]).first().unwrap_or(&"".to_string()).clone();

        AccountInfo {
            uuid,
            name,
            displayname,
        }
    }).collect();
    let accounts_partial = AccountsPartialView { accounts };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/accounts"));
    Ok(if is_htmx {
        (push_url, HtmlTemplate(accounts_partial)).into_response()
    } else {
        (
            push_url,
            HtmlTemplate(AccountsView {
                access_info: AccessInfo::new(),
                partial: accounts_partial,
            }),
        ).into_response()
    })
}

#[cfg(debug_assertions)]
use gloo::console;
use gloo::storage::{
    LocalStorage as PersistentStorage, SessionStorage as TemporaryStorage, Storage,
};
use kanidm_proto::oauth2::AuthorisationRequest;
use kanidm_proto::v1::{CUSessionToken, CUStatus};
use serde::{Deserialize, Serialize};
use wasm_bindgen::UnwrapThrowExt;
use yew_router::navigator::Navigator;

use crate::manager::Route;
use crate::views::ViewRoute;

pub fn clear_bearer_token() {
    PersistentStorage::delete("kanidm_bearer_token");
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Location {
    Manager(Route),
    Views(ViewRoute),
}

impl Location {
    pub(crate) fn goto(self, navigator: &Navigator) {
        match self {
            Location::Manager(r) => navigator.push(&r),
            Location::Views(r) => navigator.push(&r),
        }
    }
}

pub fn push_return_location(l: Location) {
    TemporaryStorage::set("return_location", l)
        .expect_throw("failed to set return_location in temporary storage");
}

pub fn pop_return_location() -> Location {
    let l: Result<Location, _> = TemporaryStorage::get("return_location");
    #[cfg(debug_assertions)]
    console::debug!(format!("return_location -> {:?}", l).as_str());
    TemporaryStorage::delete("return_location");
    l.unwrap_or(Location::Manager(Route::Landing))
}

pub fn push_oauth2_authorisation_request(r: AuthorisationRequest) {
    TemporaryStorage::set("oauth2_authorisation_request", r)
        .expect_throw("failed to set oauth2_authorisation_request in temporary storage");
}

pub fn pop_oauth2_authorisation_request() -> Option<AuthorisationRequest> {
    let l: Result<AuthorisationRequest, _> = TemporaryStorage::get("oauth2_authorisation_request");
    #[cfg(debug_assertions)]
    console::debug!(format!("oauth2_authorisation_request -> {:?}", l).as_str());
    TemporaryStorage::delete("oauth2_authorisation_request");
    l.ok()
}

pub fn push_login_hint(r: String) {
    TemporaryStorage::set("login_hint", r).expect_throw("failed to set login hint");
}

pub fn pop_login_hint() -> Option<String> {
    let l: Result<String, _> = TemporaryStorage::get("login_hint");
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::pop_login_hint -> {:?}", l).as_str());
    TemporaryStorage::delete("login_hint");
    l.ok()
}

pub fn push_login_remember_me(r: String) {
    PersistentStorage::set("login_remember_me", r).expect_throw("failed to set login remember me");
}

pub fn get_login_remember_me() -> Option<String> {
    let l: Result<String, _> = PersistentStorage::get("login_remember_me");
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::pop_login_remember_me -> {:?}", l).as_str());
    l.ok()
}

pub fn pop_login_remember_me() -> Option<String> {
    let l: Result<String, _> = PersistentStorage::get("login_remember_me");
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::pop_login_remember_me -> {:?}", l).as_str());
    PersistentStorage::delete("login_remember_me");
    l.ok()
}

/// Pushes the "cred_update_session" element into the browser's temporary storage
pub fn push_cred_update_session(s: (CUSessionToken, CUStatus)) {
    TemporaryStorage::set("cred_update_session", s)
        .expect_throw("failed to set cred session token");
}

/// Pulls the "cred_update_session" element from the browser's temporary storage
pub fn get_cred_update_session() -> Option<(CUSessionToken, CUStatus)> {
    let l: Result<(CUSessionToken, CUStatus), _> = TemporaryStorage::get("cred_update_session");
    l.ok()
}

/*
/// pops the "cred_update_session" element from the browser's temporary storage
pub fn pop_cred_update_session() -> Option<(CUSessionToken, CUStatus)> {
    let l: Result<(CUSessionToken, CUStatus), _> = TemporaryStorage::get("cred_update_session");
    TemporaryStorage::delete("cred_update_session");
    l.ok()
}
*/

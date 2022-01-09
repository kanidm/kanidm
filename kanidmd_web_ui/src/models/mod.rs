use kanidm_proto::oauth2::AuthorisationRequest;

use gloo::console;
use gloo::storage::LocalStorage as PersistentStorage;
use gloo::storage::SessionStorage as TemporaryStorage;
use gloo::storage::Storage;
use wasm_bindgen::UnwrapThrowExt;

use crate::manager::Route;
use serde::{Deserialize, Serialize};

pub fn get_bearer_token() -> Option<String> {
    let prev_session: Result<String, _> = PersistentStorage::get("kanidm_bearer_token");
    console::log!(format!("kanidm_bearer_token -> {:?}", prev_session).as_str());

    prev_session.ok()
}

pub fn set_bearer_token(bearer_token: String) {
    PersistentStorage::set("kanidm_bearer_token", bearer_token)
        .expect_throw("failed to set header");
}

pub fn clear_bearer_token() {
    PersistentStorage::delete("kanidm_bearer_token");
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Location {
    Oauth2,
    Views,
}

impl From<Location> for Route {
    fn from(l: Location) -> Self {
        match l {
            Location::Views => Route::Index,
            Location::Oauth2 => Route::Oauth2,
        }
    }
}

pub fn push_return_location(l: Location) {
    TemporaryStorage::set("return_location", l).expect_throw("failed to set header");
}

pub fn pop_return_location() -> Location {
    let l: Result<Location, _> = TemporaryStorage::get("return_location");
    console::log!(format!("return_location -> {:?}", l).as_str());
    TemporaryStorage::delete("return_location");
    l.unwrap_or(Location::Views)
}

pub fn push_oauth2_authorisation_request(r: AuthorisationRequest) {
    TemporaryStorage::set("oauth2_authorisation_request", r).expect_throw("failed to set header");
}

pub fn pop_oauth2_authorisation_request() -> Option<AuthorisationRequest> {
    let l: Result<AuthorisationRequest, _> = TemporaryStorage::get("oauth2_authorisation_request");
    console::log!(format!("oauth2_authorisation_request -> {:?}", l).as_str());
    TemporaryStorage::delete("oauth2_authorisation_request");
    l.ok()
}

pub fn push_login_hint(r: String) {
    TemporaryStorage::set("login_hint", r).expect_throw("failed to set header");
}

pub fn pop_login_hint() -> Option<String> {
    let l: Result<String, _> = TemporaryStorage::get("login_hint");
    console::log!(format!("login_hint -> {:?}", l).as_str());
    TemporaryStorage::delete("login_hint");
    l.ok()
}

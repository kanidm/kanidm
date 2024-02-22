#[cfg(debug_assertions)]
use gloo::console;
use gloo::storage::{LocalStorage, SessionStorage as TemporaryStorage, Storage};
use kanidm_proto::internal::{CUSessionToken, CUStatus};
use kanidm_proto::oauth2::AuthorisationRequest;
use wasm_bindgen::UnwrapThrowExt;

use crate::constants::URL_USER_HOME;

const BEARER_TOKEN: &str = "bearer_token";
const CRED_UPDATE_SESSION: &str = "cred_update_session";
const LOGIN_HINT: &str = "login_hint";
const LOGIN_REMEMBER_ME: &str = "login_remember_me";
const RETURN_LOCATION: &str = "return_location";
const OAUTH2_AUTHORIZATION_REQUEST: &str = "oauth2_authorisation_request";

/// Store the bearer token `r` in local storage
pub fn set_bearer_token(r: String) {
    LocalStorage::set(BEARER_TOKEN, r).expect_throw(&format!("failed to set {}", BEARER_TOKEN));
}

pub fn get_bearer_token() -> Option<String> {
    let l: Result<String, _> = LocalStorage::get(BEARER_TOKEN);
    #[cfg(debug_assertions)]
    console::debug!(&format!(
        "login_hint::get_login_remember_me -> present={:?}",
        l.is_ok()
    ));
    l.ok()
}

pub fn clear_bearer_token() {
    #[cfg(debug_assertions)]
    console::debug!("clearing the bearer token from local storage");
    LocalStorage::delete(BEARER_TOKEN);
}

/// Keep the "return location" in temporary storage when we're planning to do a redirect
pub fn push_return_location(l: &str) {
    TemporaryStorage::set(RETURN_LOCATION, l).expect_throw(&format!(
        "failed to set {} in temporary storage",
        RETURN_LOCATION
    ));
}

/// We keep the "return location" in temporary storage when we're planning to do a redirect,
/// this pulls it back and removes it from storage.
pub fn pop_return_location() -> String {
    let l: Result<String, _> = TemporaryStorage::get(RETURN_LOCATION);
    #[cfg(debug_assertions)]
    console::debug!(format!("{} -> {:?}", RETURN_LOCATION, l).as_str());
    TemporaryStorage::delete(RETURN_LOCATION);
    l.unwrap_or(URL_USER_HOME.to_string())
}

/// Store the user's username in temporary storage when we're passing it around.
pub fn push_login_hint(username: String) {
    TemporaryStorage::set(LOGIN_HINT, username).expect_throw("failed to set login hint");
}

pub fn get_login_hint() -> Option<String> {
    let l: Result<String, _> = TemporaryStorage::get(LOGIN_HINT);
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::get_login_hint -> {:?}", l).as_str());
    l.ok()
}

pub fn pop_login_hint() -> Option<String> {
    let l: Result<String, _> = TemporaryStorage::get(LOGIN_HINT);
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::pop_login_hint -> {:?}", l).as_str());
    TemporaryStorage::delete(LOGIN_HINT);
    l.ok()
}

/// Keep track of the user's username when they set the "remember me" flag on the UI
pub fn push_login_remember_me(username: String) {
    LocalStorage::set(LOGIN_REMEMBER_ME, username).expect_throw("failed to set login remember me");
}

pub fn get_login_remember_me() -> Option<String> {
    let username: Result<String, _> = LocalStorage::get(LOGIN_REMEMBER_ME);
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::get_login_remember_me -> {:?}", username).as_str());
    username.ok()
}

pub fn pop_login_remember_me() -> Option<String> {
    let username: Result<String, _> = LocalStorage::get(LOGIN_REMEMBER_ME);
    #[cfg(debug_assertions)]
    console::debug!(format!("login_hint::pop_login_remember_me -> {:?}", username).as_str());
    LocalStorage::delete(LOGIN_REMEMBER_ME);
    username.ok()
}

pub fn push_oauth2_authorisation_request(r: AuthorisationRequest) {
    TemporaryStorage::set(OAUTH2_AUTHORIZATION_REQUEST, r).expect_throw(&format!(
        "failed to set {} in temporary storage",
        OAUTH2_AUTHORIZATION_REQUEST
    ));
}

pub fn pop_oauth2_authorisation_request() -> Option<AuthorisationRequest> {
    let l: Result<AuthorisationRequest, _> = TemporaryStorage::get(OAUTH2_AUTHORIZATION_REQUEST);
    #[cfg(debug_assertions)]
    console::debug!(format!("{} -> {:?}", OAUTH2_AUTHORIZATION_REQUEST, l).as_str());
    TemporaryStorage::delete(OAUTH2_AUTHORIZATION_REQUEST);
    l.ok()
}

/// Pushes the "cred_update_session" element into the browser's temporary storage
pub fn push_cred_update_session(s: (CUSessionToken, CUStatus)) {
    TemporaryStorage::set(CRED_UPDATE_SESSION, s).expect_throw("failed to set cred session token");
}

/// Pulls the "cred_update_session" element from the browser's temporary storage
pub fn get_cred_update_session() -> Option<(CUSessionToken, CUStatus)> {
    let l: Result<(CUSessionToken, CUStatus), _> = TemporaryStorage::get(CRED_UPDATE_SESSION);
    l.ok()
}

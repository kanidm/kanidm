//! Support Utilities for interacting with cookies.

use crate::https::ServerState;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use compact_jwt::{Jws, JwsSigner};
use serde::de::DeserializeOwned;
use serde::Serialize;

fn new_cookie<'a>(state: &'_ ServerState, ck_id: &'a str, value: String) -> Cookie<'a> {
    let mut token_cookie = Cookie::new(ck_id, value);
    token_cookie.set_secure(state.secure_cookies);
    token_cookie.set_same_site(SameSite::Lax);
    // Prevent Document.cookie accessing this. Still works with fetch.
    token_cookie.set_http_only(true);
    // We set a domain here because it allows subdomains
    // of the idm to share the cookie. If domain was incorrect
    // then webauthn won't work anyway!
    token_cookie.set_domain(state.domain.clone());
    token_cookie.set_path("/");
    token_cookie
}

#[instrument(name = "views::cookies::destroy", level = "debug", skip(jar, state))]
pub fn destroy(jar: CookieJar, ck_id: &str, state: &ServerState) -> CookieJar {
    if let Some(ck) = jar.get(ck_id) {
        let mut removal_cookie = ck.clone();
        removal_cookie.make_removal();

        // Need to be set to domain else the cookie isn't removed!
        removal_cookie.set_domain(state.domain.clone());

        // Need to be set to / to remove on all parent paths.
        // If you don't set a path, NOTHING IS REMOVED!!!
        removal_cookie.set_path("/");

        jar.add(removal_cookie)
    } else {
        jar
    }
}

pub fn make_unsigned<'a>(state: &'_ ServerState, ck_id: &'a str, value: String) -> Cookie<'a> {
    new_cookie(state, ck_id, value)
}

pub fn make_signed<'a, T: Serialize>(
    state: &'_ ServerState,
    ck_id: &'a str,
    value: &'_ T,
) -> Option<Cookie<'a>> {
    let kref = &state.jws_signer;

    let jws = Jws::into_json(value)
        .map_err(|e| {
            error!(?e);
        })
        .ok()?;

    // Get the header token ready.
    let token = kref
        .sign(&jws)
        .map(|jwss| jwss.to_string())
        .map_err(|e| {
            error!(?e);
        })
        .ok()?;

    Some(new_cookie(state, ck_id, token))
}

pub fn get_signed<T: DeserializeOwned>(
    state: &ServerState,
    jar: &CookieJar,
    ck_id: &str,
) -> Option<T> {
    jar.get(ck_id)
        .map(|c| c.value())
        .and_then(|s| state.deserialise_from_str::<T>(s))
}

pub fn get_unsigned<'a>(jar: &'a CookieJar, ck_id: &'_ str) -> Option<&'a str> {
    jar.get(ck_id).map(|c| c.value())
}

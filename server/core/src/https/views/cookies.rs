//! Support Utilities for interacting with cookies.

use crate::https::ServerState;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use compact_jwt::{Jws, JwsSigner};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn destroy(jar: CookieJar, ck_id: &str) -> CookieJar {
    if let Some(ck) = jar.get(ck_id) {
        let mut ck = ck.clone();
        ck.make_removal();
        jar.add(ck)
    } else {
        jar
    }
}

pub fn make_unsigned<'a>(
    state: &'_ ServerState,
    ck_id: &'a str,
    value: String,
    path: &'a str,
) -> Cookie<'a> {
    let mut token_cookie = Cookie::new(ck_id, value);
    token_cookie.set_secure(state.secure_cookies);
    token_cookie.set_same_site(SameSite::Lax);
    // Prevent Document.cookie accessing this. Still works with fetch.
    token_cookie.set_http_only(true);
    // We set a domain here because it allows subdomains
    // of the idm to share the cookie. If domain was incorrect
    // then webauthn won't work anyway!
    token_cookie.set_domain(state.domain.clone());
    token_cookie.set_path(path);
    token_cookie
}

pub fn make_signed<'a, T: Serialize>(
    state: &'_ ServerState,
    ck_id: &'a str,
    value: &'_ T,
    path: &'a str,
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

    let mut token_cookie = Cookie::new(ck_id, token);
    token_cookie.set_secure(state.secure_cookies);
    token_cookie.set_same_site(SameSite::Lax);
    token_cookie.set_http_only(true);
    token_cookie.set_path(path);
    token_cookie.set_domain(state.domain.clone());
    Some(token_cookie)
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

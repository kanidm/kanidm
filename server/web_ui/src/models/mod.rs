#[cfg(debug_assertions)]
use gloo::console;
use gloo::storage::{SessionStorage as TemporaryStorage, Storage};
use kanidm_proto::v1::{CUSessionToken, CUStatus};
use serde::{Deserialize, Serialize};
use wasm_bindgen::UnwrapThrowExt;
use yew_router::navigator::Navigator;

use crate::manager::Route;
use crate::views::ViewRoute;

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

pub fn push_login_hint(r: String) {
    TemporaryStorage::set("login_hint", r).expect_throw("failed to set login hint");
}

/// Pushes the "cred_update_session" element into the browser's temporary storage
pub fn push_cred_update_session(s: (CUSessionToken, CUStatus)) {
    TemporaryStorage::set("cred_update_session", s)
        .expect_throw("failed to set cred session token");
}

/*
/// pops the "cred_update_session" element from the browser's temporary storage
pub fn pop_cred_update_session() -> Option<(CUSessionToken, CUStatus)> {
    let l: Result<(CUSessionToken, CUStatus), _> = TemporaryStorage::get("cred_update_session");
    TemporaryStorage::delete("cred_update_session");
    l.ok()
}
*/

use yew::format::Json;
use yew_services::storage;
use yew_services::{ConsoleService, StorageService};

use kanidm_proto::oauth2::AuthorisationRequest;

use crate::manager::Route;

fn get_persistent_storage() -> StorageService {
    StorageService::new(storage::Area::Local)
        .map_err(|e| {
            let e_msg = format!("lstorage error -> {:?}", e);
            ConsoleService::log(e_msg.as_str());
        })
        .unwrap()
}

pub fn get_bearer_token() -> Option<String> {
    let lstorage = get_persistent_storage();

    let prev_session: Result<String, _> = lstorage.restore("kanidm_bearer_token");
    ConsoleService::log(format!("prev_session -> {:?}", prev_session).as_str());

    prev_session.ok()
}

pub fn set_bearer_token(bearer_token: String) {
    let mut lstorage = get_persistent_storage();
    lstorage.store("kanidm_bearer_token", Ok(bearer_token));
}

pub fn clear_bearer_token() {
    let mut lstorage = get_persistent_storage();
    lstorage.remove("kanidm_bearer_token");
}

fn get_temporary_storage() -> StorageService {
    StorageService::new(storage::Area::Session)
        .map_err(|e| {
            let e_msg = format!("tstorage error -> {:?}", e);
            ConsoleService::log(e_msg.as_str());
        })
        .unwrap()
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
    let mut tstorage = get_temporary_storage();
    tstorage.store("return_location", Json(&l));
}

pub fn pop_return_location() -> Location {
    let mut tstorage = get_temporary_storage();

    let l: Json<Result<Location, _>> = tstorage.restore("return_location");
    ConsoleService::log(format!("return_location -> {:?}", l).as_str());
    tstorage.remove("return_location");

    l.into_inner().ok().unwrap_or(Location::Views)
}

pub fn push_oauth2_authorisation_request(r: AuthorisationRequest) {
    let mut tstorage = get_temporary_storage();
    tstorage.store("oauth2_authorisation_request", Json(&r));
}

pub fn pop_oauth2_authorisation_request() -> Option<AuthorisationRequest> {
    let mut tstorage = get_temporary_storage();

    let l: Json<Result<AuthorisationRequest, _>> = tstorage.restore("oauth2_authorisation_request");
    ConsoleService::log(format!("oauth2_authorisation_request -> {:?}", l).as_str());
    tstorage.remove("oauth2_authorisation_request");

    l.into_inner().ok()
}

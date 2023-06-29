///! Route-mapping magic for tide
///
/// Instead of adding routes with (for example) the .post method you add them with .mapped_post, passing an instance of [RouteMap] and it'll do the rest...
use serde::{Deserialize, Serialize};
use tide::{Endpoint, Route};

use crate::tide::AppState;

// Extends the tide::Route for RouteMaps, this would really be nice if it was generic :(
pub trait RouteMaps {
    fn mapped_method(
        &mut self,
        routemap: &mut RouteMap,
        method: http_types::Method,
        ep: impl Endpoint<AppState>,
    ) -> &mut Self;
    fn mapped_delete(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self;
    fn mapped_get(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self;
    fn mapped_patch(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self;
    fn mapped_post(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self;
    fn mapped_put(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self;
    // fn mapped_update(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self;
}

impl RouteMaps for Route<'_, AppState> {
    // add a mapped method to the list
    fn mapped_method(
        &mut self,
        routemap: &mut RouteMap,
        method: http_types::Method,
        ep: impl Endpoint<AppState>,
    ) -> &mut Self {
        // TODO: truly weird things involving ASTs and sacrifices to eldritch gods to figure out how to represent the Endpoint

        // if the path is empty then it's the root path...
        let path_str = self.path().to_string();
        let path = match path_str.is_empty() {
            true => String::from("/"),
            false => path_str,
        };

        // debug!("Mapping route: {:?}", path);
        routemap.routelist.push(RouteInfo { path, method });
        self.method(method, ep)
    }

    fn mapped_delete(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self {
        self.mapped_method(routemap, http_types::Method::Delete, ep)
    }

    fn mapped_get(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self {
        self.mapped_method(routemap, http_types::Method::Get, ep)
    }

    fn mapped_patch(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self {
        self.mapped_method(routemap, http_types::Method::Patch, ep)
    }

    fn mapped_post(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self {
        self.mapped_method(routemap, http_types::Method::Post, ep)
    }

    fn mapped_put(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self {
        self.mapped_method(routemap, http_types::Method::Put, ep)
    }

    // fn mapped_update(&mut self, routemap: &mut RouteMap, ep: impl Endpoint<AppState>) -> &mut Self {
    //     self.mapped_method(routemap, http_types::Method::Update, ep)
    // }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Information about a given route
pub struct RouteInfo {
    pub path: String,
    pub method: http_types::Method,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RouteMap {
    pub routelist: Vec<RouteInfo>,
}

impl RouteMap {
    // Serializes the object out to a pretty JSON blob
    pub fn do_map(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    // Inject the route for the routemap endpoint
    pub fn push_self(&mut self, path: String, method: http_types::Method) {
        self.routelist.push(RouteInfo { path, method });
    }
}

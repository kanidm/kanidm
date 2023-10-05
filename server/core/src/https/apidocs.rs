use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "token_jwt",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            )
        }
    }
}

// docs for the derive macro are here: <https://docs.rs/utoipa-gen/3.5.0/utoipa_gen/derive.OpenApi.html#info-attribute-syntax>
#[derive(OpenApi)]
#[openapi(
    paths(
        super::generic::status,
        super::generic::robots_txt,
        super::oauth2::oauth2_image_get,
        super::v1_oauth2::oauth2_id_image_delete,
        super::v1_oauth2::oauth2_id_image_post,
        super::v1_oauth2::oauth2_get,
        super::v1_oauth2::oauth2_basic_post,
        super::v1_oauth2::oauth2_public_post,
        super::v1_oauth2::oauth2_id_get,
        super::v1_oauth2::oauth2_id_patch,
        super::v1_oauth2::oauth2_id_delete,
        super::v1_oauth2::oauth2_id_image_post,
        super::v1_oauth2::oauth2_id_image_delete,
        super::v1_oauth2::oauth2_id_get_basic_secret,
        super::v1_oauth2::oauth2_id_scopemap_post,
        super::v1_oauth2::oauth2_id_scopemap_delete,
        super::v1_oauth2::oauth2_id_sup_scopemap_post,
        super::v1_oauth2::oauth2_id_sup_scopemap_delete,
        super::v1_scim::scim_sync_post,
        super::v1_scim::scim_sync_get,

        super::v1::schema_get,
        super::v1::whoami,
        super::v1::whoami_uat,
        super::v1::applinks_get,
        super::v1::schema_attributetype_get,
        super::v1::schema_attributetype_get_id,
        super::v1::schema_classtype_get,
        super::v1::schema_classtype_get_id,
        super::v1::person_get,
        super::v1::person_post,
        super::v1::service_account_credential_generate,
        super::v1::service_account_api_token_delete,
        super::v1::service_account_api_token_get,
        super::v1::service_account_api_token_post,
        super::v1::person_id_get,
        super::v1::person_id_patch,
        super::v1::person_id_delete,
        super::v1::person_id_get_attr,
        super::v1::person_id_put_attr,
        super::v1::person_id_post_attr,
        super::v1::person_id_delete_attr,
        super::v1::person_get_id_credential_status,
        super::v1::person_id_credential_update_get,
        super::v1::person_id_credential_update_intent_get,
        super::v1::person_id_credential_update_intent_ttl_get,

        super::v1::service_account_id_ssh_pubkeys_get,
        super::v1::service_account_id_ssh_pubkeys_post,

        super::v1::person_id_ssh_pubkeys_get,
        super::v1::person_id_ssh_pubkeys_post,
        super::v1::person_id_ssh_pubkeys_tag_get,
        super::v1::person_id_ssh_pubkeys_tag_delete,

        super::v1::person_id_radius_get,
        super::v1::person_id_radius_post,
        super::v1::person_id_radius_delete,
        super::v1::person_id_radius_token_get,

        super::v1::account_id_ssh_pubkeys_get,
        super::v1::account_id_radius_token_post,
        super::v1::service_account_id_unix_post,
        super::v1::person_id_unix_credential_put,
        super::v1::person_id_unix_credential_delete,
        super::v1::person_identify_user_post,
        super::v1::service_account_get,
        super::v1::service_account_post,
        super::v1::service_account_get,
        super::v1::service_account_post,
        super::v1::service_account_id_get,
        super::v1::service_account_id_delete,
        super::v1::service_account_id_get_attr,
        super::v1::service_account_id_put_attr,
        super::v1::service_account_id_post_attr,
        super::v1::service_account_id_delete_attr,
        super::v1::service_account_into_person,
        super::v1::service_account_api_token_post,
        super::v1::service_account_api_token_get,
        super::v1::service_account_api_token_delete,
        super::v1::service_account_credential_generate,
        super::v1::service_account_id_credential_status_get,
        super::v1::service_account_id_ssh_pubkeys_tag_get,
        super::v1::service_account_id_ssh_pubkeys_tag_delete,
        super::v1::account_id_unix_post,
        super::v1::account_id_unix_auth_post,
        super::v1::account_id_unix_token,
        super::v1::account_id_unix_token,
        super::v1::account_id_radius_token_post,
        super::v1::account_id_radius_token_get,
        super::v1::account_id_ssh_pubkeys_get,
        super::v1::account_id_ssh_pubkeys_tag_get,
        super::v1::account_id_user_auth_token_get,
        super::v1::account_user_auth_token_delete,
        super::v1::credential_update_exchange_intent,
        super::v1::credential_update_status,
        super::v1::credential_update_update,
        super::v1::credential_update_commit,
        super::v1::credential_update_cancel,
        super::v1::domain_get,
        super::v1::domain_attr_get,
        super::v1::domain_attr_put,
        super::v1::domain_attr_delete,
        super::v1::group_id_unix_token_get,
        super::v1::group_id_unix_post,
        super::v1::group_get,
        super::v1::group_post,
        super::v1::group_id_get,
        super::v1::group_id_delete,
        super::v1::group_id_attr_delete,
        super::v1::group_id_attr_get,
        super::v1::group_id_attr_put,
        super::v1::group_id_attr_post,
        super::v1::system_get,
        super::v1::system_attr_get,
        super::v1::system_attr_post,
        super::v1::system_attr_put,
        super::v1::system_attr_delete,
        super::v1::recycle_bin_get,
        super::v1::recycle_bin_id_get,
        super::v1::recycle_bin_revive_id_post,
        super::v1::auth,
        super::v1::auth_valid,
        super::v1::logout,
        super::v1::reauth,
        super::v1_scim::sync_account_post,
        super::v1_scim::sync_account_get,
        super::v1_scim::sync_account_post,
        super::v1_scim::sync_account_id_get,
        super::v1_scim::sync_account_id_patch,
        super::v1_scim::sync_account_id_attr_get,
        super::v1_scim::sync_account_id_attr_put,
        super::v1_scim::sync_account_id_finalise_get,
        super::v1_scim::sync_account_id_terminate_get,
        super::v1_scim::sync_account_token_post,
        super::v1_scim::sync_account_token_delete,
        super::v1::debug_ipinfo,

    ),
    components(
        // TODO: can't add ProtoEntry to schema as this was only recently supported utoipa v3.5.0 doesn't support it - ref <https://github.com/juhaku/utoipa/pull/756/files>
        // schemas(ProtoEntry)

    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "kanidm", description = "Kanidm API")
    ),
    info(
        title = "Kanidm",
        description = "API for interacting with the Kanidm system. This is a work in progress",
        contact( // <https://docs.rs/utoipa-gen/3.5.0/utoipa_gen/derive.OpenApi.html#info-attribute-syntax>
            name="Kanidm",
            url="https://github.com/kanidm/kanidm",
        )
    )
)]
pub(crate) struct ApiDoc;

pub(crate) fn router() -> SwaggerUi {
    SwaggerUi::new("/docs/swagger-ui").url(
        "/docs/v1/openapi.json",
        <ApiDoc as utoipa::OpenApi>::openapi(),
    )
}

#[test]
/// This parses the source code trying to make sure we have API docs for every endpoint we publish.
///
/// It's not perfect, but it's a start!
fn figure_out_if_we_have_all_the_routes() {
    use std::collections::HashMap;

    // load this file
    let my_filename = format!("{}/src/https/apidocs.rs", env!("CARGO_MANIFEST_DIR"));
    // println!("trying to load apidocs source file: {}", my_filename);

    let file = std::fs::read_to_string(&my_filename).unwrap();

    // find all the lines that start with super::v1:: and end with a comma
    let apidocs_function_finder = regex::Regex::new(r#"super::([a-zA-Z0-9_:]+),"#).unwrap();
    let mut apidocs_routes: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for line in file.lines() {
        if let Some(caps) = apidocs_function_finder.captures(line) {
            let route = caps.get(1).unwrap().as_str();
            println!("route: {}", route);
            let mut splitter = route.split("::");

            let module = splitter.next().unwrap();
            let handler = splitter.next().unwrap();
            if !apidocs_routes.contains_key(module) {
                apidocs_routes.insert(module.to_string(), Vec::new());
            }
            apidocs_routes
                .get_mut(module)
                .unwrap()
                .push((handler.to_string(), "unset".to_string()));
        }
    }
    for (module, routes) in apidocs_routes.iter() {
        println!("API Module: {}", module);
        for route in routes {
            println!(" - {} (method: {})", route.0, route.1);
        }
    }

    // this looks for method(handler) axum things
    let routedef_finder =
        regex::Regex::new(r#"(any|delete|get|head|options|patch|post|put|trace)\(([a-z:_]+)\)"#)
            .unwrap();
    // work our way through the source files in this package looking for routedefs
    let mut found_routes: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let walker = walkdir::WalkDir::new(format!("{}/src", env!("CARGO_MANIFEST_DIR")))
        .follow_links(false)
        .into_iter();

    for entry in walker {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            continue;
        }
        println!("checking {}", entry.path().display());
        // because nobody wants to see their project dir all over the place
        let relative_filename = entry
            .path()
            .display()
            .to_string()
            .replace(&format!("{}/", env!("CARGO_MANIFEST_DIR")), "");

        let source_module = relative_filename.split("/").last().unwrap();
        let source_module = source_module.split(".").next().unwrap();

        let file = std::fs::read_to_string(&entry.path()).unwrap();
        for line in file.lines() {
            if line.contains("skip_route_check") {
                println!("Skipping this line because it contains skip_route_check");
                continue;
            }
            if let Some(caps) = routedef_finder.captures(line) {
                let method = caps.get(1).unwrap().as_str();
                let route = caps.get(2).unwrap().as_str();

                if !found_routes.contains_key(source_module) {
                    found_routes.insert(source_module.to_string(), Vec::new());
                }
                let new_route = (route.to_string(), method.to_string());
                println!("Found new route: {} {:?}", source_module, new_route);
                found_routes.get_mut(source_module).unwrap().push(new_route);
            }
        }
    }
    // now we check the things
    for (module, routes) in found_routes {
        if ["ui"].contains(&module.as_str()) {
            println!(
                "We can skip checking {} because it's allow-listed for docs",
                module
            );
            continue;
        }
        if !apidocs_routes.contains_key(&module) {
            panic!("Module {} is missing from the API docs", module);
        }
        // we can't handle the method yet because that's in the derive
        for (route, _method) in routes {
            let mut found_route = false;
            for (apiroute_handler, _method) in apidocs_routes[&module].iter() {
                if &route == apiroute_handler {
                    found_route = true;
                    break;
                }
            }
            if !found_route {
                panic!("couldn't find apidocs route for {}::{}", module, route);
            } else {
                println!("Docs OK: {}::{}", module, route);
            }
        }
    }
}

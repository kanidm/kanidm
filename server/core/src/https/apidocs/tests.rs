#[test]
/// This parses the source code trying to make sure we have API docs for every endpoint we publish.
///
/// It's not perfect, but it's a start!
fn figure_out_if_we_have_all_the_routes() {
    use std::collections::HashMap;

    // load this file
    let module_filename = format!("{}/src/https/apidocs/mod.rs", env!("CARGO_MANIFEST_DIR"));
    println!("trying to load apidocs source file: {}", module_filename);
    let file = std::fs::read_to_string(&module_filename).unwrap();

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

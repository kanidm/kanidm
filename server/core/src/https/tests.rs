#[tokio::test]
async fn test_routes() {
    let routemap = r#"
    [
      {
        "path": "/",
        "method": "GET"
      },
      {
        "path": "/robots.txt",
        "method": "GET"
      },
      {
        "path": "/manifest.webmanifest",
        "method": "GET"
      },
      {
        "path": "/ui/",
        "method": "GET"
      },
      {
        "path": "/ui/*",
        "method": "GET"
      },
      {
        "path": "/v1/account/:id/_unix/_token",
        "method": "GET"
      },
      {
        "path": "/v1/account/:id/_radius/_token",
        "method": "GET"
      },
      {
        "path": "/v1/group/:id/_unix/_token",
        "method": "GET"
      },
      {
        "path": "/v1/oauth2/:rs_name/_icon",
        "method": "GET"
      },
      {
        "path": "/status",
        "method": "GET"
      },
      {
        "path": "/oauth2/authorise",
        "method": "POST"
      },
      {
        "path": "/oauth2/authorise",
        "method": "GET"
      },
      {
        "path": "/oauth2/authorise/permit",
        "method": "POST"
      },
      {
        "path": "/oauth2/authorise/permit",
        "method": "GET"
      },
      {
        "path": "/oauth2/authorise/reject",
        "method": "POST"
      },
      {
        "path": "/oauth2/authorise/reject",
        "method": "GET"
      },
      {
        "path": "/oauth2/token",
        "method": "POST"
      },
      {
        "path": "/oauth2/token/introspect",
        "method": "POST"
      },
      {
        "path": "/oauth2/token/revoke",
        "method": "POST"
      },
      {
        "path": "/oauth2/openid/:client_id/.well-known/openid-configuration",
        "method": "GET"
      },
      {
        "path": "/oauth2/openid/:client_id/userinfo",
        "method": "GET"
      },
      {
        "path": "/oauth2/openid/:client_id/public_key.jwk",
        "method": "GET"
      },
      {
        "path": "/scim/v1/Sync",
        "method": "POST"
      },
      {
        "path": "/scim/v1/Sync",
        "method": "GET"
      },
      {
        "path": "/scim/v1/Sink",
        "method": "GET"
      },
      {
        "path": "/v1/sync_account",
        "method": "GET"
      },
      {
        "path": "/v1/sync_account",
        "method": "POST"
      },
      {
        "path": "/v1/sync_account/:id",
        "method": "GET"
      },
      {
        "path": "/v1/sync_account/:id",
        "method": "PATCH"
      },
      {
        "path": "/v1/sync_account/:id/_finalise",
        "method": "GET"
      },
      {
        "path": "/v1/sync_account/:id/_terminate",
        "method": "GET"
      },
      {
        "path": "/v1/sync_account/:id/_sync_token",
        "method": "POST"
      },
      {
        "path": "/v1/sync_account/:id/_sync_token",
        "method": "DELETE"
      },
      {
        "path": "/v1/raw/create",
        "method": "POST"
      },
      {
        "path": "/v1/raw/modify",
        "method": "POST"
      },
      {
        "path": "/v1/raw/delete",
        "method": "POST"
      },
      {
        "path": "/v1/raw/search",
        "method": "POST"
      },
      {
        "path": "/v1/auth",
        "method": "POST"
      },
      {
        "path": "/v1/auth/valid",
        "method": "GET"
      },
      {
        "path": "/v1/reauth",
        "method": "POST"
      },
      {
        "path": "/v1/logout",
        "method": "GET"
      },
      {
        "path": "/v1/schema",
        "method": "GET"
      },
      {
        "path": "/v1/schema/attributetype",
        "method": "GET"
      },
      {
        "path": "/v1/schema/attributetype",
        "method": "POST"
      },
      {
        "path": "/v1/schema/attributetype/:id",
        "method": "GET"
      },
      {
        "path": "/v1/schema/attributetype/:id",
        "method": "PUT"
      },
      {
        "path": "/v1/schema/attributetype/:id",
        "method": "PATCH"
      },
      {
        "path": "/v1/schema/classtype",
        "method": "GET"
      },
      {
        "path": "/v1/schema/classtype",
        "method": "POST"
      },
      {
        "path": "/v1/schema/classtype/:id",
        "method": "GET"
      },
      {
        "path": "/v1/schema/classtype/:id",
        "method": "PUT"
      },
      {
        "path": "/v1/schema/classtype/:id",
        "method": "PATCH"
      },
      {
        "path": "/v1/oauth2",
        "method": "GET"
      },
      {
        "path": "/v1/oauth2/_basic",
        "method": "POST"
      },
      {
        "path": "/v1/oauth2/:rs_name",
        "method": "GET"
      },
      {
        "path": "/v1/oauth2/:rs_name",
        "method": "PATCH"
      },
      {
        "path": "/v1/oauth2/:rs_name",
        "method": "DELETE"
      },
      {
        "path": "/v1/oauth2/:rs_name/_basic_secret",
        "method": "GET"
      },
      {
        "path": "/v1/oauth2/:id/_scopemap/:group",
        "method": "POST"
      },
      {
        "path": "/v1/oauth2/:id/_scopemap/:group",
        "method": "DELETE"
      },
      {
        "path": "/v1/oauth2/:id/_sup_scopemap/:group",
        "method": "POST"
      },
      {
        "path": "/v1/oauth2/:id/_sup_scopemap/:group",
        "method": "DELETE"
      },
      {
        "path": "/v1/self",
        "method": "GET"
      },
      {
        "path": "/v1/self/_uat",
        "method": "GET"
      },
      {
        "path": "/v1/self/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/self/_credential",
        "method": "GET"
      },
      {
        "path": "/v1/self/_credential/:cid/_lock",
        "method": "GET"
      },
      {
        "path": "/v1/self/_radius",
        "method": "GET"
      },
      {
        "path": "/v1/self/_radius",
        "method": "DELETE"
      },
      {
        "path": "/v1/self/_radius",
        "method": "POST"
      },
      {
        "path": "/v1/self/_radius/_config",
        "method": "POST"
      },
      {
        "path": "/v1/self/_radius/_config/:token",
        "method": "GET"
      },
      {
        "path": "/v1/self/_radius/_config/:token/apple",
        "method": "GET"
      },
      {
        "path": "/v1/self/_applinks",
        "method": "GET"
      },
      {
        "path": "/v1/person",
        "method": "GET"
      },
      {
        "path": "/v1/person",
        "method": "POST"
      },
      {
        "path": "/v1/person/:id",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id",
        "method": "PATCH"
      },
      {
        "path": "/v1/person/:id",
        "method": "DELETE"
      },
      {
        "path": "/v1/person/:id/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_attr/:attr",
        "method": "PUT"
      },
      {
        "path": "/v1/person/:id/_attr/:attr",
        "method": "POST"
      },
      {
        "path": "/v1/person/:id/_attr/:attr",
        "method": "DELETE"
      },
      {
        "path": "/v1/person/:id/_lock",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_credential",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_credential/_status",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_credential/:cid/_lock",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_credential/_update",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_credential/_update_intent",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_credential/_update_intent/:ttl",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_ssh_pubkeys",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_ssh_pubkeys",
        "method": "POST"
      },
      {
        "path": "/v1/person/:id/_ssh_pubkeys/:tag",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_ssh_pubkeys/:tag",
        "method": "DELETE"
      },
      {
        "path": "/v1/person/:id/_radius",
        "method": "GET"
      },
      {
        "path": "/v1/person/:id/_radius",
        "method": "POST"
      },
      {
        "path": "/v1/person/:id/_radius",
        "method": "DELETE"
      },
      {
        "path": "/v1/person/:id/_unix",
        "method": "POST"
      },
      {
        "path": "/v1/person/:id/_unix/_credential",
        "method": "PUT"
      },
      {
        "path": "/v1/person/:id/_unix/_credential",
        "method": "DELETE"
      },
      {
        "path": "/v1/service_account",
        "method": "GET"
      },
      {
        "path": "/v1/service_account",
        "method": "POST"
      },
      {
        "path": "/v1/service_account/:id",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id",
        "method": "PATCH"
      },
      {
        "path": "/v1/service_account/:id",
        "method": "DELETE"
      },
      {
        "path": "/v1/service_account/:id/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_attr/:attr",
        "method": "PUT"
      },
      {
        "path": "/v1/service_account/:id/_attr/:attr",
        "method": "POST"
      },
      {
        "path": "/v1/service_account/:id/_attr/:attr",
        "method": "DELETE"
      },
      {
        "path": "/v1/service_account/:id/_lock",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_into_person",
        "method": "POST"
      },
      {
        "path": "/v1/service_account/:id/_api_token",
        "method": "POST"
      },
      {
        "path": "/v1/service_account/:id/_api_token",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_api_token/:token_id",
        "method": "DELETE"
      },
      {
        "path": "/v1/service_account/:id/_credential",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_credential/_generate",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_credential/_status",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_credential/:cid/_lock",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_ssh_pubkeys",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_ssh_pubkeys",
        "method": "POST"
      },
      {
        "path": "/v1/service_account/:id/_ssh_pubkeys/:tag",
        "method": "GET"
      },
      {
        "path": "/v1/service_account/:id/_ssh_pubkeys/:tag",
        "method": "DELETE"
      },
      {
        "path": "/v1/service_account/:id/_unix",
        "method": "POST"
      },
      {
        "path": "/v1/account/:id/_unix/_auth",
        "method": "POST"
      },
      {
        "path": "/v1/account/:id/_ssh_pubkeys",
        "method": "GET"
      },
      {
        "path": "/v1/account/:id/_ssh_pubkeys/:tag",
        "method": "GET"
      },
      {
        "path": "/v1/account/:id/_user_auth_token",
        "method": "GET"
      },
      {
        "path": "/v1/account/:id/_user_auth_token/:token_id",
        "method": "DELETE"
      },
      {
        "path": "/v1/credential/_exchange_intent",
        "method": "POST"
      },
      {
        "path": "/v1/credential/_status",
        "method": "POST"
      },
      {
        "path": "/v1/credential/_update",
        "method": "POST"
      },
      {
        "path": "/v1/credential/_commit",
        "method": "POST"
      },
      {
        "path": "/v1/credential/_cancel",
        "method": "POST"
      },
      {
        "path": "/v1/group",
        "method": "GET"
      },
      {
        "path": "/v1/group",
        "method": "POST"
      },
      {
        "path": "/v1/group/:id",
        "method": "GET"
      },
      {
        "path": "/v1/group/:id",
        "method": "DELETE"
      },
      {
        "path": "/v1/group/:id/_attr/:attr",
        "method": "DELETE"
      },
      {
        "path": "/v1/group/:id/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/group/:id/_attr/:attr",
        "method": "PUT"
      },
      {
        "path": "/v1/group/:id/_attr/:attr",
        "method": "POST"
      },
      {
        "path": "/v1/group/:id/_unix",
        "method": "POST"
      },
      {
        "path": "/v1/domain",
        "method": "GET"
      },
      {
        "path": "/v1/domain/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/domain/_attr/:attr",
        "method": "PUT"
      },
      {
        "path": "/v1/domain/_attr/:attr",
        "method": "DELETE"
      },
      {
        "path": "/v1/system",
        "method": "GET"
      },
      {
        "path": "/v1/system/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/system/_attr/:attr",
        "method": "POST"
      },
      {
        "path": "/v1/system/_attr/:attr",
        "method": "DELETE"
      },
      {
        "path": "/v1/recycle_bin",
        "method": "GET"
      },
      {
        "path": "/v1/recycle_bin/:id",
        "method": "GET"
      },
      {
        "path": "/v1/recycle_bin/:id/_revive",
        "method": "POST"
      },
      {
        "path": "/v1/access_profile",
        "method": "GET"
      },
      {
        "path": "/v1/access_profile/:id",
        "method": "GET"
      },
      {
        "path": "/v1/access_profile/:id/_attr/:attr",
        "method": "GET"
      },
      {
        "path": "/v1/routemap",
        "method": "GET"
      }
    ]
  "#;
    let routelist: Vec<serde_json::Value> = serde_json::from_str(routemap).unwrap();
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .https_only(true)
        .build()
        .unwrap();
    for route in routelist {
        // println!("{:?}", route);
        let path: String = route.get("path").unwrap().to_string();
        let method: String = route.get("method").unwrap().to_string();
        let method = method.replace('"', "");
        let method = method.as_str();
        println!("'{method}'");
        let method = match method {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "PUT" => reqwest::Method::PUT,
            _ => todo!("{}", method),
        };
        let url = format!("https://kanidm.yaleman.org{}", path.replace('"', ""));
        if path.contains(':') {
            println!("Can't do this because it has an attribute: {}", path);
            continue;
        }

        println!("{:?} {} {}", method, path, url);

        let res = client
            .request(method, url)
            .version(http::Version::HTTP_11)
            .send()
            .await
            .unwrap();
        assert!(res.status() != 404);
    }
}

//! Integration tests using browser automation

// use std::process::Output;

// use tempfile::tempdir;

use kanidm_client::KanidmClient;
use kanidmd_lib::constants::EntryClass;
use kanidmd_testkit::login_put_admin_idm_admins;
// use testkit_macros::cli_kanidm;

/// Tries to handle closing the webdriver session if there's an error
#[allow(unused_macros)]
macro_rules! handle_error {
    ($client:ident, $e:expr, $msg:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => {
                $client.close().await.unwrap();
                panic!("{:?}: {:?}", $msg, e);
            }
        }
    };
}

/// Tries to get the webdriver client, trying the default chromedriver port if the default selenium port doesn't work
#[allow(dead_code)]
#[cfg(all(feature = "webdriver", any(test, debug_assertions)))]
async fn get_webdriver_client() -> fantoccini::Client {
    use fantoccini::wd::Capabilities;
    use serde_json::json;

    // check if the env var "CI" is set
    let in_ci = match std::env::var("CI") {
        Ok(_) => true,
        Err(_) => false,
    };
    if !in_ci {
        match fantoccini::ClientBuilder::native()
            .connect("http://localhost:4444")
            .await
        {
            Ok(val) => val,
            Err(_) => {
                // trying the default chromedriver port
                eprintln!("Couldn't connect on 4444, trying 9515");
                fantoccini::ClientBuilder::new(hyper_tls::HttpsConnector::new())
                    .connect("http://localhost:9515")
                    .await
                    .unwrap()
            }
        }
    } else {
        println!("In CI setting headless and assuming Chrome");
        let cap = json!({
            "goog:chromeOptions" : {
                "args" : ["--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--window-size=1280,1024"]
            }
        });
        let cap: Capabilities = serde_json::from_value(cap).unwrap();
        fantoccini::ClientBuilder::new(hyper_tls::HttpsConnector::new())
            .capabilities(cap)
            .connect("http://localhost:9515")
            .await
            .unwrap()
    }
}

#[kanidmd_testkit::test]
#[cfg(feature = "webdriver")]
async fn test_webdriver_user_login(rsclient: kanidm_client::KanidmClient) {
    if !cfg!(feature = "webdriver") {
        println!("Skipping test as webdriver feature is not enabled!");
        return;
    }

    use fantoccini::elements::Element;
    use fantoccini::Locator;
    use kanidmd_testkit::*;
    use std::time::Duration;
    login_put_admin_idm_admins(&rsclient).await;

    create_user_with_all_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        Some(NOT_ADMIN_TEST_PASSWORD),
    )
    .await;

    let c = get_webdriver_client().await;

    handle_error!(
        c,
        c.goto(&rsclient.get_url().to_string()).await,
        "Couldn't get URL"
    );

    println!("Waiting for page to load");
    let mut wait_attempts = 0;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_micros(200)).await;
        c.wait();

        if c.find(Locator::Id("username")).await.is_ok() {
            break;
        }
        wait_attempts += 1;
        if wait_attempts > 10 {
            panic!("Couldn't find username field after 10 attempts!");
        }
    }

    let id = handle_error!(
        c,
        c.find(Locator::Id("username")).await,
        "Couldn't find input id=username"
    );
    handle_error!(c, id.click().await, "Couldn't click the username input?");

    handle_error!(
        c,
        id.send_keys(NOT_ADMIN_TEST_USERNAME).await,
        "Couldn't type the password?"
    );

    let username_form = handle_error!(
        c,
        c.form(Locator::Id("login")).await,
        "Coudln't find login form"
    );
    handle_error!(
        c,
        username_form.submit().await,
        "Couldn't submit username-login form"
    );
    c.wait();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let password_form = handle_error!(
        c,
        c.form(Locator::Id("login")).await,
        "Coudln't find login form"
    );
    let id = handle_error!(
        c,
        c.find(Locator::Id("password")).await,
        "Couldn't find input id=password"
    );
    handle_error!(c, id.click().await, "Couldn't click the username input?");

    handle_error!(
        c,
        id.send_keys(NOT_ADMIN_TEST_PASSWORD).await,
        "Couldn't type the password?"
    );
    handle_error!(
        c,
        password_form.submit().await,
        "Couldn't submit password-login form"
    );
    c.wait();

    // try clicking the nav links
    let mut navlinks: Vec<Element> = vec![];
    let mut navlinks_attempts = 0;
    while navlinks.is_empty() {
        navlinks = handle_error!(
            c,
            c.find_all(Locator::Css(".nav-link")).await,
            "Couldn't find nav-link CSS items"
        );
        navlinks_attempts += 1;
        tokio::time::sleep(Duration::from_millis(200)).await;
        if navlinks_attempts > 10 {
            panic!("Couldn't find navlinks after 2 seconds!");
        }
    }
    println!("Found navlinks: {:?}", navlinks);

    for link in navlinks {
        println!("Clicking {:?}", link.text().await);
        handle_error!(c, link.click().await, &format!("Couldn't click {:?}", link));
        if let Ok(text) = link.text().await {
            if text.to_lowercase() == "sign out" {
                println!("looking for the sign out modal to click the cancel button...");
                tokio::time::sleep(Duration::from_secs(1)).await;
                println!("Found the sign out modal, clicking the cancel button");
                // find the cancel button and click it
                let buttons = handle_error!(
                    c,
                    c.find_all(Locator::Css(".btn")).await,
                    "Couldn't find CSS 'btn' items"
                );
                println!("Found the following buttons: {:?}", buttons);
                for button in buttons {
                    if let Ok(text) = button.text().await {
                        if text == "Cancel" {
                            println!("Found the sign out cancel button, clicking it");
                            handle_error!(c, button.click().await, "Couldn't click cancel button");
                            break;
                        }
                    }
                }
            }
        }
    }
    // tokio::time::sleep(Duration::from_millis(3000)).await;
}

#[kanidmd_testkit::test]
async fn test_domain_reset_token_key(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;
    assert!(rsclient.idm_domain_reset_token_key().await.is_ok());
}

#[kanidmd_testkit::test]
async fn test_idm_domain_set_ldap_basedn(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;
    assert!(rsclient
        .idm_domain_set_ldap_basedn("dc=krabsarekool,dc=example,dc=com")
        .await
        .is_ok());
    assert!(rsclient
        .idm_domain_set_ldap_basedn("krabsarekool")
        .await
        .is_err());
}

#[kanidmd_testkit::test]
/// Checks that a built-in group idm_all_persons has the "builtin" class as expected.
async fn test_all_persons_has_builtin_class(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;
    let res = rsclient
        .idm_group_get("idm_all_persons")
        .await
        .expect("Failed to get idm_all_persons");
    eprintln!("res: {:?}", res);

    assert!(res
        .unwrap()
        .attrs
        .get("class")
        .unwrap()
        .contains(&EntryClass::Builtin.as_ref().into()));
}

// /// run a test command as the admin user
// fn test_cmd_admin(token_cache_path: &str, rsclient: &KanidmClient, cmd: &str) -> Output {
//     let split_cmd: Vec<&str> = cmd.split_ascii_whitespace().collect();
//     test_cmd_admin_split(token_cache_path, rsclient, &split_cmd)
// }
// /// run a test command as the admin user
// fn test_cmd_admin_split(token_cache_path: &str, rsclient: &KanidmClient, cmd: &[&str]) -> Output {
//     println!(
//         "##################################\nrunning {}\n##################################",
//         cmd.join(" ")
//     );
//     let res = cli_kanidm!()
//         .env("KANIDM_PASSWORD", ADMIN_TEST_PASSWORD)
//         .args(cmd)
//         .output()
//         .unwrap();
//     println!("############ result ##################");
//     println!("status: {:?}", res.status);
//     println!("stdout: {}", String::from_utf8_lossy(&res.stdout));
//     println!("stderr: {}", String::from_utf8_lossy(&res.stderr));
//     println!("######################################");
//     assert!(res.status.success());
//     res
// }

// /// run a test command as the idm_admin user
// fn test_cmd_idm_admin(token_cache_path: &str, rsclient: &KanidmClient, cmd: &str) -> Output {
//     println!("##############################\nrunning {}", cmd);
//     let res = cli_kanidm!()
//         .env("KANIDM_PASSWORD", IDM_ADMIN_TEST_PASSWORD)
//         .args(cmd.split(" "))
//         .output()
//         .unwrap();
//     println!("##############################\n{} result: {:?}", cmd, res);
//     assert!(res.status.success());
//     res
// }

// Disabled due to inconsistent test failures and blocking
/*
#[kanidmd_testkit::test]
/// Testing the CLI doing things.
async fn test_integration_with_assert_cmd(rsclient: KanidmClient) {
    // setup the admin things
    login_put_admin_idm_admins(&rsclient).await;

    rsclient
        .idm_person_account_primary_credential_set_password(
            IDM_ADMIN_TEST_USER,
            IDM_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect(&format!("Failed to set {} password", IDM_ADMIN_TEST_USER));

    let token_cache_dir = tempdir().unwrap();
    let token_cache_path = format!("{}/kanidm_tokens", token_cache_dir.path().display());

    // we have to spawn in another thread for ... reasons
    assert!(tokio::task::spawn_blocking(move || {
        let anon_login = cli_kanidm!()
            .args(&["login", "-D", "anonymous"])
            .output()
            .unwrap();
        println!("Login Output: {:?}", anon_login);

        let anon_whoami = cli_kanidm!()
            .args(&["self", "whoami", "-D", "anonymous"])
            .output()
            .unwrap();
        assert!(anon_whoami.status.success());
        println!("Output: {:?}", anon_whoami);

        test_cmd_admin(&token_cache_path, &rsclient, "login -D admin");

        // login as idm_admin
        test_cmd_idm_admin(&token_cache_path, &rsclient, "login -D idm_admin");
        test_cmd_admin_split(
            &token_cache_path,
            &rsclient,
            &[
                "service-account",
                "create",
                NOT_ADMIN_TEST_USERNAME,
                "Test account",
                "-D",
                "admin",
                "-o",
                "json",
            ],
        );

        test_cmd_admin(
            &token_cache_path,
            &rsclient,
            &format!("service-account get -D admin {}", NOT_ADMIN_TEST_USERNAME),
        );
        // updating the display name
        test_cmd_admin(
            &token_cache_path,
            &rsclient,
            &format!(
                "service-account update -D admin {} --displayname cheeseballs",
                NOT_ADMIN_TEST_USERNAME
            ),
        );
        // updating the email
        test_cmd_admin(
            &token_cache_path,
            &rsclient,
            &format!(
                "service-account update -D admin {} --mail foo@bar.com",
                NOT_ADMIN_TEST_USERNAME
            ),
        );

        // checking the email was changed
        let sad = test_cmd_admin(
            &token_cache_path,
            &rsclient,
            &format!(
                "service-account get -D admin -o json {}",
                NOT_ADMIN_TEST_USERNAME
            ),
        );
        let str_output: String = String::from_utf8_lossy(&sad.stdout).into();
        assert!(str_output.contains("foo@bar.com"));

        true
    })
    .await
    .unwrap());
    println!("Success!");
}
*/

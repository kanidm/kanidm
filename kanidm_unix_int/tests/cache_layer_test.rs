use std::net::TcpStream;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::Duration;

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, IntegrationTestConfig};
use kanidm::core::create_server_core;

use kanidm_unix_common::cache::{CacheLayer, Id};
use kanidm_unix_common::constants::{
    DEFAULT_GID_ATTR_MAP, DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX,
    DEFAULT_SHELL, DEFAULT_UID_ATTR_MAP,
};
use tokio::runtime::Runtime;

use kanidm_client::asynchronous::KanidmAsyncClient;
use kanidm_client::{KanidmClient, KanidmClientBuilder};

use async_std::task;
use tokio::sync::mpsc;

static PORT_ALLOC: AtomicU16 = AtomicU16::new(28080);
const ADMIN_TEST_PASSWORD: &str = "integration test admin password";
const TESTACCOUNT1_PASSWORD_A: &str = "password a for account1 test";
const TESTACCOUNT1_PASSWORD_B: &str = "password b for account1 test";
const TESTACCOUNT1_PASSWORD_INC: &str = "never going to work";
const ACCOUNT_EXPIRE: &str = "1970-01-01T00:00:00+00:00";

fn is_free_port(port: u16) -> bool {
    match TcpStream::connect(("0.0.0.0", port)) {
        Ok(_) => false,
        Err(_) => true,
    }
}

fn run_test(fix_fn: fn(&mut KanidmClient) -> (), test_fn: fn(CacheLayer, KanidmAsyncClient) -> ()) {
    // ::std::env::set_var("RUST_LOG", "kanidm=debug");
    let _ = env_logger::builder().is_test(true).try_init();

    let (ready_tx, mut ready_rx) = mpsc::channel(1);
    let (finish_tx, mut finish_rx) = mpsc::channel(1);

    let mut counter = 0;
    let port = loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        if counter >= 5 {
            eprintln!("Unable to allocate port!");
            assert!(false);
        }
    };

    let int_config = Box::new(IntegrationTestConfig {
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
    });

    // Setup the config ...
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.secure_cookies = false;
    config.integration_test_config = Some(int_config);
    config.log_level = Some(LogLevel::Quiet as u32);
    // config.log_level = Some(LogLevel::Verbose as u32);
    config.threads = 1;

    let t_handle = thread::spawn(move || {
        // Spawn a thread for the test runner, this should have a unique
        // port....
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start tokio");
        rt.block_on(async {
            create_server_core(config)
                .await
                .expect("failed to start server core");
            // We have to yield now to guarantee that the tide elements are setup.
            task::yield_now().await;
            ready_tx
                .send(())
                .await
                .expect("failed in indicate readiness");
            finish_rx.recv().await;
        });
    });

    let _ = task::block_on(ready_rx.recv()).expect("failed to start ctx");
    // Setup the client, and the address we selected.
    let addr = format!("http://127.0.0.1:{}", port);

    // Run fixtures
    let mut adminclient = KanidmClientBuilder::new()
        .address(addr.clone())
        .build()
        .expect("Failed to build sync client");
    fix_fn(&mut adminclient);

    let client = KanidmClientBuilder::new()
        .address(addr.clone())
        .build_async()
        .expect("Failed to build async admin client");

    let rsclient = KanidmClientBuilder::new()
        .address(addr)
        .build_async()
        .expect("Failed to build client");

    let cachelayer = task::block_on(CacheLayer::new(
        "", // The sqlite db path, this is in memory.
        300,
        rsclient,
        vec!["allowed_group".to_string()],
        DEFAULT_SHELL.to_string(),
        DEFAULT_HOME_PREFIX.to_string(),
        DEFAULT_HOME_ATTR,
        DEFAULT_HOME_ALIAS,
        DEFAULT_UID_ATTR_MAP,
        DEFAULT_GID_ATTR_MAP,
    ))
    .expect("Failed to build cache layer.");

    test_fn(cachelayer, client);

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
    task::block_on(finish_tx.send(())).expect("unable to send to ctx");
    t_handle.join().expect("failed to join thread");
}

fn test_fixture(rsclient: &mut KanidmClient) -> () {
    let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
    assert!(res.is_ok());
    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .unwrap();

    // Create a new account
    rsclient
        .idm_account_create("testaccount1", "Posix Demo Account")
        .unwrap();

    // Extend the account with posix attrs.
    rsclient
        .idm_account_unix_extend("testaccount1", Some(20000), None)
        .unwrap();
    // Assign an ssh public key.
    rsclient
        .idm_account_post_ssh_pubkey("testaccount1", "tk",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst")
        .unwrap();
    // Set a posix password
    rsclient
        .idm_account_unix_cred_put("testaccount1", TESTACCOUNT1_PASSWORD_A)
        .unwrap();

    // Setup a group
    rsclient.idm_group_create("testgroup1").unwrap();
    rsclient
        .idm_group_add_members("testgroup1", &["testaccount1"])
        .unwrap();
    rsclient
        .idm_group_unix_extend("testgroup1", Some(20001))
        .unwrap();

    // Setup the allowed group
    rsclient.idm_group_create("allowed_group").unwrap();
    rsclient
        .idm_group_unix_extend("allowed_group", Some(20002))
        .unwrap();
}

#[test]
fn test_cache_sshkey() {
    run_test(test_fixture, |cachelayer, _adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            // Force offline. Show we have no keys.
            cachelayer.mark_offline().await;

            let sk = cachelayer
                .get_sshkeys("testaccount1")
                .await
                .expect("Failed to get from cache.");
            assert!(sk.len() == 0);

            // Bring ourselves online.
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);

            let sk = cachelayer
                .get_sshkeys("testaccount1")
                .await
                .expect("Failed to get from cache.");
            assert!(sk.len() == 1);

            // Go offline, and get from cache.
            cachelayer.mark_offline().await;
            let sk = cachelayer
                .get_sshkeys("testaccount1")
                .await
                .expect("Failed to get from cache.");
            assert!(sk.len() == 1);
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_account() {
    run_test(test_fixture, |cachelayer, _adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            // Force offline. Show we have no account
            cachelayer.mark_offline().await;

            let ut = cachelayer
                .get_nssaccount_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_none());

            // go online
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);

            // get the account
            let ut = cachelayer
                .get_nssaccount_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_some());

            // go offline
            cachelayer.mark_offline().await;

            // can still get account
            let ut = cachelayer
                .get_nssaccount_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_some());

            // Finally, check we have "all accounts" in the list.
            let us = cachelayer
                .get_nssaccounts()
                .await
                .expect("failed to list all accounts");
            assert!(us.len() == 1);
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_group() {
    run_test(test_fixture, |cachelayer, _adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            // Force offline. Show we have no groups.
            cachelayer.mark_offline().await;
            let gt = cachelayer
                .get_nssgroup_name("testgroup1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_none());

            // go online. Get the group
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);
            let gt = cachelayer
                .get_nssgroup_name("testgroup1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_some());

            // go offline. still works
            cachelayer.mark_offline().await;
            let gt = cachelayer
                .get_nssgroup_name("testgroup1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_some());
            // And check we have no members in the group. Members are an artifact of
            // user lookups!
            assert!(gt.unwrap().members.len() == 0);

            // clear cache, go online
            assert!(cachelayer.invalidate().await.is_ok());
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);

            // get an account with the group
            // DO NOT get the group yet.
            let ut = cachelayer
                .get_nssaccount_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_some());

            // go offline.
            cachelayer.mark_offline().await;

            // show we have the group despite no direct calls
            let gt = cachelayer
                .get_nssgroup_name("testgroup1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_some());
            // And check we have members in the group, since we came from a userlook up
            assert!(gt.unwrap().members.len() == 1);

            // Finally, check we have "all groups" in the list.
            let gs = cachelayer
                .get_nssgroups()
                .await
                .expect("failed to list all groups");
            assert!(gs.len() == 2);
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_group_delete() {
    run_test(test_fixture, |cachelayer, mut adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            // get the group
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);
            let gt = cachelayer
                .get_nssgroup_name("testgroup1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_some());

            // delete it.
            adminclient
                .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
                .await
                .expect("failed to auth as admin");
            adminclient
                .idm_group_delete("testgroup1")
                .await
                .expect("failed to delete");

            // invalidate cache
            assert!(cachelayer.invalidate().await.is_ok());

            // "get it"
            // should be empty.
            let gt = cachelayer
                .get_nssgroup_name("testgroup1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_none());
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_account_delete() {
    run_test(test_fixture, |cachelayer, mut adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            // get the account
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);
            let ut = cachelayer
                .get_nssaccount_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_some());

            // delete it.
            adminclient
                .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
                .await
                .expect("failed to auth as admin");
            adminclient
                .idm_account_delete("testaccount1")
                .await
                .expect("failed to delete");

            // invalidate cache
            assert!(cachelayer.invalidate().await.is_ok());

            // "get it"
            let ut = cachelayer
                .get_nssaccount_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            // should be empty.
            assert!(ut.is_none());

            // The group should be removed too.
            let gt = cachelayer
                .get_nssgroup_name("testaccount1")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_none());
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_account_password() {
    run_test(test_fixture, |cachelayer, mut adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            cachelayer.attempt_online().await;
            // Test authentication failure.
            let a1 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_INC)
                .await
                .expect("failed to authenticate");
            assert!(a1 == Some(false));

            // We have to wait due to softlocking.
            task::sleep(Duration::from_secs(1)).await;

            // Test authentication success.
            let a2 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_A)
                .await
                .expect("failed to authenticate");
            assert!(a2 == Some(true));

            // change pw
            adminclient
                .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
                .await
                .expect("failed to auth as admin");
            adminclient
                .idm_account_unix_cred_put("testaccount1", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("Failed to change password");

            // test auth (old pw) fail
            let a3 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_A)
                .await
                .expect("failed to authenticate");
            assert!(a3 == Some(false));

            // We have to wait due to softlocking.
            task::sleep(Duration::from_secs(1)).await;

            // test auth (new pw) success
            let a4 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("failed to authenticate");
            assert!(a4 == Some(true));

            // Go offline.
            cachelayer.mark_offline().await;

            // Test auth success
            let a5 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("failed to authenticate");
            assert!(a5 == Some(true));

            // No softlock during offline.

            // Test auth failure.
            let a6 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_INC)
                .await
                .expect("failed to authenticate");
            assert!(a6 == Some(false));

            // clear cache
            cachelayer
                .clear_cache()
                .await
                .expect("failed to clear cache");

            // test auth good (fail)
            let a7 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("failed to authenticate");
            assert!(a7 == None);

            // go online
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);

            // test auth success
            let a8 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("failed to authenticate");
            assert!(a8 == Some(true));
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_account_pam_allowed() {
    run_test(test_fixture, |cachelayer, mut adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            cachelayer.attempt_online().await;

            // Should fail
            let a1 = cachelayer
                .pam_account_allowed("testaccount1")
                .await
                .expect("failed to authenticate");
            assert!(a1 == Some(false));

            adminclient
                .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
                .await
                .expect("failed to auth as admin");
            adminclient
                .idm_group_add_members("allowed_group", vec!["testaccount1"])
                .await
                .unwrap();

            // Invalidate cache to force a refresh
            assert!(cachelayer.invalidate().await.is_ok());

            // Should pass
            let a2 = cachelayer
                .pam_account_allowed("testaccount1")
                .await
                .expect("failed to authenticate");
            assert!(a2 == Some(true));
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_account_pam_nonexist() {
    run_test(test_fixture, |cachelayer, _adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            cachelayer.attempt_online().await;

            let a1 = cachelayer
                .pam_account_allowed("NO_SUCH_ACCOUNT")
                .await
                .expect("failed to authenticate");
            assert!(a1 == None);

            let a2 = cachelayer
                .pam_account_authenticate("NO_SUCH_ACCOUNT", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("failed to authenticate");
            assert!(a2 == None);

            cachelayer.mark_offline().await;

            let a1 = cachelayer
                .pam_account_allowed("NO_SUCH_ACCOUNT")
                .await
                .expect("failed to authenticate");
            assert!(a1 == None);

            let a2 = cachelayer
                .pam_account_authenticate("NO_SUCH_ACCOUNT", TESTACCOUNT1_PASSWORD_B)
                .await
                .expect("failed to authenticate");
            assert!(a2 == None);
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_account_expiry() {
    run_test(test_fixture, |cachelayer, mut adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);

            // We need one good auth first to prime the cache with a hash.
            let a1 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_A)
                .await
                .expect("failed to authenticate");
            assert!(a1 == Some(true));
            // Invalidate to make sure we go online next checks.
            assert!(cachelayer.invalidate().await.is_ok());

            // expire the account
            adminclient
                .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
                .await
                .expect("failed to auth as admin");
            adminclient
                .idm_account_set_attr("testaccount1", "account_expire", &[ACCOUNT_EXPIRE])
                .await
                .unwrap();
            // auth will fail
            let a2 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_A)
                .await
                .expect("failed to authenticate");
            assert!(a2 == Some(false));

            // ssh keys should be empty
            let sk = cachelayer
                .get_sshkeys("testaccount1")
                .await
                .expect("Failed to get from cache.");
            assert!(sk.len() == 0);

            // Pam account allowed should be denied.
            let a3 = cachelayer
                .pam_account_allowed("testaccount1")
                .await
                .expect("failed to authenticate");
            assert!(a3 == Some(false));

            // go offline
            cachelayer.mark_offline().await;

            // Now, check again ...
            let a4 = cachelayer
                .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_A)
                .await
                .expect("failed to authenticate");
            assert!(a4 == Some(false));

            // ssh keys should be empty
            let sk = cachelayer
                .get_sshkeys("testaccount1")
                .await
                .expect("Failed to get from cache.");
            assert!(sk.len() == 0);

            // Pam account allowed should be denied.
            let a5 = cachelayer
                .pam_account_allowed("testaccount1")
                .await
                .expect("failed to authenticate");
            assert!(a5 == Some(false));
        };
        rt.block_on(fut);
    })
}

#[test]
fn test_cache_nxcache() {
    run_test(test_fixture, |cachelayer, mut _adminclient| {
        let rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            cachelayer.attempt_online().await;
            assert!(cachelayer.test_connection().await);
            // Is it in the nxcache?

            assert!(
                !cachelayer
                    .check_nxcache(&Id::Name("root".to_string()))
                    .await
            );
            assert!(!cachelayer.check_nxcache(&Id::Gid(0)).await);
            assert!(
                !cachelayer
                    .check_nxcache(&Id::Name("root_group".to_string()))
                    .await
            );
            assert!(!cachelayer.check_nxcache(&Id::Gid(1)).await);

            // Look for the acc id + nss id
            let ut = cachelayer
                .get_nssaccount_name("root")
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_none());
            let ut = cachelayer
                .get_nssaccount_gid(0)
                .await
                .expect("Failed to get from cache");
            assert!(ut.is_none());

            let gt = cachelayer
                .get_nssgroup_name("root_group")
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_none());
            let gt = cachelayer
                .get_nssgroup_gid(1)
                .await
                .expect("Failed to get from cache");
            assert!(gt.is_none());

            // Should all now be nxed
            assert!(
                cachelayer
                    .check_nxcache(&Id::Name("root".to_string()))
                    .await
            );
            assert!(cachelayer.check_nxcache(&Id::Gid(0)).await);
            assert!(
                cachelayer
                    .check_nxcache(&Id::Name("root_group".to_string()))
                    .await
            );
            assert!(cachelayer.check_nxcache(&Id::Gid(1)).await);

            // invalidate cache
            assert!(cachelayer.invalidate().await.is_ok());

            // Both should NOT be in nxcache now.
            assert!(
                !cachelayer
                    .check_nxcache(&Id::Name("root".to_string()))
                    .await
            );
            assert!(!cachelayer.check_nxcache(&Id::Gid(0)).await);
            assert!(
                !cachelayer
                    .check_nxcache(&Id::Name("root_group".to_string()))
                    .await
            );
            assert!(!cachelayer.check_nxcache(&Id::Gid(1)).await);
        };
        rt.block_on(fut);
    })
}

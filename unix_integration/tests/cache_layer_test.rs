#![deny(warnings)]
use std::future::Future;
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_unix_common::cache::{CacheLayer, Id};
use kanidm_unix_common::constants::{
    DEFAULT_GID_ATTR_MAP, DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX,
    DEFAULT_SHELL, DEFAULT_UID_ATTR_MAP,
};
use kanidm_unix_common::unix_config::TpmPolicy;
use kanidmd_core::config::{Configuration, IntegrationTestConfig, ServerRole};
use kanidmd_core::create_server_core;
use tokio::task;
use tracing::log::debug;

static PORT_ALLOC: AtomicU16 = AtomicU16::new(28080);
const ADMIN_TEST_USER: &str = "admin";
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

type Fixture = Box<dyn FnOnce(KanidmClient) -> Pin<Box<dyn Future<Output = ()>>>>;

fn fixture<T>(f: fn(KanidmClient) -> T) -> Fixture
where
    T: Future<Output = ()> + 'static,
{
    Box::new(move |n| Box::pin(f(n)))
}

async fn setup_test(fix_fn: Fixture) -> (CacheLayer, KanidmClient) {
    sketching::test_init();

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
        admin_user: ADMIN_TEST_USER.to_string(),
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
    });

    // Setup the config ...
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.secure_cookies = false;
    config.integration_test_config = Some(int_config);
    config.role = ServerRole::WriteReplicaNoUI;
    config.threads = 1;

    create_server_core(config, false)
        .await
        .expect("failed to start server core");
    // We have to yield now to guarantee that the tide elements are setup.
    task::yield_now().await;

    // Setup the client, and the address we selected.
    let addr = format!("http://127.0.0.1:{}", port);

    // Run fixtures
    let adminclient = KanidmClientBuilder::new()
        .address(addr.clone())
        .no_proxy()
        .build()
        .expect("Failed to build sync client");

    fix_fn(adminclient).await;

    let client = KanidmClientBuilder::new()
        .address(addr.clone())
        .no_proxy()
        .build()
        .expect("Failed to build async admin client");

    let rsclient = KanidmClientBuilder::new()
        .address(addr)
        .no_proxy()
        .build()
        .expect("Failed to build client");

    let cachelayer = CacheLayer::new(
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
        vec!["masked_group".to_string()],
        &TpmPolicy::default(),
    )
    .await
    .expect("Failed to build cache layer.");

    // test_fn(cachelayer, client);
    (cachelayer, client)
    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
}

async fn test_fixture(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    debug!("auth_simple_password res: {:?}", res);
    assert!(res.is_ok());
    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_person_account_create("testaccount1", "Posix Demo Account")
        .await
        .unwrap();

    // Extend the account with posix attrs.
    rsclient
        .idm_person_account_unix_extend("testaccount1", Some(20000), None)
        .await
        .unwrap();
    // Assign an ssh public key.
    rsclient
        .idm_person_account_post_ssh_pubkey("testaccount1", "tk",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst")
        .await
        .unwrap();
    // Set a posix password
    rsclient
        .idm_person_account_unix_cred_put("testaccount1", TESTACCOUNT1_PASSWORD_A)
        .await
        .unwrap();

    // Setup a group
    rsclient.idm_group_create("testgroup1").await.unwrap();
    rsclient
        .idm_group_add_members("testgroup1", &["testaccount1"])
        .await
        .unwrap();
    rsclient
        .idm_group_unix_extend("testgroup1", Some(20001))
        .await
        .unwrap();

    // Setup the allowed group
    rsclient.idm_group_create("allowed_group").await.unwrap();
    rsclient
        .idm_group_unix_extend("allowed_group", Some(20002))
        .await
        .unwrap();

    // Setup a group that is masked by nxset, but allowed in overrides
    rsclient.idm_group_create("masked_group").await.unwrap();
    rsclient
        .idm_group_unix_extend("masked_group", Some(20003))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_cache_sshkey() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
    // Force offline. Show we have no keys.
    cachelayer.mark_offline().await;

    let sk = cachelayer
        .get_sshkeys("testaccount1")
        .await
        .expect("Failed to get from cache.");
    assert!(sk.is_empty());

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
}

#[tokio::test]
async fn test_cache_account() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
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

    // #392: Check that a `shell=None` is set to `default_shell`.
    assert!(ut.unwrap().shell == *DEFAULT_SHELL);

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
}

#[tokio::test]
async fn test_cache_group() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
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
    assert!(gt.unwrap().members.is_empty());

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
}

#[tokio::test]
async fn test_cache_group_delete() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
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
}

#[tokio::test]
async fn test_cache_account_delete() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
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
        .idm_person_account_delete("testaccount1")
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
}

#[tokio::test]
async fn test_cache_account_password() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.attempt_online().await;
    // Test authentication failure.
    let a1 = cachelayer
        .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_INC)
        .await
        .expect("failed to authenticate");
    assert!(a1 == Some(false));

    // We have to wait due to softlocking.
    tokio::time::sleep(Duration::from_secs(1)).await;

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
        .idm_person_account_unix_cred_put("testaccount1", TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("Failed to change password");

    // test auth (old pw) fail
    let a3 = cachelayer
        .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_A)
        .await
        .expect("failed to authenticate");
    assert!(a3 == Some(false));

    // We have to wait due to softlocking.
    tokio::time::sleep(Duration::from_secs(1)).await;

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
    assert!(a7.is_none());

    // go online
    cachelayer.attempt_online().await;
    assert!(cachelayer.test_connection().await);

    // test auth success
    let a8 = cachelayer
        .pam_account_authenticate("testaccount1", TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert!(a8 == Some(true));
}

#[tokio::test]
async fn test_cache_account_pam_allowed() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
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
        .idm_group_add_members("allowed_group", &["testaccount1"])
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
}

#[tokio::test]
async fn test_cache_account_pam_nonexist() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.attempt_online().await;

    let a1 = cachelayer
        .pam_account_allowed("NO_SUCH_ACCOUNT")
        .await
        .expect("failed to authenticate");
    assert!(a1.is_none());

    let a2 = cachelayer
        .pam_account_authenticate("NO_SUCH_ACCOUNT", TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert!(a2.is_none());

    cachelayer.mark_offline().await;

    let a1 = cachelayer
        .pam_account_allowed("NO_SUCH_ACCOUNT")
        .await
        .expect("failed to authenticate");
    assert!(a1.is_none());

    let a2 = cachelayer
        .pam_account_authenticate("NO_SUCH_ACCOUNT", TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert!(a2.is_none());
}

#[tokio::test]
async fn test_cache_account_expiry() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
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
        .idm_person_account_set_attr("testaccount1", "account_expire", &[ACCOUNT_EXPIRE])
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
    assert!(sk.is_empty());

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
    assert!(sk.is_empty());

    // Pam account allowed should be denied.
    let a5 = cachelayer
        .pam_account_allowed("testaccount1")
        .await
        .expect("failed to authenticate");
    assert!(a5 == Some(false));
}

#[tokio::test]
async fn test_cache_nxcache() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.attempt_online().await;
    assert!(cachelayer.test_connection().await);
    // Is it in the nxcache?

    assert!(cachelayer
        .check_nxcache(&Id::Name("oracle".to_string()))
        .await
        .is_none());
    assert!(cachelayer.check_nxcache(&Id::Gid(2000)).await.is_none());
    assert!(cachelayer
        .check_nxcache(&Id::Name("oracle_group".to_string()))
        .await
        .is_none());
    assert!(cachelayer.check_nxcache(&Id::Gid(3000)).await.is_none());

    // Look for the acc id + nss id
    let ut = cachelayer
        .get_nssaccount_name("oracle")
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_none());
    let ut = cachelayer
        .get_nssaccount_gid(2000)
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_none());

    let gt = cachelayer
        .get_nssgroup_name("oracle_group")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_none());
    let gt = cachelayer
        .get_nssgroup_gid(3000)
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_none());

    // Should all now be nxed
    assert!(cachelayer
        .check_nxcache(&Id::Name("oracle".to_string()))
        .await
        .is_some());
    assert!(cachelayer.check_nxcache(&Id::Gid(2000)).await.is_some());
    assert!(cachelayer
        .check_nxcache(&Id::Name("oracle_group".to_string()))
        .await
        .is_some());
    assert!(cachelayer.check_nxcache(&Id::Gid(3000)).await.is_some());

    // invalidate cache
    assert!(cachelayer.invalidate().await.is_ok());

    // Both should NOT be in nxcache now.
    assert!(cachelayer
        .check_nxcache(&Id::Name("oracle".to_string()))
        .await
        .is_none());
    assert!(cachelayer.check_nxcache(&Id::Gid(2000)).await.is_none());
    assert!(cachelayer
        .check_nxcache(&Id::Name("oracle_group".to_string()))
        .await
        .is_none());
    assert!(cachelayer.check_nxcache(&Id::Gid(3000)).await.is_none());
}

#[tokio::test]
async fn test_cache_nxset_account() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    // Important! This is what sets up that testaccount1 won't be resolved
    // because it's in the "local" user set.
    cachelayer
        .reload_nxset(vec![("testaccount1".to_string(), 20000)].into_iter())
        .await;

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
    assert!(ut.is_none());

    // go offline
    cachelayer.mark_offline().await;

    // still not present, was not cached.
    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_none());

    // Finally, check it's not in all accounts.
    let us = cachelayer
        .get_nssaccounts()
        .await
        .expect("failed to list all accounts");
    assert!(us.is_empty());
}

#[tokio::test]
async fn test_cache_nxset_group() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    // Important! This is what sets up that testgroup1 won't be resolved
    // because it's in the "local" group set.
    cachelayer
        .reload_nxset(vec![("testgroup1".to_string(), 20001)].into_iter())
        .await;

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
    assert!(gt.is_none());

    // go offline. still works
    cachelayer.mark_offline().await;
    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_none());

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
    assert!(gt.is_none());

    // Finally, check we only have the upg in the list
    let gs = cachelayer
        .get_nssgroups()
        .await
        .expect("failed to list all groups");
    assert!(gs.len() == 1);
    assert!(gs[0].name == "testaccount1@idm.example.com");
}

#[tokio::test]
async fn test_cache_nxset_allow_overrides() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    // Important! masked_group is set as an allowed override group even though
    // it's been "inserted" to the nxset. This means it will still resolve!
    cachelayer
        .reload_nxset(vec![("masked_group".to_string(), 20003)].into_iter())
        .await;

    // Force offline. Show we have no groups.
    cachelayer.mark_offline().await;
    let gt = cachelayer
        .get_nssgroup_name("masked_group")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_none());

    // go online. Get the group
    cachelayer.attempt_online().await;
    assert!(cachelayer.test_connection().await);
    let gt = cachelayer
        .get_nssgroup_name("masked_group")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_some());

    // go offline. still works
    cachelayer.mark_offline().await;
    let gt = cachelayer
        .get_nssgroup_name("masked_group")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_some());
}

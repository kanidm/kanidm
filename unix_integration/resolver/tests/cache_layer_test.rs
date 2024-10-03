#![deny(warnings)]
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::constants::ATTR_ACCOUNT_EXPIRE;
use kanidm_unix_common::constants::{
    DEFAULT_GID_ATTR_MAP, DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX,
    DEFAULT_SHELL, DEFAULT_UID_ATTR_MAP,
};
use kanidm_unix_common::unix_passwd::{EtcGroup, EtcShadow, EtcUser};
use kanidm_unix_resolver::db::{Cache, Db};
use kanidm_unix_resolver::idprovider::interface::Id;
use kanidm_unix_resolver::idprovider::kanidm::KanidmProvider;
use kanidm_unix_resolver::idprovider::system::SystemProvider;
use kanidm_unix_resolver::resolver::Resolver;
use kanidm_unix_resolver::unix_config::{GroupMap, KanidmConfig};
use kanidmd_core::config::{Configuration, IntegrationTestConfig, ServerRole};
use kanidmd_core::create_server_core;
use kanidmd_testkit::{is_free_port, PORT_ALLOC};
use tokio::task;
use tracing::log::{debug, trace};

use kanidm_hsm_crypto::{soft::SoftTpm, AuthValue, BoxedDynTpm, Tpm};

const ADMIN_TEST_USER: &str = "admin";
const ADMIN_TEST_PASSWORD: &str = "integration test admin password";
const IDM_ADMIN_TEST_USER: &str = "idm_admin";
const IDM_ADMIN_TEST_PASSWORD: &str = "integration test idm_admin password";
const TESTACCOUNT1_PASSWORD_A: &str = "password a for account1 test";
const TESTACCOUNT1_PASSWORD_B: &str = "password b for account1 test";
const TESTACCOUNT1_PASSWORD_INC: &str = "never going to work";
const ACCOUNT_EXPIRE: &str = "1970-01-01T00:00:00+00:00";

type Fixture = Box<dyn FnOnce(KanidmClient) -> Pin<Box<dyn Future<Output = ()>>>>;

fn fixture<T>(f: fn(KanidmClient) -> T) -> Fixture
where
    T: Future<Output = ()> + 'static,
{
    Box::new(move |n| Box::pin(f(n)))
}

async fn setup_test(fix_fn: Fixture) -> (Resolver, KanidmClient) {
    sketching::test_init();

    let mut counter = 0;
    let port = loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        #[allow(clippy::assertions_on_constants)]
        if counter >= 5 {
            eprintln!("Unable to allocate port!");
            debug_assert!(false);
        }
    };

    let int_config = Box::new(IntegrationTestConfig {
        admin_user: ADMIN_TEST_USER.to_string(),
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
        idm_admin_user: IDM_ADMIN_TEST_USER.to_string(),
        idm_admin_password: IDM_ADMIN_TEST_PASSWORD.to_string(),
    });

    // Setup the config ...
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.integration_test_config = Some(int_config);
    config.role = ServerRole::WriteReplicaNoUI;
    config.threads = 1;

    create_server_core(config, false)
        .await
        .expect("failed to start server core");
    // We have to yield now to guarantee that the elements are setup.
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

    let db = Db::new(
        "", // The sqlite db path, this is in memory.
    )
    .expect("Failed to setup DB");

    let mut dbtxn = db.write().await;
    dbtxn.migrate().expect("Unable to migrate cache db");

    let mut hsm = BoxedDynTpm::new(SoftTpm::new());

    let auth_value = AuthValue::ephemeral().unwrap();

    let loadable_machine_key = hsm.machine_key_create(&auth_value).unwrap();
    let machine_key = hsm
        .machine_key_load(&auth_value, &loadable_machine_key)
        .unwrap();

    let system_provider = SystemProvider::new().unwrap();

    let idprovider = KanidmProvider::new(
        rsclient,
        &KanidmConfig {
            conn_timeout: 1,
            request_timeout: 1,
            pam_allowed_login_groups: vec!["allowed_group".to_string()],
            map_group: vec![GroupMap {
                local: "extensible_group".to_string(),
                with: "testgroup1".to_string(),
            }],
        },
        SystemTime::now(),
        &mut (&mut dbtxn).into(),
        &mut hsm,
        &machine_key,
    )
    .unwrap();

    drop(machine_key);

    dbtxn.commit().expect("Unable to commit dbtxn");

    let cachelayer = Resolver::new(
        db,
        Arc::new(system_provider),
        vec![Arc::new(idprovider)],
        hsm,
        300,
        DEFAULT_SHELL.to_string(),
        DEFAULT_HOME_PREFIX.into(),
        DEFAULT_HOME_ATTR,
        DEFAULT_HOME_ALIAS,
        DEFAULT_UID_ATTR_MAP,
        DEFAULT_GID_ATTR_MAP,
    )
    .await
    .expect("Failed to build cache layer.");

    // test_fn(cachelayer, client);
    (cachelayer, client)
    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
}

/// This is the test fixture. It sets up the following:
/// - adds admin to idm_admins
/// - creates a test account (testaccount1)
/// - extends the test account with posix attrs
/// - adds a ssh public key to the test account
/// - sets a posix password for the test account
/// - creates a test group (testgroup1) and adds the test account to the test group
/// - extends testgroup1 with posix attrs
/// - creates two more groups with unix perms (allowed_group, masked_group)
async fn test_fixture(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    debug!("auth_simple_password res: {:?}", res);
    trace!("{:?}", &res);
    assert!(res.is_ok());
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
    rsclient.idm_group_create("testgroup1", None).await.unwrap();
    rsclient
        .idm_group_add_members("testgroup1", &["testaccount1"])
        .await
        .unwrap();
    rsclient
        .idm_group_unix_extend("testgroup1", Some(20001))
        .await
        .unwrap();

    // Setup the allowed group
    rsclient
        .idm_group_create("allowed_group", None)
        .await
        .unwrap();
    rsclient
        .idm_group_unix_extend("allowed_group", Some(20002))
        .await
        .unwrap();

    // Setup a group that is masked by nxset, but allowed in overrides
    rsclient
        .idm_group_create("masked_group", None)
        .await
        .unwrap();
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
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    let sk = cachelayer
        .get_sshkeys("testaccount1")
        .await
        .expect("Failed to get from cache.");
    assert_eq!(sk.len(), 1);

    // Go offline, and get from cache.
    cachelayer.mark_offline().await;
    let sk = cachelayer
        .get_sshkeys("testaccount1")
        .await
        .expect("Failed to get from cache.");
    assert_eq!(sk.len(), 1);
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
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // get the account
    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_some());

    // #392: Check that a `shell=None` is set to `default_shell`.
    assert_eq!(ut.unwrap().shell, *DEFAULT_SHELL);

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
    assert_eq!(us.len(), 1);
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
    cachelayer.mark_next_check_now(SystemTime::now()).await;
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
    cachelayer.mark_next_check_now(SystemTime::now()).await;
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
    assert_eq!(gt.unwrap().members.len(), 1);

    // Finally, check we have "all groups" in the list.
    let gs = cachelayer
        .get_nssgroups()
        .await
        .expect("failed to list all groups");
    assert_eq!(gs.len(), 2);
}

#[tokio::test]
async fn test_cache_group_delete() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
    // get the group
    cachelayer.mark_next_check_now(SystemTime::now()).await;
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
    cachelayer.mark_next_check_now(SystemTime::now()).await;
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
    let current_time = OffsetDateTime::now_utc();
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    // Test authentication failure.
    let a1 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_INC)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(false));

    // We have to wait due to softlocking.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Test authentication success.
    let a2 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_A)
        .await
        .expect("failed to authenticate");
    assert_eq!(a2, Some(true));

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
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_A)
        .await
        .expect("failed to authenticate");
    assert_eq!(a3, Some(false));

    // We have to wait due to softlocking.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // test auth (new pw) success
    let a4 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert_eq!(a4, Some(true));

    // Go offline.
    cachelayer.mark_offline().await;

    // Test auth success
    let a5 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert_eq!(a5, Some(true));

    // No softlock during offline.

    // Test auth failure.
    let a6 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_INC)
        .await
        .expect("failed to authenticate");
    assert_eq!(a6, Some(false));

    // clear cache
    cachelayer
        .clear_cache()
        .await
        .expect("failed to clear cache");

    // test auth good (fail)
    let a7 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert!(a7.is_none());

    // go online
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // test auth success
    let a8 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert_eq!(a8, Some(true));
}

#[tokio::test]
async fn test_cache_account_pam_allowed() {
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.mark_next_check_now(SystemTime::now()).await;

    // Should fail
    let a1 = cachelayer
        .pam_account_allowed("testaccount1")
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(false));

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
    assert_eq!(a2, Some(true));
}

#[tokio::test]
async fn test_cache_account_pam_nonexist() {
    let current_time = OffsetDateTime::now_utc();
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.mark_next_check_now(SystemTime::now()).await;

    let a1 = cachelayer
        .pam_account_allowed("NO_SUCH_ACCOUNT")
        .await
        .expect("failed to authenticate");
    assert!(a1.is_none());

    let a2 = cachelayer
        .pam_account_authenticate("NO_SUCH_ACCOUNT", current_time, TESTACCOUNT1_PASSWORD_B)
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
        .pam_account_authenticate("NO_SUCH_ACCOUNT", current_time, TESTACCOUNT1_PASSWORD_B)
        .await
        .expect("failed to authenticate");
    assert!(a2.is_none());
}

#[tokio::test]
async fn test_cache_account_expiry() {
    let current_time = OffsetDateTime::now_utc();
    let (cachelayer, adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // We need one good auth first to prime the cache with a hash.
    let a1 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_A)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(true));
    // Invalidate to make sure we go online next checks.
    assert!(cachelayer.invalidate().await.is_ok());

    // expire the account
    adminclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await
        .expect("failed to auth as admin");
    adminclient
        .idm_person_account_set_attr("testaccount1", ATTR_ACCOUNT_EXPIRE, &[ACCOUNT_EXPIRE])
        .await
        .unwrap();
    // auth will fail
    let a2 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_A)
        .await
        .expect("failed to authenticate");
    assert_eq!(a2, Some(false));

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
    assert_eq!(a3, Some(false));

    // go offline
    cachelayer.mark_offline().await;

    // Now, check again. Since this uses the cached pw and we are offline, this
    // will now succeed.
    let a4 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, TESTACCOUNT1_PASSWORD_A)
        .await
        .expect("failed to authenticate");
    assert_eq!(a4, Some(true));

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
    assert_eq!(a5, Some(false));
}

#[tokio::test]
async fn test_cache_nxcache() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;
    cachelayer.mark_next_check_now(SystemTime::now()).await;
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
    assert!(
        cachelayer
            .check_nxcache(&Id::Name("oracle".to_string()))
            .await
            .is_some(),
        "'oracle' Wasn't in the nxcache!"
    );
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
        .reload_system_identities(
            vec![EtcUser {
                name: "testaccount1".to_string(),
                uid: 30000,
                gid: 30000,
                password: Default::default(),
                gecos: Default::default(),
                homedir: Default::default(),
                shell: Default::default(),
            }],
            None,
            vec![],
        )
        .await;

    // go online
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // get the account
    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");

    let ut = ut.unwrap();
    // Assert the user is the system version.
    assert_eq!(ut.uid, 30000);

    // go offline
    cachelayer.mark_offline().await;

    // still not present, was not cached.
    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");

    let ut = ut.unwrap();
    // Assert the user is the system version.
    assert_eq!(ut.uid, 30000);

    // Finally, check it's the system version in all accounts.
    let us = cachelayer
        .get_nssaccounts()
        .await
        .expect("failed to list all accounts");

    let us: Vec<_> = us
        .into_iter()
        .filter(|nss_user| nss_user.name == "testaccount1")
        .collect();

    assert_eq!(us.len(), 1);
    assert_eq!(us[0].gid, 30000);
}

#[tokio::test]
async fn test_cache_nxset_group() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    // Important! This is what sets up that testgroup1 won't be resolved
    // because it's in the "local" group set.
    cachelayer
        .reload_system_identities(
            vec![],
            None,
            vec![EtcGroup {
                name: "testgroup1".to_string(),
                // Important! We set the GID to differ from what kanidm stores so we can
                // tell we got the system version.
                gid: 30001,
                password: Default::default(),
                members: Default::default(),
            }],
        )
        .await;

    // go online. Get the group
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);
    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");

    // We get the group, it's the system version. Check the gid.
    let gt = gt.unwrap();
    assert_eq!(gt.gid, 30001);

    // go offline. still works
    cachelayer.mark_offline().await;
    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    assert_eq!(gt.gid, 30001);

    // clear cache, go online
    assert!(cachelayer.invalidate().await.is_ok());
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // get a kanidm account with the kanidm equivalent group
    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_some());

    // go offline.
    cachelayer.mark_offline().await;

    // show that the group we have is still the system version, and lacks our
    // member.
    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    assert_eq!(gt.gid, 30001);
    assert!(gt.members.is_empty());

    // Finally, check we only have the system group version in the list.
    let gs = cachelayer
        .get_nssgroups()
        .await
        .expect("failed to list all groups");

    let gs: Vec<_> = gs
        .into_iter()
        .filter(|nss_group| nss_group.name == "testgroup1")
        .collect();

    debug!("{:?}", gs);
    assert_eq!(gs.len(), 1);
    assert_eq!(gs[0].gid, 30001);
}

#[tokio::test]
async fn test_cache_authenticate_system_account() {
    const SECURE_PASSWORD: &str = "a";

    let current_time = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365);
    let expire_time = OffsetDateTime::UNIX_EPOCH + time::Duration::days(380);
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    // Important! This is what sets up that testaccount1 won't be resolved
    // because it's in the "local" user set.
    cachelayer
        .reload_system_identities(
            vec![
            EtcUser {
                name: "testaccount1".to_string(),
                uid: 30000,
                gid: 30000,
                password: Default::default(),
                gecos: Default::default(),
                homedir: Default::default(),
                shell: Default::default(),
            },
            EtcUser {
                name: "testaccount2".to_string(),
                uid: 30001,
                gid: 30001,
                password: Default::default(),
                gecos: Default::default(),
                homedir: Default::default(),
                shell: Default::default(),
            }
            ],
            Some(vec![
                EtcShadow {
                    name: "testaccount1".to_string(),
                    // The very secure password, "a".
                    password: "$6$5.bXZTIXuVv.xI3.$sAubscCJPwnBWwaLt2JR33lo539UyiDku.aH5WVSX0Tct9nGL2ePMEmrqT3POEdBlgNQ12HJBwskewGu2dpF//".to_string(),
                    epoch_change_days: None,
                    days_min_password_age: 0,
                    days_max_password_age: Some(1),
                    days_warning_period: 1,
                    days_inactivity_period: None,
                    epoch_expire_date: Some(380),
                    flag_reserved: None
                },
                EtcShadow {
                    name: "testaccount2".to_string(),
                    // The very secure password, "a".
                    password: "$6$5.bXZTIXuVv.xI3.$sAubscCJPwnBWwaLt2JR33lo539UyiDku.aH5WVSX0Tct9nGL2ePMEmrqT3POEdBlgNQ12HJBwskewGu2dpF//".to_string(),
    epoch_change_days: Some(364),
                    days_min_password_age: 0,
                    days_max_password_age: Some(2),
                    days_warning_period: 1,
                    days_inactivity_period: None,
                    epoch_expire_date: Some(380),
                    flag_reserved: None
                },
            ]),
            vec![],
        )
        .await;

    // get the accounts to assert they exist,
    let _ = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");
    let _ = cachelayer
        .get_nssaccount_name("testaccount2")
        .await
        .expect("Failed to get from cache");

    // Non exist name
    let a1 = cachelayer
        .pam_account_authenticate("testaccount69", current_time, SECURE_PASSWORD)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, None);

    // Check wrong pw.
    let a1 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, "wrong password")
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(false));

    // Check correct pw (both accounts)
    let a1 = cachelayer
        .pam_account_authenticate("testaccount1", current_time, SECURE_PASSWORD)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(true));

    let a1 = cachelayer
        .pam_account_authenticate("testaccount2", current_time, SECURE_PASSWORD)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(true));

    // Check expired time (both accounts)
    let a1 = cachelayer
        .pam_account_authenticate("testaccount1", expire_time, SECURE_PASSWORD)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(false));

    let a1 = cachelayer
        .pam_account_authenticate("testaccount2", expire_time, SECURE_PASSWORD)
        .await
        .expect("failed to authenticate");
    assert_eq!(a1, Some(false));

    // due to how posix auth works, session and authorisation are simpler, and should
    // always just return "true".
    let a1 = cachelayer
        .pam_account_allowed("testaccount1")
        .await
        .expect("failed to authorise");
    assert_eq!(a1, Some(true));

    let a1 = cachelayer
        .pam_account_allowed("testaccount2")
        .await
        .expect("failed to authorise");
    assert_eq!(a1, Some(true));

    // Should we make home dirs?
    let a1 = cachelayer
        .pam_account_beginsession("testaccount1")
        .await
        .expect("failed to begin session");
    assert_eq!(a1, None);

    let a1 = cachelayer
        .pam_account_beginsession("testaccount2")
        .await
        .expect("failed to begin session");
    assert_eq!(a1, None);
}

/// Issue 1830. If cache items expire where we have an account and a group, and we
/// refresh the group *first*, the group appears to drop it's members. This is because
/// sqlite "INSERT OR REPLACE INTO" triggers a delete cascade of the foreign key elements
/// which then makes the group appear empty.
///
/// We can reproduce this by retrieving an account + group, wait for expiry, then retrieve
/// only the group.
#[tokio::test]
async fn test_cache_group_fk_deferred() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // Get the account then the group.
    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_some());

    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_some());
    assert_eq!(gt.unwrap().members.len(), 1);

    // Invalidate all items.
    cachelayer.mark_offline().await;
    assert!(cachelayer.invalidate().await.is_ok());
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    // Get the *group*. It *should* still have it's members.
    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_some());
    // And check we have members in the group, since we came from a userlook up
    assert_eq!(gt.unwrap().members.len(), 1);
}

#[tokio::test]
/// Test group extension. Groups extension is not the same as "overriding". Extension
/// only allows the *members* of a remote group to supplement the members of the local
/// group. This prevents a remote group changing the gidnumber of the local group and
/// causing breakages.
async fn test_cache_extend_group_members() {
    let (cachelayer, _adminclient) = setup_test(fixture(test_fixture)).await;

    cachelayer
        .reload_system_identities(
            vec![EtcUser {
                name: "local_account".to_string(),
                uid: 30000,
                gid: 30000,
                password: Default::default(),
                gecos: Default::default(),
                homedir: Default::default(),
                shell: Default::default(),
            }],
            None,
            vec![EtcGroup {
                // This group is configured to allow extension from
                // the group "testgroup1"
                name: "extensible_group".to_string(),
                gid: 30001,
                password: Default::default(),
                // We have the local account as a member, it should NOT be stomped.
                members: vec!["local_account".to_string()],
            }],
        )
        .await;

    // Force offline. Show we have no groups.
    cachelayer.mark_offline().await;
    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");
    assert!(gt.is_none());

    // While offline, extensible_group has only local_account as a member.
    let gt = cachelayer
        .get_nssgroup_name("extensible_group")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    assert_eq!(gt.gid, 30001);
    assert_eq!(gt.members.as_slice(), &["local_account".to_string()]);

    // Go online. Group now exists, extensible_group has group members.
    // Need to resolve test-account first so that the membership is linked.
    cachelayer.mark_next_check_now(SystemTime::now()).await;
    assert!(cachelayer.test_connection().await);

    let ut = cachelayer
        .get_nssaccount_name("testaccount1")
        .await
        .expect("Failed to get from cache");
    assert!(ut.is_some());

    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    assert_eq!(gt.gid, 20001);
    assert_eq!(
        gt.members.as_slice(),
        &["testaccount1@idm.example.com".to_string()]
    );

    let gt = cachelayer
        .get_nssgroup_name("extensible_group")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    // Even though it's extended, still needs to be the local uid/gid
    assert_eq!(gt.gid, 30001);
    assert_eq!(
        gt.members.as_slice(),
        &[
            "local_account".to_string(),
            "testaccount1@idm.example.com".to_string()
        ]
    );

    let groups = cachelayer
        .get_nssgroups()
        .await
        .expect("Failed to get from cache");

    assert!(groups.iter().any(|group| {
        group.name == "extensible_group"
            && group.members.as_slice()
                == &[
                    "local_account".to_string(),
                    "testaccount1@idm.example.com".to_string(),
                ]
    }));

    // Go offline. Group cached, extensible_group has members.
    cachelayer.mark_offline().await;

    let gt = cachelayer
        .get_nssgroup_name("testgroup1")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    assert_eq!(gt.gid, 20001);
    assert_eq!(
        gt.members.as_slice(),
        &["testaccount1@idm.example.com".to_string()]
    );

    let gt = cachelayer
        .get_nssgroup_name("extensible_group")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    // Even though it's extended, still needs to be the local uid/gid
    assert_eq!(gt.gid, 30001);
    assert_eq!(
        gt.members.as_slice(),
        &[
            "local_account".to_string(),
            "testaccount1@idm.example.com".to_string()
        ]
    );

    // clear cache
    cachelayer
        .clear_cache()
        .await
        .expect("failed to clear cache");

    // No longer has testaccount.
    let gt = cachelayer
        .get_nssgroup_name("extensible_group")
        .await
        .expect("Failed to get from cache");

    let gt = gt.unwrap();
    assert_eq!(gt.gid, 30001);
    assert_eq!(gt.members.as_slice(), &["local_account".to_string()]);
}

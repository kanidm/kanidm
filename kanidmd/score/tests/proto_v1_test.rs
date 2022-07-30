#![deny(warnings)]
use std::time::SystemTime;

use tracing::debug;

use kanidm::credential::totp::Totp;
use kanidm_proto::v1::{CURegState, CredentialDetailType, Entry, Filter, Modify, ModifyList};

mod common;
use crate::common::{setup_async_test, ADMIN_TEST_PASSWORD};

use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

const ADMIN_TEST_PASSWORD_CHANGE: &str = "integration test admin new🎉";
const UNIX_TEST_PASSWORD: &str = "unix test user password";

#[tokio::test]
async fn test_server_create() {
    let rsclient = setup_async_test().await;
    let e: Entry = serde_json::from_str(
        r#"{
            "attrs": {
                "class": ["account"],
                "name": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
    )
    .unwrap();

    // Not logged in - should fail!
    let res = rsclient.create(vec![e.clone()]).await;
    assert!(res.is_err());

    let a_res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(a_res.is_ok());

    let res = rsclient.create(vec![e]).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_server_modify() {
    let rsclient = setup_async_test().await;
    // Build a self mod.

    let f = Filter::SelfUuid;
    let m = ModifyList::new_list(vec![
        Modify::Purged("displayname".to_string()),
        Modify::Present("displayname".to_string(), "test".to_string()),
    ]);

    // Not logged in - should fail!
    let res = rsclient.modify(f.clone(), m.clone()).await;
    assert!(res.is_err());

    let a_res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(a_res.is_ok());

    let res = rsclient.modify(f, m).await;
    println!("{:?}", res);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_server_whoami_anonymous() {
    let rsclient = setup_async_test().await;
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    assert!(pre_res.unwrap().is_none());

    // Now login as anonymous
    let res = rsclient.auth_anonymous().await;
    assert!(res.is_ok());

    // Now do a whoami.
    let (_e, uat) = match rsclient.whoami().await.unwrap() {
        Some((e, uat)) => (e, uat),
        None => panic!(),
    };
    debug!("{}", uat);
    assert!(uat.spn == "anonymous@localhost");

    // Do a check of the auth/valid endpoint, tells us if our token
    // is okay.
    let res = rsclient.auth_valid().await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_server_whoami_admin_simple_password() {
    let rsclient = setup_async_test().await;
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    assert!(pre_res.unwrap().is_none());

    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Now do a whoami.
    let (_e, uat) = match rsclient.whoami().await.unwrap() {
        Some((e, uat)) => (e, uat),
        None => panic!(),
    };
    debug!("{}", uat);
    assert!(uat.spn == "admin@localhost");
}

#[tokio::test]
async fn test_server_search() {
    let rsclient = setup_async_test().await;
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    assert!(pre_res.unwrap().is_none());

    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let rset = rsclient
        .search(Filter::Eq("name".to_string(), "admin".to_string()))
        .await
        .unwrap();
    println!("{:?}", rset);
    let e = rset.first().unwrap();
    // Check it's admin.
    println!("{:?}", e);
    let name = e.attrs.get("name").unwrap();
    assert!(name == &vec!["admin".to_string()]);
}

#[tokio::test]
async fn test_server_admin_change_simple_password() {
    let rsclient = setup_async_test().await;
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    assert!(pre_res.unwrap().is_none());

    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Now change the password.
    rsclient
        .idm_account_set_password(ADMIN_TEST_PASSWORD_CHANGE.to_string())
        .await
        .unwrap();

    // Now "reset" the client.
    let _ = rsclient.logout().await;
    // New password works!
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD_CHANGE)
        .await;

    assert!(res.is_ok());

    // On the admin, show our credential state.
    let cred_state = rsclient
        .idm_account_get_credential_status("admin")
        .await
        .unwrap();
    // Check the creds are what we expect.
    if cred_state.creds.len() != 1 {
        assert!(false);
    }

    if let Some(cred) = cred_state.creds.get(0) {
        assert!(cred.type_ == CredentialDetailType::Password)
    } else {
        assert!(false);
    }

    // Old password fails, check after to prevent soft-locking.
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_err());
}

// Add a test for resetting another accounts pws via the rest api
#[tokio::test]
async fn test_server_admin_reset_simple_password() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // Create a diff account
    let e: Entry = serde_json::from_str(
        r#"{
            "attrs": {
                "class": ["account"],
                "name": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
    )
    .unwrap();

    // Not logged in - should fail!
    let res = rsclient.create(vec![e]).await;
    assert!(res.is_ok());
    // By default, admin's can't actually administer accounts, so mod them into
    // the account admin group.
    let f = Filter::Eq("name".to_string(), "idm_admins".to_string());
    let m = ModifyList::new_list(vec![Modify::Present(
        "member".to_string(),
        "system_admins".to_string(),
    )]);
    let res = rsclient.modify(f, m).await;
    assert!(res.is_ok());

    // Now set it's password - should be rejected based on low quality
    let res = rsclient
        .idm_account_primary_credential_set_password("testperson", "password")
        .await;
    assert!(res.is_err());
    // Set the password to ensure it's good
    let res = rsclient
        .idm_account_primary_credential_set_password(
            "testperson",
            "tai4eCohtae9aegheo3Uw0oobahVighaig6heeli",
        )
        .await;
    assert!(res.is_ok());
    // Check it stuck.
    let tclient = rsclient.new_session().expect("failed to build new session");
    assert!(tclient
        .auth_simple_password("testperson", "tai4eCohtae9aegheo3Uw0oobahVighaig6heeli")
        .await
        .is_ok());

    // Generate a pw instead
    let res = rsclient
        .idm_account_primary_credential_set_generated("testperson")
        .await;
    assert!(res.is_ok());
    let gpw = res.unwrap();
    let tclient = rsclient.new_session().expect("failed to build new session");
    assert!(tclient
        .auth_simple_password("testperson", gpw.as_str())
        .await
        .is_ok());
}

// test the rest group endpoint.
#[tokio::test]
async fn test_server_rest_group_read() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List the groups
    let g_list = rsclient.idm_group_list().await.unwrap();
    assert!(!g_list.is_empty());

    let g = rsclient.idm_group_get("idm_admins").await.unwrap();
    assert!(g.is_some());
    println!("{:?}", g);
}

#[tokio::test]
async fn test_server_rest_group_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List the groups
    let g_list = rsclient.idm_group_list().await.unwrap();
    assert!(!g_list.is_empty());

    // Create a new group
    rsclient.idm_group_create("demo_group").await.unwrap();

    // List again, ensure one more.
    let g_list_2 = rsclient.idm_group_list().await.unwrap();
    assert!(g_list_2.len() > g_list.len());

    // Test modifications to the group

    // Add a member.
    rsclient
        .idm_group_add_members("demo_group", &["admin"])
        .await
        .unwrap();
    let members = rsclient.idm_group_get_members("demo_group").await.unwrap();
    assert!(members == Some(vec!["admin@localhost".to_string()]));

    // Set the list of members
    rsclient
        .idm_group_set_members("demo_group", &["admin", "demo_group"])
        .await
        .unwrap();
    let members = rsclient.idm_group_get_members("demo_group").await.unwrap();
    assert!(
        members
            == Some(vec![
                "admin@localhost".to_string(),
                "demo_group@localhost".to_string()
            ])
    );

    // Remove a member from the group
    rsclient
        .idm_group_remove_members("demo_group", &["demo_group"])
        .await
        .unwrap();
    let members = rsclient.idm_group_get_members("demo_group").await.unwrap();
    assert!(members == Some(vec!["admin@localhost".to_string()]));

    // purge members
    rsclient
        .idm_group_purge_members("demo_group")
        .await
        .unwrap();
    let members = rsclient.idm_group_get_members("demo_group").await.unwrap();
    assert!(members == None);

    // Delete the group
    rsclient.idm_group_delete("demo_group").await.unwrap();
    let g_list_3 = rsclient.idm_group_list().await.unwrap();
    assert!(g_list_3.len() == g_list.len());

    // Check we can get an exact group
    let g = rsclient.idm_group_get("idm_admins").await.unwrap();
    assert!(g.is_some());
    println!("{:?}", g);

    // They should have members
    let members = rsclient.idm_group_get_members("idm_admins").await.unwrap();
    println!("{:?}", members);
    assert!(members == Some(vec!["idm_admin@localhost".to_string()]));
}

#[tokio::test]
async fn test_server_rest_account_read() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List the accounts
    let a_list = rsclient.idm_account_list().await.unwrap();
    assert!(!a_list.is_empty());

    let a = rsclient.idm_account_get("admin").await.unwrap();
    assert!(a.is_some());
    println!("{:?}", a);
}

#[tokio::test]
async fn test_server_rest_schema_read() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List the schema
    let s_list = rsclient.idm_schema_list().await.unwrap();
    assert!(!s_list.is_empty());

    let a_list = rsclient.idm_schema_attributetype_list().await.unwrap();
    assert!(!a_list.is_empty());

    let c_list = rsclient.idm_schema_classtype_list().await.unwrap();
    assert!(!c_list.is_empty());

    // Get an attr/class
    let a = rsclient.idm_schema_attributetype_get("name").await.unwrap();
    assert!(a.is_some());
    println!("{:?}", a);

    let c = rsclient.idm_schema_classtype_get("account").await.unwrap();
    assert!(c.is_some());
    println!("{:?}", c);
}

// Test resetting a radius cred, and then checking/viewing it.
#[tokio::test]
async fn test_server_radius_credential_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // self management of credentials is only for persons.
    rsclient
        .idm_account_person_extend("admin", None, None)
        .await
        .unwrap();

    let f = Filter::Eq("name".to_string(), "idm_admins".to_string());
    let m = ModifyList::new_list(vec![Modify::Present(
        "member".to_string(),
        "system_admins".to_string(),
    )]);
    let res = rsclient.modify(f, m).await;
    assert!(res.is_ok());

    rsclient
        .idm_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // Should have no radius secret
    let n_sec = rsclient
        .idm_account_radius_credential_get("demo_account")
        .await
        .unwrap();
    assert!(n_sec.is_none());

    // Set one
    let sec1 = rsclient
        .idm_account_radius_credential_regenerate("demo_account")
        .await
        .unwrap();

    // Should be able to get it.
    let r_sec = rsclient
        .idm_account_radius_credential_get("demo_account")
        .await
        .unwrap();
    assert!(sec1 == r_sec.unwrap());

    // test getting the token - we can do this as self or the radius server
    let r_tok = rsclient
        .idm_account_radius_token_get("demo_account")
        .await
        .unwrap();
    assert!(sec1 == r_tok.secret);
    assert!(r_tok.name == "demo_account");

    // Reset it
    let sec2 = rsclient
        .idm_account_radius_credential_regenerate("demo_account")
        .await
        .unwrap();

    // Should be different
    println!("s1 {} != s2 {}", sec1, sec2);
    assert!(sec1 != sec2);

    // Delete it
    let res = rsclient
        .idm_account_radius_credential_delete("demo_account")
        .await;
    assert!(res.is_ok());

    // No secret
    let n_sec = rsclient
        .idm_account_radius_credential_get("demo_account")
        .await
        .unwrap();
    assert!(n_sec.is_none());
}

#[tokio::test]
async fn test_server_rest_account_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // To enable the admin to actually make some of these changes, we have
    // to make them a people admin. NOT recommended in production!
    rsclient
        .idm_group_add_members("idm_account_write_priv", &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // View the account
    rsclient.idm_account_get("demo_account").await.unwrap();

    // change the name?
    rsclient
        .idm_account_set_displayname("demo_account", "Demo Account")
        .await
        .unwrap();

    // Test adding some mail addrs
    rsclient
        .idm_account_add_attr("demo_account", "mail", &["demo@idm.example.com"])
        .await
        .unwrap();

    let r = rsclient
        .idm_account_get_attr("demo_account", "mail")
        .await
        .unwrap();

    assert!(r == Some(vec!["demo@idm.example.com".to_string()]));

    // Delete the account
    rsclient.idm_account_delete("demo_account").await.unwrap();
}

#[tokio::test]
async fn test_server_rest_sshkey_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Get the keys, should be empty vec.
    let sk1 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk1.is_empty());

    // idm_account_get_ssh_pubkeys
    // idm_account_post_ssh_pubkey
    // idm_account_get_ssh_pubkey
    // idm_account_delete_ssh_pubkey

    // Post an invalid key (should error)
    let r1 = rsclient
        .idm_account_post_ssh_pubkey("admin", "inv", "invalid key")
        .await;
    assert!(r1.is_err());

    // Post a valid key
    let r2 = rsclient
            .idm_account_post_ssh_pubkey("admin", "k1", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst").await;
    println!("{:?}", r2);
    assert!(r2.is_ok());

    // Get, should have the key
    let sk2 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk2.len() == 1);

    // Post a valid key
    let r3 = rsclient
            .idm_account_post_ssh_pubkey("admin", "k2", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx4TpJYQjd0YI5lQIHqblIsCIK5NKVFURYS/eM3o6/Z william@amethyst").await;
    assert!(r3.is_ok());

    // Get, should have both keys.
    let sk3 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk3.len() == 2);

    // Delete a key (by tag)
    let r4 = rsclient.idm_account_delete_ssh_pubkey("admin", "k1").await;
    assert!(r4.is_ok());

    // Get, should have remaining key.
    let sk4 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk4.len() == 1);

    // get by tag
    let skn = rsclient.idm_account_get_ssh_pubkey("admin", "k2").await;
    assert!(skn.is_ok());
    assert!(skn.unwrap() == Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx4TpJYQjd0YI5lQIHqblIsCIK5NKVFURYS/eM3o6/Z william@amethyst".to_string()));
}

#[tokio::test]
async fn test_server_rest_domain_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let _dlocal = rsclient.idm_domain_get().await.unwrap();

    // Change the ssid
    rsclient.idm_domain_set_ssid("new_ssid").await.unwrap();
    // check get and get the ssid and domain info
    let nssid = rsclient.idm_domain_get_ssid().await.unwrap();
    assert!(nssid == "new_ssid");

    // Change the domain display name
    rsclient
        .idm_domain_set_display_name("Super Cool Crabz")
        .await
        .unwrap();
    let dlocal = rsclient.idm_domain_get().await.unwrap();
    assert!(
        dlocal
            .attrs
            .get("domain_display_name")
            .and_then(|v| v.get(0))
            == Some(&"Super Cool Crabz".to_string())
    );
}

#[tokio::test]
async fn test_server_rest_posix_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_account_create("posix_account", "Posix Demo Account")
        .await
        .unwrap();

    // Extend the account with posix attrs.
    rsclient
        .idm_account_unix_extend("posix_account", None, None)
        .await
        .unwrap();

    // Create a group

    // Extend the group with posix attrs
    rsclient.idm_group_create("posix_group").await.unwrap();
    rsclient
        .idm_group_add_members("posix_group", &["posix_account"])
        .await
        .unwrap();
    rsclient
        .idm_group_unix_extend("posix_group", None)
        .await
        .unwrap();

    // Open a new connection as anonymous
    let res = rsclient.auth_anonymous().await;
    assert!(res.is_ok());

    // Get the account by name
    let r = rsclient
        .idm_account_unix_token_get("posix_account")
        .await
        .unwrap();
    // Get the account by gidnumber
    let r1 = rsclient
        .idm_account_unix_token_get(r.gidnumber.to_string().as_str())
        .await
        .unwrap();
    // get the account by spn
    let r2 = rsclient
        .idm_account_unix_token_get(r.spn.as_str())
        .await
        .unwrap();
    // get the account by uuid
    let r3 = rsclient
        .idm_account_unix_token_get(r.uuid.as_str())
        .await
        .unwrap();

    println!("{:?}", r);
    assert!(r.name == "posix_account");
    assert!(r1.name == "posix_account");
    assert!(r2.name == "posix_account");
    assert!(r3.name == "posix_account");

    // get the group by nam
    let r = rsclient
        .idm_group_unix_token_get("posix_group")
        .await
        .unwrap();
    // Get the group by gidnumber
    let r1 = rsclient
        .idm_group_unix_token_get(r.gidnumber.to_string().as_str())
        .await
        .unwrap();
    // get the group spn
    let r2 = rsclient
        .idm_group_unix_token_get(r.spn.as_str())
        .await
        .unwrap();
    // get the group by uuid
    let r3 = rsclient
        .idm_group_unix_token_get(r.uuid.as_str())
        .await
        .unwrap();

    println!("{:?}", r);
    assert!(r.name == "posix_group");
    assert!(r1.name == "posix_group");
    assert!(r2.name == "posix_group");
    assert!(r3.name == "posix_group");
}

#[tokio::test]
async fn test_server_rest_posix_auth_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // Get an anon connection
    let anon_rsclient = rsclient.new_session().unwrap();
    assert!(anon_rsclient.auth_anonymous().await.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Setup a unix user
    rsclient
        .idm_account_create("posix_account", "Posix Demo Account")
        .await
        .unwrap();

    // Extend the account with posix attrs.
    rsclient
        .idm_account_unix_extend("posix_account", None, None)
        .await
        .unwrap();

    // add their password (unix self)
    rsclient
        .idm_account_unix_cred_put("posix_account", UNIX_TEST_PASSWORD)
        .await
        .unwrap();

    // attempt to verify (good, anon-conn)
    let r1 = anon_rsclient
        .idm_account_unix_cred_verify("posix_account", UNIX_TEST_PASSWORD)
        .await;
    match r1 {
        Ok(Some(_tok)) => {}
        _ => assert!(false),
    };

    // attempt to verify (bad, anon-conn)
    let r2 = anon_rsclient
        .idm_account_unix_cred_verify("posix_account", "ntaotnhuohtsuoehtsu")
        .await;
    match r2 {
        Ok(None) => {}
        _ => assert!(false),
    };

    // lock? (admin-conn)
    // attempt to verify (good pw, should fail, anon-conn)
    // status? (self-conn)

    // clear password? (unix self)
    rsclient
        .idm_account_unix_cred_delete("posix_account")
        .await
        .unwrap();

    // attempt to verify (good pw, should fail, anon-conn)
    let r3 = anon_rsclient
        .idm_account_unix_cred_verify("posix_account", UNIX_TEST_PASSWORD)
        .await;
    match r3 {
        Ok(None) => {}
        _ => assert!(false),
    };
}

#[tokio::test]
async fn test_server_rest_recycle_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Setup a unix user
    rsclient
        .idm_account_create("recycle_account", "Recycle Demo Account")
        .await
        .unwrap();

    // delete them
    rsclient
        .idm_account_delete("recycle_account")
        .await
        .unwrap();

    // not there
    let acc = rsclient.idm_account_get("recycle_account").await.unwrap();
    assert!(acc.is_none());

    // list the recycle bin
    let r_list = rsclient.recycle_bin_list().await.unwrap();

    assert!(r_list.len() == 1);
    // get the user in recycle bin
    let r_user = rsclient.recycle_bin_get("recycle_account").await.unwrap();
    assert!(r_user.is_some());

    // revive
    rsclient
        .recycle_bin_revive("recycle_account")
        .await
        .unwrap();

    // they are there!
    let acc = rsclient.idm_account_get("recycle_account").await.unwrap();
    assert!(acc.is_some());
}

#[tokio::test]
async fn test_server_rest_account_import_password() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // To enable the admin to actually make some of these changes, we have
    // to make them a password import admin. NOT recommended in production!
    rsclient
        .idm_group_add_members("idm_people_account_password_import_priv", &["admin"])
        .await
        .unwrap();
    rsclient
        .idm_group_add_members("idm_people_extend_priv", &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // Make them a person, so we can import the password
    rsclient
        .idm_account_person_extend("demo_account", None, None)
        .await
        .unwrap();

    // Attempt to import a bad password
    let r = rsclient
        .idm_account_primary_credential_import_password("demo_account", "password")
        .await;
    assert!(r.is_err());

    // Import a good password
    // eicieY7ahchaoCh0eeTa
    // pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=
    rsclient
        .idm_account_primary_credential_import_password(
            "demo_account",
            "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=",
        )
        .await
        .unwrap();

    // Now show we can auth with it
    // "reset" the client.
    let _ = rsclient.logout();
    let res = rsclient
        .auth_simple_password("demo_account", "eicieY7ahchaoCh0eeTa")
        .await;
    assert!(res.is_ok());

    // And that the account can self read the cred status.
    let cred_state = rsclient
        .idm_account_get_credential_status("demo_account")
        .await
        .unwrap();

    if let Some(cred) = cred_state.creds.get(0) {
        assert!(cred.type_ == CredentialDetailType::Password)
    } else {
        assert!(false);
    }
}

#[tokio::test]
async fn test_server_rest_totp_auth_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // Enroll a totp to the account
    assert!(rsclient
        .idm_account_primary_credential_set_password("demo_account", "sohdi3iuHo6mai7noh0a")
        .await
        .is_ok());
    let (sessionid, tok) = rsclient
        .idm_account_primary_credential_generate_totp("demo_account")
        .await
        .unwrap();

    let r_tok: Totp = tok.into();
    let totp = r_tok
        .do_totp_duration_from_epoch(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
        .expect("Failed to do totp?");

    rsclient
        .idm_account_primary_credential_verify_totp("demo_account", totp, sessionid)
        .await
        .unwrap(); // the result

    // Check a good auth
    let rsclient_good = rsclient.new_session().unwrap();
    let totp = r_tok
        .do_totp_duration_from_epoch(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
        .expect("Failed to do totp?");
    // TODO: It's extremely rare, but it's happened ONCE where, the time window
    // elapsed DURING this test, so there is a minor possibility of this actually
    // having a false negative. Is it possible to prevent this?
    assert!(rsclient_good
        .auth_password_totp("demo_account", "sohdi3iuHo6mai7noh0a", totp)
        .await
        .is_ok());

    // Check a bad auth - needs to be second as we are going to trigger the slock.
    // Get a new connection
    let rsclient_bad = rsclient.new_session().unwrap();
    assert!(rsclient_bad
        .auth_password_totp("demo_account", "sohdi3iuHo6mai7noh0a", 0)
        .await
        .is_err());
    // Delay by one second to allow the account to recover from the softlock.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Remove TOTP on the account.
    rsclient
        .idm_account_primary_credential_remove_totp("demo_account")
        .await
        .unwrap();
    // Check password auth.
    let rsclient_good = rsclient.new_session().unwrap();
    assert!(rsclient_good
        .auth_simple_password("demo_account", "sohdi3iuHo6mai7noh0a")
        .await
        .is_ok());
}

#[tokio::test]
async fn test_server_rest_backup_code_auth_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // Enroll a totp to the account
    assert!(rsclient
        .idm_account_primary_credential_set_password("demo_account", "sohdi3iuHo6mai7noh0a")
        .await
        .is_ok());
    let (sessionid, tok) = rsclient
        .idm_account_primary_credential_generate_totp("demo_account")
        .await
        .unwrap();

    let r_tok: Totp = tok.into();
    let totp = r_tok
        .do_totp_duration_from_epoch(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
        .expect("Failed to do totp?");

    rsclient
        .idm_account_primary_credential_verify_totp("demo_account", totp, sessionid)
        .await
        .unwrap(); // the result

    // Generate backup codes
    let backup_codes = rsclient
        .idm_account_primary_credential_generate_backup_code("demo_account")
        .await
        .expect("Failed to generate backup codes?");

    // Check a good auth using a backup code
    let rsclient_good = rsclient.new_session().unwrap();
    assert!(rsclient_good
        .auth_password_backup_code(
            "demo_account",
            "sohdi3iuHo6mai7noh0a",
            backup_codes[0].as_str()
        )
        .await
        .is_ok());

    // Check a bad auth - needs to be second as we are going to trigger the slock.
    // Get a new connection
    let rsclient_bad = rsclient.new_session().unwrap();
    assert!(rsclient_bad
        .auth_password_backup_code("demo_account", "sohdi3iuHo6mai7noh0a", "wrong-backup-code")
        .await
        .is_err());
    // Delay by one second to allow the account to recover from the softlock.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Remove TOTP and backup codes on the account.
    rsclient
        .idm_account_primary_credential_remove_totp("demo_account")
        .await
        .unwrap();
    // Check password auth.
    let rsclient_good = rsclient.new_session().unwrap();
    assert!(rsclient_good
        .auth_simple_password("demo_account", "sohdi3iuHo6mai7noh0a")
        .await
        .is_ok());
}

#[tokio::test]
async fn test_server_rest_oauth2_basic_lifecycle() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List, there are non.
    let initial_configs = rsclient
        .idm_oauth2_rs_list()
        .await
        .expect("Failed to retrieve oauth2 configs");

    assert!(initial_configs.is_empty());

    // Create a new oauth2 config
    rsclient
        .idm_oauth2_rs_basic_create(
            "test_integration",
            "Test Integration",
            "https://demo.example.com",
        )
        .await
        .expect("Failed to create oauth2 config");

    // List, there is what we created.
    let initial_configs = rsclient
        .idm_oauth2_rs_list()
        .await
        .expect("Failed to retrieve oauth2 configs");

    assert!(initial_configs.len() == 1);

    // Get the value. Assert we have oauth2_rs_basic_secret,
    // but can NOT see the token_secret.
    let oauth2_config = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    eprintln!("{:?}", oauth2_config);

    // What can we see?
    assert!(oauth2_config.attrs.contains_key("oauth2_rs_basic_secret"));
    // This is present, but redacted.
    assert!(oauth2_config.attrs.contains_key("oauth2_rs_token_key"));

    // Mod delete the secret/key and check them again.
    // Check we can patch the oauth2_rs_name / oauth2_rs_origin
    rsclient
        .idm_oauth2_rs_update(
            "test_integration",
            None,
            Some("Test Integration"),
            Some("https://new_demo.example.com"),
            Some(vec!["read", "email"]),
            true,
            true,
            true,
        )
        .await
        .expect("Failed to update config");

    let oauth2_config_updated = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    assert!(oauth2_config_updated != oauth2_config);

    // Check that we can add scope maps and delete them.
    rsclient
        .idm_oauth2_rs_create_scope_map("test_integration", "system_admins", vec!["a", "b"])
        .await
        .expect("Failed to create scope map");

    let oauth2_config_updated2 = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    assert!(oauth2_config_updated != oauth2_config_updated2);

    rsclient
        .idm_oauth2_rs_delete_scope_map("test_integration", "system_admins")
        .await
        .expect("Failed to delete scope map");

    let oauth2_config_updated3 = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    eprintln!("{:?}", oauth2_config_updated);
    eprintln!("{:?}", oauth2_config_updated3);

    assert!(oauth2_config_updated == oauth2_config_updated3);

    // Delete the config
    rsclient
        .idm_oauth2_rs_delete("test_integration")
        .await
        .expect("Failed to delete test_integration");

    // List, there are none.
    let final_configs = rsclient
        .idm_oauth2_rs_list()
        .await
        .expect("Failed to retrieve oauth2 configs");

    assert!(final_configs.is_empty());
}

#[tokio::test]
async fn test_server_credential_update_session_pw() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create an account
    rsclient
        .idm_account_create("demo_account", "Demo Account")
        .await
        .unwrap();

    // Create an intent token for them
    let intent_token = rsclient
        .idm_account_credential_update_intent("demo_account")
        .await
        .unwrap();

    // Logout, we don't need any auth now.
    let _ = rsclient.logout();
    // Exchange the intent token
    let (session_token, _status) = rsclient
        .idm_account_credential_update_exchange(intent_token)
        .await
        .unwrap();

    let _status = rsclient
        .idm_account_credential_update_status(&session_token)
        .await
        .unwrap();

    // Setup and update the password
    let _status = rsclient
        .idm_account_credential_update_set_password(&session_token, "eicieY7ahchaoCh0eeTa")
        .await
        .unwrap();

    // Commit it
    rsclient
        .idm_account_credential_update_commit(&session_token)
        .await
        .unwrap();

    // Assert it now works.
    let _ = rsclient.logout();
    let res = rsclient
        .auth_simple_password("demo_account", "eicieY7ahchaoCh0eeTa")
        .await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_server_credential_update_session_totp_pw() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create an account
    rsclient
        .idm_account_create("demo_account", "Demo Account")
        .await
        .unwrap();

    // Make them a person so they can self-modify credentials later in the test
    rsclient
        .idm_account_person_extend("demo_account", None, None)
        .await
        .unwrap();

    let intent_token = rsclient
        .idm_account_credential_update_intent("demo_account")
        .await
        .unwrap();

    // Logout, we don't need any auth now, the intent tokens care for it.
    let _ = rsclient.logout();
    // Exchange the intent token
    let (session_token, _statu) = rsclient
        .idm_account_credential_update_exchange(intent_token)
        .await
        .unwrap();

    let _status = rsclient
        .idm_account_credential_update_status(&session_token)
        .await
        .unwrap();

    // Set the password
    let _status = rsclient
        .idm_account_credential_update_set_password(&session_token, "sohdi3iuHo6mai7noh0a")
        .await
        .unwrap();

    // Set the totp.
    let status = rsclient
        .idm_account_credential_update_init_totp(&session_token)
        .await
        .unwrap();

    // Extract the totp from the status, and set it back
    let totp: Totp = match status.mfaregstate {
        CURegState::TotpCheck(totp_secret) => totp_secret.into(),
        _ => unreachable!(),
    };

    let totp_chal = totp
        .do_totp_duration_from_epoch(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
        .expect("Failed to do totp?");

    let _status = rsclient
        .idm_account_credential_update_check_totp(&session_token, totp_chal)
        .await
        .unwrap();

    // Commit it
    rsclient
        .idm_account_credential_update_commit(&session_token)
        .await
        .unwrap();

    let totp_chal = totp
        .do_totp_duration_from_epoch(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
        .expect("Failed to do totp?");

    // Assert it now works.
    let _ = rsclient.logout();
    let res = rsclient
        .auth_password_totp("demo_account", "sohdi3iuHo6mai7noh0a", totp_chal)
        .await;
    assert!(res.is_ok());

    // We are now authed as the demo_account

    // Self create the session and remove the totp now.
    let (session_token, _status) = rsclient
        .idm_account_credential_update_begin("demo_account")
        .await
        .unwrap();

    let _status = rsclient
        .idm_account_credential_update_remove_totp(&session_token)
        .await
        .unwrap();

    // Commit it
    rsclient
        .idm_account_credential_update_commit(&session_token)
        .await
        .unwrap();

    // Assert it now works.
    let _ = rsclient.logout();
    let res = rsclient
        .auth_simple_password("demo_account", "sohdi3iuHo6mai7noh0a")
        .await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_server_credential_update_session_passkey() {
    let rsclient = setup_async_test().await;
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();

    // Create an account
    rsclient
        .idm_account_create("demo_account", "Demo Account")
        .await
        .unwrap();

    // Create an intent token for them
    let intent_token = rsclient
        .idm_account_credential_update_intent("demo_account")
        .await
        .unwrap();

    // Logout, we don't need any auth now.
    let _ = rsclient.logout();
    // Exchange the intent token
    let (session_token, _status) = rsclient
        .idm_account_credential_update_exchange(intent_token)
        .await
        .unwrap();

    let _status = rsclient
        .idm_account_credential_update_status(&session_token)
        .await
        .unwrap();

    // Setup and update the passkey
    let mut wa = WebauthnAuthenticator::new(SoftPasskey::new());

    let status = rsclient
        .idm_account_credential_update_passkey_init(&session_token)
        .await
        .unwrap();

    let passkey_chal = match status.mfaregstate {
        CURegState::Passkey(c) => Some(c),
        _ => None,
    }
    .expect("Unable to access passkey challenge, invalid state");

    eprintln!("{}", rsclient.get_origin());
    let passkey_resp = wa
        .do_registration(rsclient.get_origin().clone(), passkey_chal)
        .expect("Failed to create soft passkey");

    let label = "Soft Passkey".to_string();

    let status = rsclient
        .idm_account_credential_update_passkey_finish(&session_token, label, passkey_resp)
        .await
        .unwrap();

    assert!(status.can_commit);
    assert!(status.passkeys.len() == 1);

    // Commit it
    rsclient
        .idm_account_credential_update_commit(&session_token)
        .await
        .unwrap();

    // Assert it now works.
    let _ = rsclient.logout();
    let res = rsclient
        .auth_passkey_begin("demo_account")
        .await
        .expect("Failed to start passkey auth");

    let pkc = wa
        .do_authentication(rsclient.get_origin().clone(), res)
        .expect("Failed to authentication with soft passkey");

    let res = rsclient.auth_passkey_complete(pkc).await;
    assert!(res.is_ok());
}

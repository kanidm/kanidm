#![deny(warnings)]
use std::time::SystemTime;

use log::debug;

use kanidm::credential::totp::Totp;
use kanidm_client::KanidmClient;
use kanidm_proto::v1::{CredentialDetailType, Entry, Filter, Modify, ModifyList};

mod common;
use crate::common::{run_test, ADMIN_TEST_PASSWORD};

use webauthn_authenticator_rs::{softtok::U2FSoft, WebauthnAuthenticator};

const ADMIN_TEST_PASSWORD_CHANGE: &str = "integration test admin new🎉";
const UNIX_TEST_PASSWORD: &str = "unix test user password";

#[test]
fn test_server_create() {
    run_test(|rsclient: KanidmClient| {
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
        let res = rsclient.create(vec![e.clone()]);
        assert!(res.is_err());

        let a_res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(a_res.is_ok());

        let res = rsclient.create(vec![e]);
        assert!(res.is_ok());
    });
}

#[test]
fn test_server_modify() {
    run_test(|rsclient: KanidmClient| {
        // Build a self mod.

        let f = Filter::SelfUuid;
        let m = ModifyList::new_list(vec![
            Modify::Purged("displayname".to_string()),
            Modify::Present("displayname".to_string(), "test".to_string()),
        ]);

        // Not logged in - should fail!
        let res = rsclient.modify(f.clone(), m.clone());
        assert!(res.is_err());

        let a_res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(a_res.is_ok());

        let res = rsclient.modify(f, m);
        println!("{:?}", res);
        assert!(res.is_ok());
    });
}

#[test]
fn test_server_whoami_anonymous() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        // Now login as anonymous
        let res = rsclient.auth_anonymous();
        assert!(res.is_ok());

        // Now do a whoami.
        let (_e, uat) = match rsclient.whoami().unwrap() {
            Some((e, uat)) => (e, uat),
            None => panic!(),
        };
        debug!("{}", uat);
        assert!(uat.name == "anonymous");
    });
}

#[test]
fn test_server_whoami_admin_simple_password() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Now do a whoami.
        let (_e, uat) = match rsclient.whoami().unwrap() {
            Some((e, uat)) => (e, uat),
            None => panic!(),
        };
        debug!("{}", uat);
        assert!(uat.name == "admin");
    });
}

#[test]
fn test_server_search() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        let rset = rsclient
            .search(Filter::Eq("name".to_string(), "admin".to_string()))
            .unwrap();
        println!("{:?}", rset);
        let e = rset.first().unwrap();
        // Check it's admin.
        println!("{:?}", e);
        let name = e.attrs.get("name").unwrap();
        assert!(name == &vec!["admin".to_string()]);
    });
}

#[test]
fn test_server_admin_change_simple_password() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Now change the password.
        rsclient
            .idm_account_set_password(ADMIN_TEST_PASSWORD_CHANGE.to_string())
            .unwrap();

        // Now "reset" the client.
        let _ = rsclient.logout();
        // New password works!
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD_CHANGE);
        assert!(res.is_ok());

        // On the admin, show our credential state.
        let cred_state = rsclient.idm_account_get_credential_status("admin").unwrap();
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
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_err());
    });
}

// Add a test for resetting another accounts pws via the rest api
#[test]
fn test_server_admin_reset_simple_password() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
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
        let res = rsclient.create(vec![e]);
        assert!(res.is_ok());
        // By default, admin's can't actually administer accounts, so mod them into
        // the account admin group.
        let f = Filter::Eq("name".to_string(), "idm_admins".to_string());
        let m = ModifyList::new_list(vec![Modify::Present(
            "member".to_string(),
            "system_admins".to_string(),
        )]);
        let res = rsclient.modify(f, m);
        assert!(res.is_ok());

        // Now set it's password - should be rejected based on low quality
        let res = rsclient.idm_account_primary_credential_set_password("testperson", "password");
        assert!(res.is_err());
        // Set the password to ensure it's good
        let res = rsclient.idm_account_primary_credential_set_password(
            "testperson",
            "tai4eCohtae9aegheo3Uw0oobahVighaig6heeli",
        );
        assert!(res.is_ok());
        // Check it stuck.
        let tclient = rsclient.new_session().expect("failed to build new session");
        assert!(tclient
            .auth_simple_password("testperson", "tai4eCohtae9aegheo3Uw0oobahVighaig6heeli")
            .is_ok());

        // Generate a pw instead
        let res = rsclient.idm_account_primary_credential_set_generated("testperson");
        assert!(res.is_ok());
        let gpw = res.unwrap();
        let tclient = rsclient.new_session().expect("failed to build new session");
        assert!(tclient
            .auth_simple_password("testperson", gpw.as_str())
            .is_ok());
    });
}

// test the rest group endpoint.
#[test]
fn test_server_rest_group_read() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the groups
        let g_list = rsclient.idm_group_list().unwrap();
        assert!(!g_list.is_empty());

        let g = rsclient.idm_group_get("idm_admins").unwrap();
        assert!(g.is_some());
        println!("{:?}", g);
    });
}

#[test]
fn test_server_rest_group_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the groups
        let g_list = rsclient.idm_group_list().unwrap();
        assert!(!g_list.is_empty());

        // Create a new group
        rsclient.idm_group_create("demo_group").unwrap();

        // List again, ensure one more.
        let g_list_2 = rsclient.idm_group_list().unwrap();
        assert!(g_list_2.len() > g_list.len());

        // Test modifications to the group

        // Add a member.
        rsclient
            .idm_group_add_members("demo_group", &["admin"])
            .unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members == Some(vec!["admin@example.com".to_string()]));

        // Set the list of members
        rsclient
            .idm_group_set_members("demo_group", &["admin", "demo_group"])
            .unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(
            members
                == Some(vec![
                    "admin@example.com".to_string(),
                    "demo_group@example.com".to_string()
                ])
        );

        // Remove a member from the group
        rsclient
            .idm_group_remove_members("demo_group", &["demo_group"])
            .unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members == Some(vec!["admin@example.com".to_string()]));

        // purge members
        rsclient.idm_group_purge_members("demo_group").unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members == None);

        // Delete the group
        rsclient.idm_group_delete("demo_group").unwrap();
        let g_list_3 = rsclient.idm_group_list().unwrap();
        assert!(g_list_3.len() == g_list.len());

        // Check we can get an exact group
        let g = rsclient.idm_group_get("idm_admins").unwrap();
        assert!(g.is_some());
        println!("{:?}", g);

        // They should have members
        let members = rsclient.idm_group_get_members("idm_admins").unwrap();
        println!("{:?}", members);
        assert!(members == Some(vec!["idm_admin@example.com".to_string()]));
    });
}

#[test]
fn test_server_rest_account_read() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the accounts
        let a_list = rsclient.idm_account_list().unwrap();
        assert!(!a_list.is_empty());

        let a = rsclient.idm_account_get("admin").unwrap();
        assert!(a.is_some());
        println!("{:?}", a);
    });
}

#[test]
fn test_server_rest_schema_read() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the schema
        let s_list = rsclient.idm_schema_list().unwrap();
        assert!(!s_list.is_empty());

        let a_list = rsclient.idm_schema_attributetype_list().unwrap();
        assert!(!a_list.is_empty());

        let c_list = rsclient.idm_schema_classtype_list().unwrap();
        assert!(!c_list.is_empty());

        // Get an attr/class
        let a = rsclient.idm_schema_attributetype_get("name").unwrap();
        assert!(a.is_some());
        println!("{:?}", a);

        let c = rsclient.idm_schema_classtype_get("account").unwrap();
        assert!(c.is_some());
        println!("{:?}", c);
    });
}

// Test resetting a radius cred, and then checking/viewing it.
#[test]
fn test_server_radius_credential_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Should have no radius secret
        let n_sec = rsclient.idm_account_radius_credential_get("admin").unwrap();
        assert!(n_sec.is_none());

        // Set one
        let sec1 = rsclient
            .idm_account_radius_credential_regenerate("admin")
            .unwrap();

        // Should be able to get it.
        let r_sec = rsclient.idm_account_radius_credential_get("admin").unwrap();
        assert!(sec1 == r_sec.unwrap());

        // test getting the token - we can do this as self or the radius server
        let r_tok = rsclient.idm_account_radius_token_get("admin").unwrap();
        assert!(sec1 == r_tok.secret);
        assert!(r_tok.name == "admin");

        // Reset it
        let sec2 = rsclient
            .idm_account_radius_credential_regenerate("admin")
            .unwrap();

        // Should be different
        println!("s1 {} != s2 {}", sec1, sec2);
        assert!(sec1 != sec2);

        // Delete it
        let res = rsclient.idm_account_radius_credential_delete("admin");
        assert!(res.is_ok());

        // No secret
        let n_sec = rsclient.idm_account_radius_credential_get("admin").unwrap();
        assert!(n_sec.is_none());
    });
}

#[test]
fn test_server_rest_account_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());
        // To enable the admin to actually make some of these changes, we have
        // to make them a people admin. NOT recommended in production!
        rsclient
            .idm_group_add_members("idm_account_write_priv", &["admin"])
            .unwrap();

        // Create a new account
        rsclient
            .idm_account_create("demo_account", "Deeeeemo")
            .unwrap();

        // View the account
        rsclient.idm_account_get("demo_account").unwrap();

        // change the name?
        rsclient
            .idm_account_set_displayname("demo_account", "Demo Account")
            .unwrap();

        // Delete the account
        rsclient.idm_account_delete("demo_account").unwrap();
    });
}

#[test]
fn test_server_rest_sshkey_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Get the keys, should be empty vec.
        let sk1 = rsclient.idm_account_get_ssh_pubkeys("admin").unwrap();
        assert!(sk1.is_empty());

        // idm_account_get_ssh_pubkeys
        // idm_account_post_ssh_pubkey
        // idm_account_get_ssh_pubkey
        // idm_account_delete_ssh_pubkey

        // Post an invalid key (should error)
        let r1 = rsclient.idm_account_post_ssh_pubkey("admin", "inv", "invalid key");
        assert!(r1.is_err());

        // Post a valid key
        let r2 = rsclient
            .idm_account_post_ssh_pubkey("admin", "k1", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst");
        println!("{:?}", r2);
        assert!(r2.is_ok());

        // Get, should have the key
        let sk2 = rsclient.idm_account_get_ssh_pubkeys("admin").unwrap();
        assert!(sk2.len() == 1);

        // Post a valid key
        let r3 = rsclient
            .idm_account_post_ssh_pubkey("admin", "k2", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx4TpJYQjd0YI5lQIHqblIsCIK5NKVFURYS/eM3o6/Z william@amethyst");
        assert!(r3.is_ok());

        // Get, should have both keys.
        let sk3 = rsclient.idm_account_get_ssh_pubkeys("admin").unwrap();
        assert!(sk3.len() == 2);

        // Delete a key (by tag)
        let r4 = rsclient.idm_account_delete_ssh_pubkey("admin", "k1");
        assert!(r4.is_ok());

        // Get, should have remaining key.
        let sk4 = rsclient.idm_account_get_ssh_pubkeys("admin").unwrap();
        assert!(sk4.len() == 1);

        // get by tag
        let skn = rsclient.idm_account_get_ssh_pubkey("admin", "k2");
        assert!(skn.is_ok());
        assert!(skn.unwrap() == Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx4TpJYQjd0YI5lQIHqblIsCIK5NKVFURYS/eM3o6/Z william@amethyst".to_string()));
    });
}

#[test]
fn test_server_rest_domain_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        let mut dlist = rsclient.idm_domain_list().unwrap();
        assert!(dlist.len() == 1);

        let dlocal = rsclient.idm_domain_get("domain_local").unwrap();
        // There should be one, and it's the domain_local
        assert!(dlist.pop().unwrap().attrs == dlocal.attrs);

        // Change the ssid
        rsclient
            .idm_domain_set_ssid("domain_local", "new_ssid")
            .unwrap();
        // check get and get the ssid and domain info
        let nssid = rsclient.idm_domain_get_ssid("domain_local").unwrap();
        assert!(nssid == "new_ssid");
    });
}

#[test]
fn test_server_rest_posix_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());
        // Not recommended in production!
        rsclient
            .idm_group_add_members("idm_admins", &["admin"])
            .unwrap();

        // Create a new account
        rsclient
            .idm_account_create("posix_account", "Posix Demo Account")
            .unwrap();

        // Extend the account with posix attrs.
        rsclient
            .idm_account_unix_extend("posix_account", None, None)
            .unwrap();

        // Create a group

        // Extend the group with posix attrs
        rsclient.idm_group_create("posix_group").unwrap();
        rsclient
            .idm_group_add_members("posix_group", &["posix_account"])
            .unwrap();
        rsclient.idm_group_unix_extend("posix_group", None).unwrap();

        // Open a new connection as anonymous
        let res = rsclient.auth_anonymous();
        assert!(res.is_ok());

        // Get the account by name
        let r = rsclient
            .idm_account_unix_token_get("posix_account")
            .unwrap();
        // Get the account by gidnumber
        let r1 = rsclient
            .idm_account_unix_token_get(r.gidnumber.to_string().as_str())
            .unwrap();
        // get the account by spn
        let r2 = rsclient.idm_account_unix_token_get(r.spn.as_str()).unwrap();
        // get the account by uuid
        let r3 = rsclient
            .idm_account_unix_token_get(r.uuid.as_str())
            .unwrap();

        println!("{:?}", r);
        assert!(r.name == "posix_account");
        assert!(r1.name == "posix_account");
        assert!(r2.name == "posix_account");
        assert!(r3.name == "posix_account");

        // get the group by nam
        let r = rsclient.idm_group_unix_token_get("posix_group").unwrap();
        // Get the group by gidnumber
        let r1 = rsclient
            .idm_group_unix_token_get(r.gidnumber.to_string().as_str())
            .unwrap();
        // get the group spn
        let r2 = rsclient.idm_group_unix_token_get(r.spn.as_str()).unwrap();
        // get the group by uuid
        let r3 = rsclient.idm_group_unix_token_get(r.uuid.as_str()).unwrap();

        println!("{:?}", r);
        assert!(r.name == "posix_group");
        assert!(r1.name == "posix_group");
        assert!(r2.name == "posix_group");
        assert!(r3.name == "posix_group");
    });
}

#[test]
fn test_server_rest_posix_auth_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());
        // Get an anon connection
        let anon_rsclient = rsclient.new_session().unwrap();
        assert!(anon_rsclient.auth_anonymous().is_ok());

        // Not recommended in production!
        rsclient
            .idm_group_add_members("idm_admins", &["admin"])
            .unwrap();

        // Setup a unix user
        rsclient
            .idm_account_create("posix_account", "Posix Demo Account")
            .unwrap();

        // Extend the account with posix attrs.
        rsclient
            .idm_account_unix_extend("posix_account", None, None)
            .unwrap();

        // add their password (unix self)
        rsclient
            .idm_account_unix_cred_put("posix_account", UNIX_TEST_PASSWORD)
            .unwrap();

        // attempt to verify (good, anon-conn)
        let r1 = anon_rsclient.idm_account_unix_cred_verify("posix_account", UNIX_TEST_PASSWORD);
        match r1 {
            Ok(Some(_tok)) => {}
            _ => assert!(false),
        };

        // attempt to verify (bad, anon-conn)
        let r2 = anon_rsclient.idm_account_unix_cred_verify("posix_account", "ntaotnhuohtsuoehtsu");
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
            .unwrap();

        // attempt to verify (good pw, should fail, anon-conn)
        let r3 = anon_rsclient.idm_account_unix_cred_verify("posix_account", UNIX_TEST_PASSWORD);
        match r3 {
            Ok(None) => {}
            _ => assert!(false),
        };
    });
}

#[test]
fn test_server_rest_recycle_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Not recommended in production!
        rsclient
            .idm_group_add_members("idm_admins", &["admin"])
            .unwrap();

        // Setup a unix user
        rsclient
            .idm_account_create("recycle_account", "Recycle Demo Account")
            .unwrap();

        // delete them
        rsclient.idm_account_delete("recycle_account").unwrap();

        // not there
        let acc = rsclient.idm_account_get("recycle_account").unwrap();
        assert!(acc.is_none());

        // list the recycle bin
        let r_list = rsclient.recycle_bin_list().unwrap();

        assert!(r_list.len() == 1);
        // get the user in recycle bin
        let r_user = rsclient.recycle_bin_get("recycle_account").unwrap();
        assert!(r_user.is_some());

        // revive
        rsclient.recycle_bin_revive("recycle_account").unwrap();

        // they are there!
        let acc = rsclient.idm_account_get("recycle_account").unwrap();
        assert!(acc.is_some());
    });
}

#[test]
fn test_server_rest_account_import_password() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());
        // To enable the admin to actually make some of these changes, we have
        // to make them a password import admin. NOT recommended in production!
        rsclient
            .idm_group_add_members("idm_people_account_password_import_priv", &["admin"])
            .unwrap();
        rsclient
            .idm_group_add_members("idm_people_extend_priv", &["admin"])
            .unwrap();

        // Create a new account
        rsclient
            .idm_account_create("demo_account", "Deeeeemo")
            .unwrap();

        // Make them a person, so we can import the password
        rsclient.idm_account_person_extend("demo_account").unwrap();

        // Attempt to import a bad password
        let r = rsclient.idm_account_primary_credential_import_password("demo_account", "password");
        assert!(r.is_err());

        // Import a good password
        // eicieY7ahchaoCh0eeTa
        // pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=
        rsclient
            .idm_account_primary_credential_import_password(
                "demo_account",
                "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=",
            )
            .unwrap();

        // Now show we can auth with it
        // "reset" the client.
        let _ = rsclient.logout();
        let res = rsclient.auth_simple_password("demo_account", "eicieY7ahchaoCh0eeTa");
        assert!(res.is_ok());

        // And that the account can self read the cred status.
        let cred_state = rsclient
            .idm_account_get_credential_status("demo_account")
            .unwrap();

        if let Some(cred) = cred_state.creds.get(0) {
            assert!(cred.type_ == CredentialDetailType::Password)
        } else {
            assert!(false);
        }
    });
}

#[test]
fn test_server_rest_totp_auth_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Not recommended in production!
        rsclient
            .idm_group_add_members("idm_admins", &["admin"])
            .unwrap();

        // Create a new account
        rsclient
            .idm_account_create("demo_account", "Deeeeemo")
            .unwrap();

        // Enroll a totp to the account
        assert!(rsclient
            .idm_account_primary_credential_set_password("demo_account", "sohdi3iuHo6mai7noh0a")
            .is_ok());
        let (sessionid, tok) = rsclient
            .idm_account_primary_credential_generate_totp("demo_account", "demo")
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
            .is_ok());

        // Check a bad auth - needs to be second as we are going to trigger the slock.
        // Get a new connection
        let rsclient_bad = rsclient.new_session().unwrap();
        assert!(rsclient_bad
            .auth_password_totp("demo_account", "sohdi3iuHo6mai7noh0a", 0)
            .is_err());
        // Delay by one second to allow the account to recover from the softlock.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Remove TOTP on the account.
        rsclient
            .idm_account_primary_credential_remove_totp("demo_account")
            .unwrap();
        // Check password auth.
        let rsclient_good = rsclient.new_session().unwrap();
        assert!(rsclient_good
            .auth_simple_password("demo_account", "sohdi3iuHo6mai7noh0a")
            .is_ok());
    });
}

#[test]
fn test_server_rest_webauthn_auth_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Not recommended in production!
        rsclient
            .idm_group_add_members("idm_admins", &["admin"])
            .unwrap();

        // Create a new account
        rsclient
            .idm_account_create("demo_account", "Deeeeemo")
            .unwrap();

        // Enroll a soft token to the account webauthn.
        let mut wa_softtok = WebauthnAuthenticator::new(U2FSoft::new());

        // Do the challenge
        let (sessionid, regchal) = rsclient
            .idm_account_primary_credential_register_webauthn("demo_account", "softtok")
            .unwrap();

        let rego = wa_softtok
            .do_registration("https://idm.example.com", regchal)
            .expect("Failed to register to softtoken");

        // Enroll the cred after signing.
        rsclient
            .idm_account_primary_credential_complete_webuthn_registration(
                "demo_account",
                rego,
                sessionid,
            )
            .unwrap();

        // ====== Reg a second token.
        let mut wa_softtok_2 = WebauthnAuthenticator::new(U2FSoft::new());

        // Do the challenge
        let (sessionid, regchal) = rsclient
            .idm_account_primary_credential_register_webauthn("demo_account", "softtok_2")
            .unwrap();

        let rego = wa_softtok_2
            .do_registration("https://idm.example.com", regchal)
            .expect("Failed to register to softtoken");

        // Enroll the cred after signing.
        rsclient
            .idm_account_primary_credential_complete_webuthn_registration(
                "demo_account",
                rego,
                sessionid,
            )
            .unwrap();

        // Now do an auth
        let rsclient_good = rsclient.new_session().unwrap();

        let pkr = rsclient_good.auth_webauthn_begin("demo_account").unwrap();

        // Get the auth chal.
        let auth = wa_softtok_2
            .do_authentication("https://idm.example.com", pkr)
            .expect("Failed to auth to softtoken");

        // Submit the webauthn auth.
        rsclient_good
            .auth_webauthn_complete(auth)
            .expect("Failed to authenticate");

        // ======== remove the second softtok.

        rsclient
            .idm_account_primary_credential_remove_webauthn("demo_account", "softtok_2")
            .expect("failed to remove softtoken");

        // All good, check first tok auth.

        let rsclient_good = rsclient.new_session().unwrap();

        let pkr = rsclient_good.auth_webauthn_begin("demo_account").unwrap();

        // Get the auth chal.
        let auth = wa_softtok
            .do_authentication("https://idm.example.com", pkr)
            .expect("Failed to auth to softtoken");

        // Submit the webauthn auth.
        rsclient_good
            .auth_webauthn_complete(auth)
            .expect("Failed to authenticate");
    });
}

#[test]
fn test_server_rest_webauthn_mfa_auth_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Not recommended in production!
        rsclient
            .idm_group_add_members("idm_admins", &["admin"])
            .unwrap();

        // Create a new account
        rsclient
            .idm_account_create("demo_account", "Deeeeemo")
            .unwrap();

        // Enroll a soft token to the account webauthn.
        let mut wa_softtok = WebauthnAuthenticator::new(U2FSoft::new());

        // Do the challenge
        let (sessionid, regchal) = rsclient
            .idm_account_primary_credential_register_webauthn("demo_account", "softtok")
            .unwrap();

        let rego = wa_softtok
            .do_registration("https://idm.example.com", regchal)
            .expect("Failed to register to softtoken");

        // Enroll the cred after signing.
        rsclient
            .idm_account_primary_credential_complete_webuthn_registration(
                "demo_account",
                rego,
                sessionid,
            )
            .unwrap();

        // Now do an auth
        let rsclient_good = rsclient.new_session().unwrap();

        let pkr = rsclient_good.auth_webauthn_begin("demo_account").unwrap();

        // Get the auth chal.
        let auth = wa_softtok
            .do_authentication("https://idm.example.com", pkr)
            .expect("Failed to auth to softtoken");

        // Submit the webauthn auth.
        rsclient_good
            .auth_webauthn_complete(auth)
            .expect("Failed to authenticate");

        // Set a password to cause the state to change to PasswordMfa
        assert!(rsclient
            .idm_account_primary_credential_set_password("demo_account", "sohdi3iuHo6mai7noh0a")
            .is_ok());

        // Now remove Webauthn ...
        rsclient
            .idm_account_primary_credential_remove_webauthn("demo_account", "softtok")
            .expect("failed to remove softtoken");

        // Check pw only
        let rsclient_good = rsclient.new_session().unwrap();
        assert!(rsclient_good
            .auth_simple_password("demo_account", "sohdi3iuHo6mai7noh0a")
            .is_ok());
    });
}

// Test setting account expiry

// Test the self version of the radius path.

// Test hitting all auth-required endpoints and assert they give unauthorized.

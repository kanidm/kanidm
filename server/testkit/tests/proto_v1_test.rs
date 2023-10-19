#![deny(warnings)]
use std::path::Path;
use std::time::SystemTime;

use kanidm_proto::constants::KSESSIONID;
use kanidm_proto::internal::ImageValue;
use kanidm_proto::v1::{
    ApiToken, AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthResponse, AuthState,
    AuthStep, CURegState, CredentialDetailType, Entry, Filter, Modify, ModifyList, UatPurpose,
    UserAuthToken,
};
use kanidmd_lib::credential::totp::Totp;
use kanidmd_lib::prelude::{
    Attribute, BUILTIN_GROUP_IDM_ADMINS_V1, BUILTIN_GROUP_SYSTEM_ADMINS_V1,
    IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
};
use tracing::{debug, trace};

use std::str::FromStr;

use compact_jwt::JwsUnverified;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::WebauthnAuthenticator;

use kanidm_client::{ClientError, KanidmClient};
use kanidmd_testkit::{ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};

const UNIX_TEST_PASSWORD: &str = "unix test user password";

#[kanidmd_testkit::test]
async fn test_server_create(rsclient: KanidmClient) {
    let e: Entry = serde_json::from_str(
        r#"{
            "attrs": {
                "class": ["account", "service_account"],
                "name": ["testaccount"],
                "displayname": ["testaccount"]
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

#[kanidmd_testkit::test]
async fn test_server_modify(rsclient: KanidmClient) {
    // Build a self mod.
    let f = Filter::SelfUuid;
    let m = ModifyList::new_list(vec![
        Modify::Purged(Attribute::DisplayName.to_string()),
        Modify::Present(Attribute::DisplayName.to_string(), "test".to_string()),
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

#[kanidmd_testkit::test]
async fn test_server_whoami_anonymous(rsclient: KanidmClient) {
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    assert!(pre_res.unwrap().is_none());

    // Now login as anonymous
    let res = rsclient.auth_anonymous().await;
    assert!(res.is_ok());

    // Now do a whoami.
    let e = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned");
    debug!(?e);
    assert!(e.attrs.get("spn") == Some(&vec!["anonymous@localhost".to_string()]));

    // Do a check of the auth/valid endpoint, tells us if our token
    // is okay.
    let res = rsclient.auth_valid().await;
    assert!(res.is_ok());
}

#[kanidmd_testkit::test]
async fn test_server_whoami_admin_simple_password(rsclient: KanidmClient) {
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    assert!(pre_res.unwrap().is_none());

    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Now do a whoami.
    let e = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned");
    debug!(?e);
    assert!(e.attrs.get("spn") == Some(&vec!["admin@localhost".to_string()]));
}

#[kanidmd_testkit::test]
async fn test_server_search(rsclient: KanidmClient) {
    // First show we are un-authenticated.
    let pre_res = rsclient.whoami().await;
    // This means it was okay whoami, but no uat attached.
    println!("Response: {:?}", pre_res);
    assert!(pre_res.unwrap().is_none());

    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let rset = rsclient
        .search(Filter::Eq(Attribute::Name.to_string(), "admin".to_string()))
        .await
        .unwrap();
    println!("{:?}", rset);
    let e = rset.first().unwrap();
    // Check it's admin.
    println!("{:?}", e);
    let name = e.attrs.get(Attribute::Name.as_ref()).unwrap();
    assert!(name == &vec!["admin".to_string()]);
}

// test the rest group endpoint.
#[kanidmd_testkit::test]
async fn test_server_rest_group_read(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List the groups
    let g_list = rsclient.idm_group_list().await.unwrap();
    assert!(!g_list.is_empty());

    let g = rsclient
        .idm_group_get(BUILTIN_GROUP_IDM_ADMINS_V1.name)
        .await
        .unwrap();
    assert!(g.is_some());
    println!("{:?}", g);
}

#[kanidmd_testkit::test]
async fn test_server_rest_group_lifecycle(rsclient: KanidmClient) {
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
    assert!(members.is_none());

    // Delete the group
    rsclient.idm_group_delete("demo_group").await.unwrap();
    let g_list_3 = rsclient.idm_group_list().await.unwrap();
    assert!(g_list_3.len() == g_list.len());

    // Check we can get an exact group
    let g = rsclient
        .idm_group_get(BUILTIN_GROUP_IDM_ADMINS_V1.name)
        .await
        .unwrap();
    assert!(g.is_some());
    println!("{:?}", g);

    // They should have members
    let members = rsclient
        .idm_group_get_members(BUILTIN_GROUP_IDM_ADMINS_V1.name)
        .await
        .unwrap();
    println!("{:?}", members);
    assert!(members == Some(vec!["idm_admin@localhost".to_string()]));
}

#[kanidmd_testkit::test]
async fn test_server_rest_account_read(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // List the accounts
    let a_list = rsclient.idm_service_account_list().await.unwrap();
    assert!(!a_list.is_empty());

    let a = rsclient.idm_service_account_get("admin").await.unwrap();
    assert!(a.is_some());
    println!("{:?}", a);
}

#[kanidmd_testkit::test]
async fn test_server_rest_schema_read(rsclient: KanidmClient) {
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
    let a = rsclient
        .idm_schema_attributetype_get(Attribute::Name.as_ref())
        .await
        .unwrap();
    assert!(a.is_some());
    println!("{:?}", a);

    let c = rsclient
        .idm_schema_classtype_get(Attribute::Account.as_ref())
        .await
        .unwrap();
    assert!(c.is_some());
    println!("{:?}", c);
}

// Test resetting a radius cred, and then checking/viewing it.
#[kanidmd_testkit::test]
async fn test_server_radius_credential_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // All admin to create persons.
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // self management of credentials is only for persons.
    rsclient
        .idm_person_account_create("demo_account", "Deeeeemo")
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

#[kanidmd_testkit::test]
async fn test_server_rest_person_account_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // To enable the admin to actually make some of these changes, we have
    // to make them a people admin. NOT recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_person_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // View the account
    rsclient
        .idm_person_account_get("demo_account")
        .await
        .unwrap();

    // change the name?
    rsclient
        .idm_person_account_set_attr("demo_account", "displayname", &["Demo Account"])
        .await
        .unwrap();

    // Test adding some mail addrs
    rsclient
        .idm_person_account_add_attr(
            "demo_account",
            Attribute::Mail.as_ref(),
            &["demo@idm.example.com"],
        )
        .await
        .unwrap();

    let r = rsclient
        .idm_person_account_get_attr("demo_account", Attribute::Mail.as_ref())
        .await
        .unwrap();

    assert!(r == Some(vec!["demo@idm.example.com".to_string()]));

    // Delete the account
    rsclient
        .idm_person_account_delete("demo_account")
        .await
        .unwrap();
}

#[kanidmd_testkit::test]
async fn test_server_rest_sshkey_lifecycle(rsclient: KanidmClient) {
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
        .idm_service_account_post_ssh_pubkey("admin", "inv", "invalid key")
        .await;
    assert!(r1.is_err());

    // Post a valid key
    let r2 = rsclient
            .idm_service_account_post_ssh_pubkey("admin", "k1", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst").await;
    println!("{:?}", r2);
    assert!(r2.is_ok());

    // Get, should have the key
    let sk2 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk2.len() == 1);

    // Post a valid key
    let r3 = rsclient
            .idm_service_account_post_ssh_pubkey("admin", "k2", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx4TpJYQjd0YI5lQIHqblIsCIK5NKVFURYS/eM3o6/Z william@amethyst").await;
    assert!(r3.is_ok());

    // Get, should have both keys.
    let sk3 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk3.len() == 2);

    // Delete a key (by tag)
    let r4 = rsclient
        .idm_service_account_delete_ssh_pubkey("admin", "k1")
        .await;
    assert!(r4.is_ok());

    // Get, should have remaining key.
    let sk4 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk4.len() == 1);

    // get by tag
    let skn = rsclient.idm_account_get_ssh_pubkey("admin", "k2").await;
    assert!(skn.is_ok());
    assert!(skn.unwrap() == Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx4TpJYQjd0YI5lQIHqblIsCIK5NKVFURYS/eM3o6/Z william@amethyst".to_string()));

    // Add a key and delete with a space in the name.
    let r5 = rsclient
            .idm_service_account_post_ssh_pubkey("admin", "Yk 5 Nfc", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBENubZikrb8hu+HeVRdZ0pp/VAk2qv4JDbuJhvD0yNdWDL2e3cBbERiDeNPkWx58Q4rVnxkbV1fa8E2waRtT91wAAAAEc3NoOg== william@maxixe").await;
    assert!(r5.is_ok());

    let r6 = rsclient
        .idm_service_account_delete_ssh_pubkey("admin", "Yk 5 Nfc")
        .await;
    assert!(r6.is_ok());

    let sk5 = rsclient.idm_account_get_ssh_pubkeys("admin").await.unwrap();
    assert!(sk5.len() == 1);
}

#[kanidmd_testkit::test]
async fn test_server_rest_domain_lifecycle(rsclient: KanidmClient) {
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
            .get(Attribute::DomainDisplayName.as_ref())
            .and_then(|v| v.get(0))
            == Some(&"Super Cool Crabz".to_string())
    );
}

#[kanidmd_testkit::test]
async fn test_server_rest_posix_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Create a new account
    rsclient
        .idm_person_account_create("posix_account", "Posix Demo Account")
        .await
        .unwrap();

    // Extend the account with posix attrs.
    rsclient
        .idm_person_account_unix_extend("posix_account", None, None)
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
    // here we check that we can successfully change the gid without breaking anything

    let res = rsclient
        .idm_group_unix_extend("posix_group", Some(123123))
        .await;
    assert!(res.is_ok());

    let res = rsclient.idm_group_unix_extend("posix_group", None).await;
    assert!(res.is_ok());

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
        .idm_account_unix_token_get(&r.uuid.hyphenated().to_string())
        .await
        .unwrap();

    println!("{:?}", r);
    assert!(r.name == "posix_account");
    assert!(r1.name == "posix_account");
    assert!(r2.name == "posix_account");
    assert!(r3.name == "posix_account");

    // get the group by name
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
        .idm_group_unix_token_get(&r.uuid.hyphenated().to_string())
        .await
        .unwrap();

    println!("{:?}", r);
    assert!(r.name == "posix_group");
    assert!(r1.name == "posix_group");
    assert!(r2.name == "posix_group");
    assert!(r3.name == "posix_group");
}

#[kanidmd_testkit::test]
async fn test_server_rest_posix_auth_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // Get an anon connection
    let anon_rsclient = rsclient.new_session().unwrap();
    assert!(anon_rsclient.auth_anonymous().await.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Setup a unix user
    rsclient
        .idm_person_account_create("posix_account", "Posix Demo Account")
        .await
        .unwrap();

    // Extend the account with posix attrs.
    rsclient
        .idm_person_account_unix_extend("posix_account", None, None)
        .await
        .unwrap();

    // add their password (unix self)
    rsclient
        .idm_person_account_unix_cred_put("posix_account", UNIX_TEST_PASSWORD)
        .await
        .unwrap();

    // test sending a faulty JSON blob to the person unix update endpoint
    let bad_json: serde_json::Value = serde_json::json!({
        "shell" : "test_value",
        "gidnumber" : "5" // this should be a u32, but it's not!
    });
    let res = rsclient
        .perform_post_request::<serde_json::Value, String>(
            format!("/v1/person/{}/_unix", "posix_account").as_str(),
            bad_json,
        )
        .await;
    tracing::trace!("{:?}", &res);
    assert!(res.is_err());

    // test sending a faulty JSON blob to the person unix update endpoint
    let bad_json: serde_json::Value = serde_json::json!({
        "crab" : "cakes", // this is an invalid field.
        "gidnumber" : 5
    });
    let res = rsclient
        .perform_post_request::<serde_json::Value, String>(
            format!("/v1/person/{}/_unix", "posix_account").as_str(),
            bad_json,
        )
        .await;
    tracing::trace!("{:?}", &res);
    assert!(res.is_err());

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
        .idm_person_account_unix_cred_delete("posix_account")
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

#[kanidmd_testkit::test]
async fn test_server_rest_recycle_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Setup a unix user
    rsclient
        .idm_person_account_create("recycle_account", "Recycle Demo Account")
        .await
        .unwrap();

    // delete them
    rsclient
        .idm_person_account_delete("recycle_account")
        .await
        .unwrap();

    // not there
    let acc = rsclient
        .idm_person_account_get("recycle_account")
        .await
        .unwrap();
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
    let acc = rsclient
        .idm_person_account_get("recycle_account")
        .await
        .unwrap();
    assert!(acc.is_some());
}

#[kanidmd_testkit::test]
async fn test_server_rest_account_import_password(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    // To enable the admin to actually make some of these changes, we have
    // to make them a password import admin. NOT recommended in production!
    rsclient
        .idm_group_add_members(IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1.name, &["admin"])
        .await
        .unwrap();
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Create a new person
    rsclient
        .idm_person_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // Attempt to import a bad password
    let r = rsclient
        .idm_person_account_primary_credential_import_password("demo_account", "password")
        .await;
    assert!(r.is_err());

    // Import a good password
    // eicieY7ahchaoCh0eeTa
    // pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=
    rsclient
        .idm_person_account_primary_credential_import_password(
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
        .idm_person_account_get_credential_status("demo_account")
        .await
        .unwrap();

    if let Some(cred) = cred_state.creds.get(0) {
        assert!(cred.type_ == CredentialDetailType::Password)
    } else {
        assert!(false);
    }
}

#[kanidmd_testkit::test]
async fn test_server_rest_oauth2_basic_lifecycle(rsclient: KanidmClient) {
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
    assert!(oauth2_config
        .attrs
        .contains_key(Attribute::OAuth2RsBasicSecret.as_ref()));
    // This is present, but redacted.
    assert!(oauth2_config
        .attrs
        .contains_key(Attribute::OAuth2RsTokenKey.as_ref()));

    // Mod delete the secret/key and check them again.
    // Check we can patch the oauth2_rs_name / oauth2_rs_origin
    rsclient
        .idm_oauth2_rs_update(
            "test_integration",
            None,
            Some("Test Integration"),
            Some("https://new_demo.example.com"),
            None,
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
        .idm_oauth2_rs_update_scope_map(
            "test_integration",
            BUILTIN_GROUP_SYSTEM_ADMINS_V1.name,
            vec!["a", "b"],
        )
        .await
        .expect("Failed to create scope map");

    let oauth2_config_updated2 = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    assert!(oauth2_config_updated != oauth2_config_updated2);

    // Check we can update a scope map
    rsclient
        .idm_oauth2_rs_update_scope_map(
            "test_integration",
            BUILTIN_GROUP_SYSTEM_ADMINS_V1.name,
            vec!["a", "b", "c"],
        )
        .await
        .expect("Failed to create scope map");

    let oauth2_config_updated3 = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    assert!(oauth2_config_updated2 != oauth2_config_updated3);

    // Check we can upload an image
    let image_path = Path::new("../../server/lib/src/valueset/image/test_images/ok.png");
    assert!(image_path.exists());
    let image_contents = std::fs::read(image_path).unwrap();
    let image = ImageValue::new(
        "test".to_string(),
        kanidm_proto::internal::ImageType::Png,
        image_contents,
    );

    let res = rsclient
        .idm_oauth2_rs_update_image("test_integration", image)
        .await;
    trace!("update image result: {:?}", &res);
    assert!(res.is_ok());

    //test getting the image
    let client = reqwest::Client::new();

    let response = client
        .get(rsclient.make_url("/ui/images/oauth2/test_integration"))
        .bearer_auth(rsclient.get_token().await.unwrap());

    let response = response
        .send()
        .await
        .map_err(|err| rsclient.handle_response_error(err))
        .unwrap();

    assert!(response.status().is_success());

    // check we can upload a *replacement* image

    let image_path = Path::new("../../server/lib/src/valueset/image/test_images/ok.jpg");
    trace!("image path {:?}", &image_path.canonicalize());
    assert!(image_path.exists());
    let jpg_file_contents = std::fs::read(image_path).unwrap();
    let image = ImageValue::new(
        "test".to_string(),
        kanidm_proto::internal::ImageType::Jpg,
        jpg_file_contents.clone(),
    );
    let res = rsclient
        .idm_oauth2_rs_update_image("test_integration", image)
        .await;
    trace!("idm_oauth2_rs_update_image result: {:?}", &res);
    assert!(res.is_ok());

    // check it fails when we upload a jpg and say it's a webp
    let image = ImageValue::new(
        "test".to_string(),
        kanidm_proto::internal::ImageType::Webp,
        jpg_file_contents,
    );
    let res = rsclient
        .idm_oauth2_rs_update_image("test_integration", image)
        .await;
    trace!("idm_oauth2_rs_update_image result: {:?}", &res);
    assert!(res.is_err());

    // check we can remove an image

    let res = rsclient
        .idm_oauth2_rs_delete_image("test_integration")
        .await;
    trace!("idm_oauth2_rs_delete_image result: {:?}", &res);
    assert!(res.is_ok());

    // Check we can delete a scope map.

    rsclient
        .idm_oauth2_rs_delete_scope_map("test_integration", BUILTIN_GROUP_SYSTEM_ADMINS_V1.name)
        .await
        .expect("Failed to delete scope map");

    let oauth2_config_updated4 = rsclient
        .idm_oauth2_rs_get("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration config");

    eprintln!("{:?}", oauth2_config_updated);
    eprintln!("{:?}", oauth2_config_updated4);

    assert!(oauth2_config_updated == oauth2_config_updated4);

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

#[kanidmd_testkit::test]
async fn test_server_credential_update_session_pw(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Create an account
    rsclient
        .idm_person_account_create("demo_account", "Demo Account")
        .await
        .unwrap();

    // Create an intent token for them
    let intent_token = rsclient
        .idm_person_account_credential_update_intent("demo_account", Some(0))
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

#[kanidmd_testkit::test]
async fn test_server_credential_update_session_totp_pw(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Create a person
    // - person so they can self-modify credentials later in the test
    rsclient
        .idm_person_account_create("demo_account", "Demo Account")
        .await
        .unwrap();

    let intent_token = rsclient
        .idm_person_account_credential_update_intent("demo_account", Some(999999))
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
        CURegState::TotpCheck(totp_secret) => totp_secret.try_into().unwrap(),
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
        .idm_account_credential_update_check_totp(&session_token, totp_chal, "totp")
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

    // We are now authed as the demo_account, however we need to priv auth to get write
    // access to self for credential updates.
    let totp_chal = totp
        .do_totp_duration_from_epoch(
            &SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
        .expect("Failed to do totp?");

    let res = rsclient
        .reauth_password_totp("sohdi3iuHo6mai7noh0a", totp_chal)
        .await;
    assert!(res.is_ok());

    // Self create the session and remove the totp now.
    let (session_token, _status) = rsclient
        .idm_account_credential_update_begin("demo_account")
        .await
        .unwrap();

    let _status = rsclient
        .idm_account_credential_update_remove_totp(&session_token, "totp")
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

async fn setup_demo_account_passkey(rsclient: &KanidmClient) -> WebauthnAuthenticator<SoftPasskey> {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .unwrap();

    // Create an account
    rsclient
        .idm_person_account_create("demo_account", "Demo Account")
        .await
        .unwrap();

    // Create an intent token for them
    let intent_token = rsclient
        .idm_person_account_credential_update_intent("demo_account", Some(1234))
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
    let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

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

    wa
}

async fn setup_demo_account_password(
    rsclient: &KanidmClient,
) -> Result<(String, String), ClientError> {
    let account_name = String::from_str("demo_account").expect("Failed to parse string");

    let account_pass = String::from_str("eicieY7ahchaoCh0eeTa").expect("Failed to parse string");

    rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &["admin"])
        .await
        .expect("Failed to add admin to idm_admins");

    rsclient
        .idm_person_account_create("demo_account", "Deeeeemo")
        .await
        .expect("Failed to create demo account");

    // First, show there are no auth sessions.
    let sessions = rsclient
        .idm_account_list_user_auth_token("demo_account")
        .await
        .expect("Failed to list user auth tokens");
    assert!(sessions.is_empty());

    // Setup the credentials for the account
    // Create an intent token for them
    let intent_token = rsclient
        .idm_person_account_credential_update_intent("demo_account", None)
        .await
        .expect("Failed to create intent token");

    // Logout, we don't need any auth now.
    rsclient.logout().await.expect("Failed to logout");

    // Exchange the intent token
    let (session_token, _status) = rsclient
        .idm_account_credential_update_exchange(intent_token)
        .await
        .expect("Failed to exchange intent token");

    // Setup and update the password
    rsclient
        .idm_account_credential_update_set_password(&session_token, account_pass.as_str())
        .await
        .expect("Failed to set password");

    // Commit it
    rsclient
        .idm_account_credential_update_commit(&session_token)
        .await
        .expect("Failed to commit changes");

    Ok((account_name, account_pass))
}

#[kanidmd_testkit::test]
async fn test_server_credential_update_session_passkey(rsclient: KanidmClient) {
    let mut wa = setup_demo_account_passkey(&rsclient).await;

    let res = rsclient
        .auth_passkey_begin("demo_account")
        .await
        .expect("Failed to start passkey auth");

    let pkc = wa
        .do_authentication(rsclient.get_origin().clone(), res)
        .map(Box::new)
        .expect("Failed to authentication with soft passkey");

    let res = rsclient.auth_passkey_complete(pkc).await;
    assert!(res.is_ok());
}

#[kanidmd_testkit::test]
async fn test_server_api_token_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let test_service_account_username = "test_service";

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &[ADMIN_TEST_USER])
        .await
        .unwrap();

    rsclient
        .idm_service_account_create(test_service_account_username, "Test Service")
        .await
        .expect("Failed to create service account");

    let tokens = rsclient
        .idm_service_account_list_api_token(test_service_account_username)
        .await
        .expect("Failed to list service account api tokens");
    assert!(tokens.is_empty());

    let token = rsclient
        .idm_service_account_generate_api_token(
            test_service_account_username,
            "test token",
            None,
            false,
        )
        .await
        .expect("Failed to create service account api token");

    // Decode it?
    let token_unverified = JwsUnverified::from_str(&token).expect("Failed to parse apitoken");

    let token: ApiToken = token_unverified
        .validate_embeded()
        .map(|j| j.into_inner())
        .expect("Embedded jwk not found");

    let tokens = rsclient
        .idm_service_account_list_api_token(test_service_account_username)
        .await
        .expect("Failed to list service account api tokens");

    assert!(tokens == vec![token.clone()]);

    rsclient
        .idm_service_account_destroy_api_token(&token.account_id.to_string(), token.token_id)
        .await
        .expect("Failed to destroy service account api token");

    let tokens = rsclient
        .idm_service_account_list_api_token(test_service_account_username)
        .await
        .expect("Failed to list service account api tokens");
    assert!(tokens.is_empty());

    // test we can add an attribute
    assert!(rsclient
        .idm_service_account_add_attr(
            test_service_account_username,
            Attribute::Mail.as_ref(),
            &vec!["test@example.com"]
        )
        .await
        .is_ok());

    // test we can overwrite an attribute
    let new_displayname = vec!["testing displayname 1235"];
    assert!(rsclient
        .idm_service_account_set_attr(
            test_service_account_username,
            Attribute::DisplayName.as_ref(),
            &new_displayname
        )
        .await
        .is_ok());
    // check it actually set
    let displayname = rsclient
        .idm_service_account_get_attr(
            test_service_account_username,
            Attribute::DisplayName.as_ref(),
        )
        .await
        .expect("Failed to get displayname")
        .expect("Failed to unwrap displayname");
    assert!(new_displayname == displayname);

    rsclient
        .idm_service_account_purge_attr(test_service_account_username, Attribute::Mail.as_ref())
        .await
        .expect("Failed to purge displayname");

    assert!(rsclient
        .idm_service_account_get_attr(test_service_account_username, Attribute::Mail.as_ref(),)
        .await
        .expect("Failed to check mail attr")
        .is_none());

    assert!(rsclient
        .idm_service_account_unix_extend(
            test_service_account_username,
            Some(58008),
            Some("/bin/vim")
        )
        .await
        .is_ok());

    assert!(rsclient
        .idm_service_account_unix_extend(
            test_service_account_username,
            Some(1000),
            Some("/bin/vim")
        )
        .await
        .is_err());

    // because you have to set *something*
    assert!(rsclient
        .idm_service_account_update(test_service_account_username, None, None, None)
        .await
        .is_err());
    assert!(rsclient
        .idm_service_account_update(
            test_service_account_username,
            Some(&format!("{}lol", test_service_account_username)),
            Some(&format!("{}displayzzzz", test_service_account_username)),
            Some(&[format!("{}@example.crabs", test_service_account_username)]),
        )
        .await
        .is_err());

    let pw = rsclient
        .idm_service_account_generate_password(test_service_account_username)
        .await
        .expect("Failed to get a pw for the service account");

    assert!(!pw.is_empty());
    assert!(pw.is_ascii());

    let res = rsclient
        .idm_service_account_get_credential_status(test_service_account_username)
        .await;
    dbg!(&res);
    assert!(res.is_ok());

    println!(
        "testing deletion of service account {}",
        test_service_account_username
    );
    assert!(rsclient
        .idm_service_account_delete(test_service_account_username)
        .await
        .is_ok());

    // let's create one and just yolo it into a person
    // TODO: Turns out this doesn't work because admin doesn't have the right perms to remove `jws_es256_private_key` from the account?
    // rsclient
    // .idm_service_account_create(test_service_account_username, "Test Service")
    // .await
    // .expect("Failed to create service account");

    // rsclient.idm_service_account_into_person(test_service_account_username).await.expect("Failed to convert service account into person");

    // assert!(rsclient
    //     .idm_person_account_delete(test_service_account_username)
    //     .await
    //     .is_ok());

    // No need to test expiry, that's validated in the server internal tests.
}

#[kanidmd_testkit::test]
async fn test_server_user_auth_token_lifecycle(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Not recommended in production!
    rsclient
        .idm_group_add_members(BUILTIN_GROUP_IDM_ADMINS_V1.name, &[ADMIN_TEST_USER])
        .await
        .unwrap();

    rsclient
        .idm_person_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // First, show there are no auth sessions.
    let sessions = rsclient
        .idm_account_list_user_auth_token("demo_account")
        .await
        .expect("Failed to list user auth tokens");
    assert!(sessions.is_empty());

    // Setup the credentials for the account

    {
        // Create an intent token for them
        let intent_token = rsclient
            .idm_person_account_credential_update_intent("demo_account", None)
            .await
            .unwrap();

        // Logout, we don't need any auth now.
        let _ = rsclient.logout();
        // Exchange the intent token
        let (session_token, _status) = rsclient
            .idm_account_credential_update_exchange(intent_token)
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
    }

    // Auth as the user.

    let _ = rsclient.logout();
    let res = rsclient
        .auth_simple_password("demo_account", "eicieY7ahchaoCh0eeTa")
        .await;
    assert!(res.is_ok());

    let token = rsclient.get_token().await.expect("No bearer token present");

    let token_unverified =
        JwsUnverified::from_str(&token).expect("Failed to parse user auth token");

    let token: UserAuthToken = token_unverified
        .validate_embeded()
        .map(|j| j.into_inner())
        .expect("Embedded jwk not found");

    let sessions = rsclient
        .idm_account_list_user_auth_token("demo_account")
        .await
        .expect("Failed to list user auth tokens");

    assert!(sessions[0].session_id == token.session_id);

    // idm_account_destroy_user_auth_token
    rsclient
        .idm_account_destroy_user_auth_token("demo_account", token.session_id)
        .await
        .expect("Failed to destroy user auth token");

    // Since the session is revoked, check with the admin.
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let tokens = rsclient
        .idm_service_account_list_api_token("demo_account")
        .await
        .expect("Failed to list user auth tokens");
    assert!(tokens.is_empty());

    // No need to test expiry, that's validated in the server internal tests.

    // testing idm_account_credential_update_cancel_mfareg
    let (token, _status) = rsclient
        .idm_account_credential_update_begin("demo_account")
        .await
        .expect("Failed to get token for demo_account");

    println!("trying to cancel the token we just got");
    assert!(rsclient
        .idm_account_credential_update_cancel_mfareg(&token)
        .await
        .is_ok());
}

#[kanidmd_testkit::test]
async fn test_server_user_auth_reauthentication(rsclient: KanidmClient) {
    let mut wa = setup_demo_account_passkey(&rsclient).await;

    let res = rsclient
        .auth_passkey_begin("demo_account")
        .await
        .expect("Failed to start passkey auth");

    let pkc = wa
        .do_authentication(rsclient.get_origin().clone(), res)
        .map(Box::new)
        .expect("Failed to authentication with soft passkey");

    let res = rsclient.auth_passkey_complete(pkc).await;
    assert!(res.is_ok());

    // Assert we are still readonly
    let token = rsclient
        .get_token()
        .await
        .expect("Must have a bearer token");
    let jwtu = JwsUnverified::from_str(&token).expect("Failed to parse jwsu");

    let uat: UserAuthToken = jwtu
        .validate_embeded()
        .map(|jws| jws.into_inner())
        .expect("Unable to open up token.");

    let now = time::OffsetDateTime::now_utc();
    assert!(!uat.purpose_readwrite_active(now));

    // The auth is done, now we have to setup to re-auth for our session.
    // Should we bother looking at the internals of the token here to assert
    // it all worked? I don't think we have to because the server tests have
    // already checked all those bits.

    let res = rsclient
        // TODO! Should we actually be able to track what was used here? Or
        // do we just assume?
        .reauth_passkey_begin()
        .await
        .expect("Failed to start passkey re-authentication");

    let pkc = wa
        .do_authentication(rsclient.get_origin().clone(), res)
        .map(Box::new)
        .expect("Failed to re-authenticate with soft passkey");

    let res = rsclient.reauth_passkey_complete(pkc).await;
    assert!(res.is_ok());

    // assert we are elevated now
    let token = rsclient
        .get_token()
        .await
        .expect("Must have a bearer token");
    let jwtu = JwsUnverified::from_str(&token).expect("Failed to parse jwsu");

    let uat: UserAuthToken = jwtu
        .validate_embeded()
        .map(|jws| jws.into_inner())
        .expect("Unable to open up token.");

    let now = time::OffsetDateTime::now_utc();
    eprintln!("{:?} {:?}", now, uat.purpose);
    assert!(uat.purpose_readwrite_active(now));
}

#[kanidmd_testkit::test]
async fn test_authsession_expiry(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    let authsession_expiry = 2878_u32;
    rsclient
        .system_authsession_expiry_set(authsession_expiry)
        .await
        .unwrap();
    let result = rsclient.system_authsession_expiry_get().await.unwrap();
    assert_eq!(authsession_expiry, result);
}

#[kanidmd_testkit::test]
async fn test_privilege_expiry(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    let authsession_expiry = 2878_u32;

    rsclient
        .system_auth_privilege_expiry_set(authsession_expiry)
        .await
        .unwrap();
    let result = rsclient.system_auth_privilege_expiry_get().await.unwrap();
    assert_eq!(authsession_expiry, result);
}

async fn start_password_session(
    rsclient: &KanidmClient,
    username: &str,
    password: &str,
    privileged: bool,
) -> Result<UserAuthToken, ()> {
    let client = reqwest::Client::new();

    let authreq = AuthRequest {
        step: AuthStep::Init2 {
            username: username.to_string(),
            issue: AuthIssueSession::Token,
            privileged,
        },
    };
    let authreq = serde_json::to_string(&authreq).expect("Failed to serialize AuthRequest");

    let res = match client
        .post(rsclient.make_url("/v1/auth"))
        .header("Content-Type", "application/json")
        .body(authreq)
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => panic!("Failed to post: {:#?}", error),
    };
    assert_eq!(res.status(), 200);

    let session_id = res.headers().get(KSESSIONID).unwrap();

    let authreq = AuthRequest {
        step: AuthStep::Begin(AuthMech::Password),
    };
    let authreq = serde_json::to_string(&authreq).expect("Failed to serialize AuthRequest");

    let res = match client
        .post(rsclient.make_url("/v1/auth"))
        .header("Content-Type", "application/json")
        .header(KSESSIONID, session_id)
        .body(authreq)
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => panic!("Failed to post: {:#?}", error),
    };
    assert_eq!(res.status(), 200);

    let authreq = AuthRequest {
        step: AuthStep::Cred(AuthCredential::Password(password.to_string())),
    };
    let authreq = serde_json::to_string(&authreq).expect("Failed to serialize AuthRequest");

    let res = match client
        .post(rsclient.make_url("/v1/auth"))
        .header("Content-Type", "application/json")
        .header(KSESSIONID, session_id)
        .body(authreq)
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => panic!("Failed to post: {:#?}", error),
    };
    assert_eq!(res.status(), 200);

    let res: AuthResponse = res.json().await.expect("Failed to read JSON response");
    let jwt = match res.state {
        AuthState::Success(val) => val,
        _ => panic!("Failed to extract jwt"),
    };

    let jwt = JwsUnverified::from_str(&jwt).expect("Failed to parse jwt");
    let uat: UserAuthToken = jwt
        .validate_embeded()
        .map(|jws| jws.into_inner())
        .expect("Unable extract uat");

    Ok(uat)
}

#[kanidmd_testkit::test]
async fn test_server_user_auth_unprivileged(rsclient: KanidmClient) {
    let (account_name, account_pass) = setup_demo_account_password(&rsclient)
        .await
        .expect("Failed to setup demo_account");

    let uat = start_password_session(
        &rsclient,
        account_name.as_str(),
        account_pass.as_str(),
        false,
    )
    .await
    .expect("Failed to start session");

    match uat.purpose {
        UatPurpose::ReadOnly => panic!("Unexpected uat purpose"),
        UatPurpose::ReadWrite { expiry } => {
            assert!(expiry.is_none())
        }
    }
}

#[kanidmd_testkit::test]
async fn test_server_user_auth_privileged_shortcut(rsclient: KanidmClient) {
    let (account_name, account_pass) = setup_demo_account_password(&rsclient)
        .await
        .expect("Failed to setup demo_account");

    let uat = start_password_session(
        &rsclient,
        account_name.as_str(),
        account_pass.as_str(),
        true,
    )
    .await
    .expect("Failed to start session");

    match uat.purpose {
        UatPurpose::ReadOnly => panic!("Unexpected uat purpose"),
        UatPurpose::ReadWrite { expiry } => {
            assert!(expiry.is_some())
        }
    }
}

// wanna test how long it takes for testkit to start up? here's your biz.
// turns out  as of 2023-10-11 on my M2 Max, it's about 1.0 seconds per iteration
// #[kanidmd_testkit::test]
// fn test_teskit_test_test() {
//     #[allow(unnameable_test_items)]

//     for _ in 0..15 {
//         #[kanidmd_testkit::test]
//         #[allow(dead_code)]
//         async fn test_teskit_test(rsclient: KanidmClient){
//             assert!(rsclient.auth_anonymous().await.is_ok());
//         }

//         tk_test_teskit_test();
//     }

// }

use kanidm_proto::scim_v1::{
    client::{ScimEntryApplicationPost, ScimReference},
    ScimApplicationPasswordCreate,
};
use kanidmd_testkit::{
    setup_account_passkey, AsyncTestEnvironment, IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER,
};
use ldap3_client::LdapClientBuilder;
use tracing::debug;

const TEST_PERSON: &str = "user_mcuserton";
const TEST_GROUP: &str = "group_mcgroupington";

#[kanidmd_testkit::test(ldap = true)]
async fn test_ldap_basic_unix_bind(test_env: &AsyncTestEnvironment) {
    let ldap_url = test_env.ldap_url.as_ref().unwrap();

    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();

    // Bind as anonymous
    ldap_client
        .bind("".to_string(), "".to_string())
        .await
        .unwrap();

    let whoami = ldap_client.whoami().await.unwrap();

    assert_eq!(whoami, Some("u: anonymous@localhost".to_string()));
}

#[kanidmd_testkit::test(ldap = true)]
async fn test_ldap_application_password_basic(test_env: &AsyncTestEnvironment) {
    const APPLICATION_1_NAME: &str = "test_application_1";
    const APPLICATION_2_NAME: &str = "test_application_2";

    // Remember, this isn't the exhaustive test for application password behaviours,
    // those are in the main server. This is just a basic smoke test that the interfaces
    // are exposed and work in a basic manner.

    let idm_admin_rsclient = test_env.rsclient.new_session().unwrap();

    // Create a person

    idm_admin_rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as admin");

    idm_admin_rsclient
        .idm_person_account_create(TEST_PERSON, TEST_PERSON)
        .await
        .expect("Failed to create the user");

    idm_admin_rsclient
        .idm_group_create(TEST_GROUP, None)
        .await
        .expect("Failed to create test group");

    idm_admin_rsclient
        .idm_group_add_members(TEST_GROUP, &[TEST_PERSON])
        .await
        .expect("Failed to create test group");

    // Configure a passkey for the user.
    let mut soft_passkey = setup_account_passkey(&idm_admin_rsclient, TEST_PERSON).await;

    // Create two applications
    let application_1 = ScimEntryApplicationPost {
        name: APPLICATION_1_NAME.to_string(),
        displayname: APPLICATION_1_NAME.to_string(),
        linked_group: ScimReference::from(TEST_GROUP),
    };

    let application_entry = idm_admin_rsclient
        .idm_application_create(&application_1)
        .await
        .expect("Failed to create the application");

    debug!(?application_entry);

    let application_2 = ScimEntryApplicationPost {
        name: APPLICATION_2_NAME.to_string(),
        displayname: APPLICATION_2_NAME.to_string(),
        linked_group: ScimReference::from(TEST_GROUP),
    };

    let application_entry = idm_admin_rsclient
        .idm_application_create(&application_2)
        .await
        .expect("Failed to create the application");

    debug!(?application_entry);

    // List, get them.
    let applications = idm_admin_rsclient
        .idm_application_list(None)
        .await
        .expect("Failed to list applications.");

    assert_eq!(applications.resources.len(), 2);

    // Login as the person
    let person_rsclient = test_env.rsclient.new_session().unwrap();

    let _ = person_rsclient.logout().await;

    let res = person_rsclient
        .auth_passkey_begin(TEST_PERSON)
        .await
        .expect("Failed to start passkey auth");

    let pkc = soft_passkey
        .do_authentication(person_rsclient.get_origin().clone(), res)
        .map(Box::new)
        .expect("Failed to authentication with soft passkey");

    let res = person_rsclient.auth_passkey_complete(pkc).await;
    assert!(res.is_ok());

    // We need RW privs, elevate now.
    let res = person_rsclient
        .reauth_passkey_begin()
        .await
        .expect("Failed to start passkey reauth");

    let pkc = soft_passkey
        .do_authentication(person_rsclient.get_origin().clone(), res)
        .map(Box::new)
        .expect("Failed to authentication with soft passkey");

    let res = person_rsclient.reauth_passkey_complete(pkc).await;
    assert!(res.is_ok());

    // List the applications we can see
    let applications = person_rsclient
        .idm_application_list(None)
        .await
        .expect("Failed to list applications");

    debug!(?applications);

    let application_1 = person_rsclient
        .idm_application_get(APPLICATION_1_NAME, None)
        .await
        .expect("Failed to get application");

    let application_2 = person_rsclient
        .idm_application_get(APPLICATION_2_NAME, None)
        .await
        .expect("Failed to get application");

    debug!(?application_1);
    debug!(?application_2);

    let application_1_uuid = application_1.header.id;
    let application_2_uuid = application_2.header.id;

    // Create application passwords
    let create_application_password_req = ScimApplicationPasswordCreate {
        application_uuid: application_1_uuid,
        label: "label_1".to_string(),
    };

    let application_1_password_create_1 = person_rsclient
        .idm_application_password_create(TEST_PERSON, &create_application_password_req)
        .await
        .expect("Failed to create application password");

    let create_application_password_req = ScimApplicationPasswordCreate {
        application_uuid: application_1_uuid,
        label: "label_2".to_string(),
    };

    let application_1_password_create_2 = person_rsclient
        .idm_application_password_create(TEST_PERSON, &create_application_password_req)
        .await
        .expect("Failed to create application password");

    let create_application_password_req = ScimApplicationPasswordCreate {
        application_uuid: application_2_uuid,
        label: "label_3".to_string(),
    };

    let application_2_password_create_1 = person_rsclient
        .idm_application_password_create(TEST_PERSON, &create_application_password_req)
        .await
        .expect("Failed to create application password");

    debug!(?application_1_password_create_1);
    debug!(?application_1_password_create_2);
    debug!(?application_2_password_create_1);

    // Check the work.

    let ldap_url = test_env.ldap_url.as_ref().unwrap();

    // We can bind as our applications
    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_1_NAME}"),
            application_1_password_create_1.secret.clone(),
        )
        .await
        .expect("Failed to bind to application 1 as test person");

    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_1_NAME},dc=localhost"),
            application_1_password_create_2.secret.clone(),
        )
        .await
        .expect("Failed to bind to application 1 as test person");

    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_2_NAME},dc=localhost"),
            application_2_password_create_1.secret.clone(),
        )
        .await
        .expect("Failed to bind to application 1 as test person");

    // == Check they can't cross talk.
    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    // Using application 2 password!!!
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_1_NAME},dc=localhost"),
            application_2_password_create_1.secret.clone(),
        )
        .await
        .expect_err("Should not succeed!!");

    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    // Using application 2 password!!!
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_2_NAME}"),
            application_1_password_create_1.secret.clone(),
        )
        .await
        .expect_err("Should not succeed!!");

    // Done!

    // Check removeal of app passwords
    person_rsclient
        .idm_application_password_delete(TEST_PERSON, application_1_password_create_2.uuid)
        .await
        .expect("Failed to remove application password");

    // Then test it no longer works.
    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_1_NAME},dc=localhost"),
            application_1_password_create_2.secret.clone(),
        )
        .await
        .expect_err("Should not succeed!!");

    // Delete the applications
    idm_admin_rsclient
        .idm_application_delete(APPLICATION_1_NAME)
        .await
        .expect("Failed to delete the application");

    // Check that you can no longer bind.
    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
    ldap_client
        .bind(
            format!("name={TEST_PERSON},app={APPLICATION_1_NAME},dc=localhost"),
            application_1_password_create_1.secret.clone(),
        )
        .await
        .expect_err("Should not succeed!!");

    // Done!!!! Application passwords work!!!
}

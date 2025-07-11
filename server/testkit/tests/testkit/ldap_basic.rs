use kanidm_proto::scim_v1::client::{ScimEntryApplicationPost, ScimReference};
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
    ldap_client.bind("".into(), "".into()).await.unwrap();

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

    // List the applications we can see
    let applications = person_rsclient
        .idm_application_list(None)
        .await
        .expect("Failed to list applications");

    debug!(?applications);

    /*
    let _application = person_rsclient
        .idm_application_get(APPLICATION_2_NAME, None)
        .await
        .expect("Failed to list applications");
    */

    // Create application passwords

    /*
    let application_1_password_create_1 = person_rsclient
        .idm_application_create_password(
            APPLICATION_1_NAME,
            "label_1",
        )
        .await
        .expect("Failed to create application password");

    let application_1_password_create_2 = person_rsclient
        .idm_application_create_password(
            APPLICATION_1_NAME,
            "label_2",
        )
        .await
        .expect("Failed to create application password");

    let application_2_password_create_1 = person_rsclient
        .idm_application_create_password(
            APPLICATION_2_NAME,
            "label_1",
        )
        .await
        .expect("Failed to create application password");
    */

    // Check the work.

    // let ldap_url = test_env.ldap_url.as_ref().unwrap();
    // let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();

    // Check they can't cross talk.

    // Done!

    // Check removeal of app passwords

    // Delete the applications
    idm_admin_rsclient
        .idm_application_delete(APPLICATION_1_NAME)
        .await
        .expect("Failed to delete the application");

    // Check that you can no longer bind.

    // They no longer list
}

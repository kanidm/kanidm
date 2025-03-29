use kanidm_proto::scim_v1::client::{ScimEntryApplicationPost, ScimReference};
use kanidmd_testkit::{AsyncTestEnvironment, IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER};
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

    // Create two applications

    let application_1 = ScimEntryApplicationPost {
        name: APPLICATION_1_NAME.to_string(),
        displayname: APPLICATION_1_NAME.to_string(),
        linked_group: ScimReference::from(TEST_GROUP),
    };

    let application_entry = idm_admin_rsclient
        .idm_application_create(&application_1)
        .await
        .expect("Failed to create the user");

    debug!(?application_entry);

    // List, get them.

    // Login as the person

    // Create application passwords

    // Check the work.

    // Check they can't cross talk.

    // Done!

    // let ldap_url = test_env.ldap_url.as_ref().unwrap();

    // let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();

    let result = idm_admin_rsclient
        .idm_application_delete(APPLICATION_1_NAME)
        .await
        .expect("Failed to create the user");

    debug!(?result);

    // Delete the applications

    // Check that you can no longer bind.

    // They no longer list
}

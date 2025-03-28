use kanidmd_testkit::{AsyncTestEnvironment, IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER};
use ldap3_client::LdapClientBuilder;

const TEST_PERSON: &str = "user_mcuserton";

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
    // Remember, this isn't the exhaustive test for application password behaviours,
    // those are in the main server. This is just a basic smoke test that the interfaces
    // are exposed and work in a basic manner.

    let rsclient = test_env.rsclient.new_session().unwrap();

    // Create a person

    rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as admin");

    #[allow(clippy::expect_used)]
    rsclient
        .idm_person_account_create(TEST_PERSON, TEST_PERSON)
        .await
        .expect("Failed to create the user");

    // Create two applications

    // List, get them.

    // Login as the person

    // Create application passwords

    // Check the work.

    // Check they can't cross talk.

    // Done!

    // let ldap_url = test_env.ldap_url.as_ref().unwrap();

    // let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();
}
